// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

// Command meetings-connector serves one meetings connector.
//
// It listens on $PORT, which the platform allocates: 8080 is reserved and an
// app that hard-codes a port does not start.
package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Privasys/connectors/meetings/internal/api"
	"github.com/Privasys/connectors/meetings/internal/archive"
	"github.com/Privasys/connectors/meetings/internal/config"
	"github.com/Privasys/connectors/meetings/internal/store"
	"github.com/Privasys/connectors/sdk/broker"
	"github.com/Privasys/connectors/sdk/configure"
	"github.com/Privasys/connectors/sdk/drive"
	"github.com/Privasys/connectors/sdk/grant"
	"github.com/Privasys/connectors/sdk/holder"
)

func main() {
	log.SetFlags(log.LstdFlags | log.LUTC)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8000"
	}

	// The credentials and the capabilities live in memory and nowhere else.
	// There is no backend to choose: anything more durable would be a copy of
	// a holder's credential kept somewhere they did not put it. A restart
	// forgets everything; the wallet sends back what it kept (the refresh
	// token this service asked it to hold) at the next use.
	srv := api.New(store.NewMemory(), grant.NewMemory(), requireGrant())

	// Who this deployment will accept as a HOLDER. The platform's own issuer
	// unless configure replaces it. Installed here as well as there so that a
	// restart of an already-configured deployment can verify a wallet's token
	// before anyone reconfigures it.
	srv.SetVerifier(holder.NewJWKS(holder.DefaultIssuer, holder.DefaultAudience))

	// Configure-then-freeze. A deployment that has never been configured still
	// starts and serves /configure; everything else answers 503 until it has
	// been. Refusing to boot would leave an operator nothing to configure.
	path := envOr("MEETINGS_CONFIG", "/data/meetings-connector/config.json")
	cfg, found, err := configure.Load[config.Config](path)
	if err != nil {
		log.Fatalf("configuration at %s: %v", path, err)
	}
	gate := configure.NewGate(path, cfg, found)
	srv.SetConfigurable(gate)
	// The archive is rebuilt from the settings after every configure, on top
	// of what the connector itself takes from them (the OAuth clients).
	applyArchive := func(c config.Config) { srv.SetArchive(buildArchive(c)) }
	inner := gate.OnApply
	gate.OnApply = func(c config.Config) {
		if inner != nil {
			inner(c)
		}
		applyArchive(c)
	}
	if found {
		srv.SetVerifier(holder.NewJWKS(cfg.IdpIssuer, cfg.IdpAudience))
		applyArchive(cfg)
		log.Printf("holders are whoever %s says they are", cfg.IdpIssuer)
		log.Printf("Zoom accounts: %s; Microsoft accounts: %s", configured(cfg.ZoomConfigured()), configured(cfg.MicrosoftConfigured()))
	} else {
		log.Print("not configured yet: serving /configure and nothing else")
	}
	defer srv.Close()

	httpSrv := &http.Server{
		Addr:    ":" + port,
		Handler: srv.Handler(),
		// The change feed holds a call for up to a minute, so the write
		// timeout has to clear that with room, or it would be cut off by our
		// own server rather than by the caller's deadline.
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      2 * time.Minute,
		IdleTimeout:       2 * time.Minute,
	}

	go func() {
		log.Printf("meetings-connector listening on :%s", port)
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("serve: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(ctx)
	log.Print("stopped")
}

// buildArchive turns the settings into the place transcripts are kept: the
// holder's Drive over the attested leg, with the runtime broker for the
// folder and the proofs. Off the platform, or on a deployment that names
// no Drive, there is no archive and save_transcript says so.
func buildArchive(c config.Config) archive.Archive {
	if !c.DriveConfigured() {
		log.Print("no Drive configured: transcripts can be read but not kept")
		return archive.None{}
	}
	b, err := broker.New(archive.Resource)
	if err != nil {
		log.Printf("no runtime capability broker (%v): transcripts can be read but not kept", err)
		return archive.None{}
	}
	tr, err := drive.NewTransport(c.DriveHost, c.DriveAppID, c.DriveDigest)
	if err != nil {
		log.Printf("the Drive leg cannot be built (%v): transcripts can be read but not kept", err)
		return archive.None{}
	}
	if !tr.Mutual() {
		// Drive's strict attested-caller check only engages when the caller
		// can prove what it is. Without it the grant rests on the key alone,
		// which is weaker than the sentence the holder was shown.
		log.Print("WARNING: no manager identity, so the Drive leg proves the peer but not us")
	}
	d, err := drive.New(c.DriveHost, tr, b)
	if err != nil {
		log.Printf("the Drive client cannot be built (%v): transcripts can be read but not kept", err)
		return archive.None{}
	}
	log.Printf("saved transcripts go to each holder's Drive at %s, over an attested leg", c.DriveHost)
	return archive.NewDrive(b, d)
}

// requireGrant decides whether every tool call must be covered by a capability
// the holder approved on their device.
//
// Fail closed. Turning it off is a development affordance, and it is the
// single switch that separates "a service the holder authorised" from "a
// service that will read anyone's transcripts for anyone who asks", so it is
// loud and never the default.
func requireGrant() bool {
	if os.Getenv("MEETINGS_ALLOW_UNGRANTED") == "yes-i-am-developing" {
		log.Print("DEVELOPMENT: capability checks are OFF; every caller may reach every connected account")
		return false
	}
	return true
}

func configured(ok bool) string {
	if ok {
		return "configured"
	}
	return "no OAuth client configured"
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
