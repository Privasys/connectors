// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

// Command files-connector serves one files connector.
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

	"github.com/Privasys/connectors/files/internal/api"
	"github.com/Privasys/connectors/files/internal/config"
	"github.com/Privasys/connectors/files/internal/store"
	"github.com/Privasys/connectors/sdk/configure"
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
	// forgets everything; the wallet sends back the refresh token this
	// service asked it to hold at the next use.
	srv := api.New(store.NewMemory(), grant.NewMemory(), requireGrant())

	// Who this deployment will accept as a HOLDER. The platform's own issuer
	// unless configure replaces it. Installed here as well as there so that a
	// restart of an already-configured deployment can verify a wallet's token
	// before anyone reconfigures it.
	srv.SetVerifier(holder.NewJWKS(holder.DefaultIssuer, holder.DefaultAudience))

	// Configure-then-freeze. A deployment that has never been configured still
	// starts and serves /configure; everything else answers 503 until it has
	// been. Refusing to boot would leave an operator nothing to configure.
	path := envOr("FILES_CONFIG", "/data/files-connector/config.json")
	cfg, found, err := configure.Load[config.Config](path)
	if err != nil {
		log.Fatalf("configuration at %s: %v", path, err)
	}
	srv.SetConfigurable(configure.NewGate(path, cfg, found))
	if found {
		srv.SetVerifier(holder.NewJWKS(cfg.IdpIssuer, cfg.IdpAudience))
		log.Printf("holders are whoever %s says they are", cfg.IdpIssuer)
		if cfg.MicrosoftConfigured() {
			log.Printf("Microsoft accounts sign in through app registration %s", cfg.MicrosoftClientID)
		} else {
			log.Print("no Microsoft client configured: Microsoft accounts cannot be connected")
		}
		if cfg.GoogleConfigured() {
			log.Printf("Google accounts sign in through OAuth client %s", cfg.GoogleClientID)
		} else {
			log.Print("no Google OAuth client configured: Google accounts cannot be connected")
		}
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
		log.Printf("files-connector listening on :%s", port)
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

// requireGrant decides whether every tool call must be covered by a capability
// the holder approved on their device.
//
// Fail closed. Turning it off is a development affordance, and it is the
// single switch that separates "a service the holder authorised" from "a
// service that will read anyone's files for anyone who asks", so it is loud
// and never the default.
func requireGrant() bool {
	if os.Getenv("FILES_ALLOW_UNGRANTED") == "yes-i-am-developing" {
		log.Print("DEVELOPMENT: capability checks are OFF; every caller may reach every connected file store")
		return false
	}
	return true
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
