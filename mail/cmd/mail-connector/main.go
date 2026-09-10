// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

// Command mail-connector serves one mailbox connector.
//
// It listens on $PORT, which the platform allocates: 8080 is reserved and an
// app that hard-codes a port does not start.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Privasys/connectors/mail/internal/api"
	"github.com/Privasys/connectors/mail/internal/attested"
	"github.com/Privasys/connectors/mail/internal/broker"
	"github.com/Privasys/connectors/mail/internal/config"
	"github.com/Privasys/connectors/mail/internal/grant"
	"github.com/Privasys/connectors/mail/internal/store"
)

func main() {
	log.SetFlags(log.LstdFlags | log.LUTC)
	flag.Parse()
	if *linkSub != "" {
		if err := linkFromFile(*linkSub, *linkCreds); err != nil {
			log.Fatal(err)
		}
		return
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8000"
	}

	st, needsConfig, err := openStore()
	if err != nil {
		log.Fatalf("credential store: %v", err)
	}

	srv := api.New(st, grant.NewMemory(), requireGrant())

	// Configure-then-freeze. A deployment that has never been configured still
	// starts and serves /configure; everything else answers 503 until it has
	// been. Refusing to boot would leave an operator nothing to configure.
	if needsConfig {
		path := envOr("MAIL_CONFIG", "/data/mail-connector/config.json")
		cfg, found, cerr := config.Load(path)
		if cerr != nil {
			// Stored settings that will not parse or will not validate: refuse
			// rather than run on half of them. A connector pointed at an
			// unpinned peer is worse than one that will not start.
			log.Fatalf("configuration at %s: %v", path, cerr)
		}
		if found {
			built, berr := buildStore(cfg)
			if berr != nil {
				log.Printf("stored configuration will not open a store yet (%v); serving /configure only", berr)
			} else {
				st = built
				log.Printf("credential store: holders' own Drive at %s, over an attested leg", cfg.DriveHost)
			}
		}
		srv.SetStore(st)
		srv.SetConfigurable(path, buildStore, cfg, found && st != nil)
		if st == nil {
			log.Print("not configured yet: serving /configure and nothing else")
		}
	}
	defer srv.Close()

	httpSrv := &http.Server{
		Addr:    ":" + port,
		Handler: srv.Handler(),
		// A tool call may long-poll the mailbox for up to a minute, so the
		// write timeout has to clear that with room, or Changes would be cut
		// off by our own server rather than by the caller's deadline.
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      2 * time.Minute,
		IdleTimeout:       2 * time.Minute,
	}

	go func() {
		log.Printf("mail-connector listening on :%s", port)
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

// openStore picks the credential backend.
//
// The production backend keeps the ciphertext in the USER's Drive under a key
// sealed to this connector's measurement, so the user's own revoke is the kill
// switch. The local backend exists so the connector runs on a workstation, and it is deliberately awkward to select: it puts user
// secrets on the connector's own disk, which is the thing the design says must
// not happen, so it takes an explicit opt-in rather than being the default
// that quietly ships.
// buildStore turns a configuration into the production credential store.
//
// Everything it needs beyond the configuration comes from the runtime: the
// capability broker over loopback, and the identity the manager mints for the
// attested leg. Off the platform those are absent and this fails, which is the
// right outcome — the development store is chosen explicitly, never fallen
// back to.
func buildStore(c config.Config) (store.Store, error) {
	b, err := broker.New(envOr("MAIL_RESOURCE", "storage"))
	if err != nil {
		return nil, err
	}
	tr, err := attested.New(c.DriveHost, c.DriveAppID, c.DriveDigest)
	if err != nil {
		return nil, err
	}
	if !tr.Mutual() {
		// Drive's strict attested-caller check only engages when the caller
		// can prove what it is. Without it the grant rests on the key alone,
		// which is weaker than the sentence the holder was shown.
		log.Print("WARNING: no manager identity, so the Drive leg proves the peer but not us")
	}
	return store.OpenDrive(b, c.DriveHost, envOr("MAIL_SEAL_KEY", "/data/mail-connector/seal.key"), tr)
}

// openStore picks the credential backend.
//
// The production backend keeps ciphertext in the HOLDER's Drive under a key
// sealed to this app's volume, so their own revoke is the kill switch. It is
// configured through the platform rather than the environment, and until that
// has happened the service still starts and serves only /configure. That is
// what configure-then-freeze means: refusing to boot would leave an operator
// with nothing to configure.
//
// The local backend exists so this runs on a workstation. It is deliberately
// awkward to select, because it puts holder secrets on this host, which is the
// thing the design forbids.
func openStore() (store.Store, bool, error) {
	if os.Getenv("MAIL_STORE") == "local" {
		dir := envOr("MAIL_STORE_DIR", "./.mail-store")
		key, err := localKey()
		if err != nil {
			return nil, false, err
		}
		log.Printf("DEVELOPMENT credential store at %s: holder secrets are on this host, not their Drive", dir)
		st, err := store.OpenLocal(dir, key)
		return st, false, err
	}
	return nil, true, nil
}

func localKey() ([]byte, error) {
	if h := os.Getenv("MAIL_STORE_KEY"); h != "" {
		key, err := hex.DecodeString(h)
		if err != nil || len(key) != 32 {
			return nil, errors.New("MAIL_STORE_KEY must be 64 hex characters")
		}
		return key, nil
	}
	// A fresh key each start means anything stored before is unreadable, which
	// is the right failure for a development store: it fails loudly rather
	// than pretending a credential survived a restart it did not.
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	log.Print("no MAIL_STORE_KEY: generated an ephemeral one, so linked mailboxes will not survive a restart")
	return key, nil
}

// requireGrant decides whether every tool call must be covered by a capability
// the holder approved on their device.
//
// Fail closed. Turning it off is a development affordance for exercising the
// mailbox before the wallet flow exists, and it is the single switch that
// separates "a service the holder authorised" from "a service that will read
// anyone's mail for anyone who asks", so it is loud and never the default.
func requireGrant() bool {
	if os.Getenv("MAIL_ALLOW_UNGRANTED") == "yes-i-am-developing" {
		log.Print("DEVELOPMENT: capability checks are OFF; every caller may reach every linked mailbox")
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
