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
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Privasys/connectors/mail/internal/api"
	"github.com/Privasys/connectors/mail/internal/store"
)

func main() {
	log.SetFlags(log.LstdFlags | log.LUTC)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8000"
	}

	st, err := openStore()
	if err != nil {
		log.Fatalf("credential store: %v", err)
	}
	defer st.Close()

	srv := &http.Server{
		Addr:    ":" + port,
		Handler: api.New(st).Handler(),
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
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("serve: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
	log.Print("stopped")
}

// openStore picks the credential backend.
//
// The production backend keeps the ciphertext in the USER's Drive under a key
// sealed to this connector's measurement, so the user's own revoke is the kill
// switch. It is not built yet. The local backend exists so the connector runs
// on a workstation, and it is deliberately awkward to select: it puts user
// secrets on the connector's own disk, which is the thing the design says must
// not happen, so it takes an explicit opt-in rather than being the default
// that quietly ships.
func openStore() (store.Store, error) {
	switch os.Getenv("MAIL_STORE") {
	case "drive", "":
		return nil, errors.New(
			"the Drive-backed credential store is not built yet; " +
				"set MAIL_STORE=local for development, understanding that it keeps " +
				"user secrets on this host")
	case "local":
		dir := os.Getenv("MAIL_STORE_DIR")
		if dir == "" {
			dir = "./.mail-store"
		}
		key, err := localKey()
		if err != nil {
			return nil, err
		}
		log.Printf("DEVELOPMENT credential store at %s: user secrets are on this host, not the user's Drive", dir)
		return store.OpenLocal(dir, key)
	default:
		return nil, errors.New("MAIL_STORE must be 'drive' or 'local'")
	}
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
