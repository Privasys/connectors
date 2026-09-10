// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/Privasys/connectors/mail/internal/store"
)

// linkFromFile seeds a development store from a credentials file, so the
// connector can be exercised end to end before the account-linking page and
// the wallet capability exist.
//
// It reads the secret from a FILE outside the tree rather than a flag or an
// environment variable: a password in argv is visible to every process on the
// machine and lands in shell history.
//
//	mail-connector -link <sub> -creds C:\path\creds.json
//
//	{"host":"imap.gmail.com:993","user":"you@example.com","password":"…",
//	 "own_domains":["example.com"]}
func linkFromFile(sub, path string) error {
	if sub == "" || path == "" {
		return errors.New("-link needs a subject and -creds a file path")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	var c struct {
		Host       string   `json:"host"`
		User       string   `json:"user"`
		Password   string   `json:"password"`
		OwnDomains []string `json:"own_domains"`
	}
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("parse %s: %w", path, err)
	}
	if c.User == "" || c.Password == "" {
		return fmt.Errorf("%s: user and password are both required", path)
	}
	if c.Host == "" {
		c.Host = "imap.gmail.com:993"
	}
	// The development link path only ever writes to the local store; the
	// production one is reached through the running service, where the
	// holder authenticates.
	if os.Getenv("MAIL_STORE") != "local" {
		return errors.New("-link is a development affordance: set MAIL_STORE=local")
	}
	st, _, err := openStore()
	if err != nil {
		return err
	}
	defer st.Close()
	if err := st.Put(context.Background(), sub, store.Account{
		Provider: "imap", Host: c.Host, User: c.User, Secret: c.Password,
		OwnDomains: c.OwnDomains, LinkedAt: time.Now(),
	}); err != nil {
		return err
	}
	fmt.Printf("linked %s for subject %s\n", c.User, sub)
	return nil
}

var (
	linkSub   = flag.String("link", "", "development only: link a mailbox for this subject and exit")
	linkCreds = flag.String("creds", "", "development only: path to the credentials file used by -link")
)
