// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package imapdrv

// XOAUTH2 is how Gmail and Microsoft 365 take an OAuth access token over
// IMAP: one SASL mechanism, one initial response, and on failure one JSON
// challenge naming the status. It is not in go-sasl, which carries only the
// RFC 7628 OAUTHBEARER that Microsoft's IMAP does not speak, so it is written
// here. It is small enough that a dependency would be the larger risk.

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/emersion/go-sasl"
)

// xoauth2Mechanism is the SASL name the server advertises.
const xoauth2Mechanism = "XOAUTH2"

// xoauth2String is the initial response, before base64: the address the
// token is for, then the bearer, each line ended with ^A and the whole ended
// with a second ^A. The server checks that the address matches the account
// the token was issued to, which is what makes a sign-in for another account
// fail at the dial rather than read a stranger's mail.
func xoauth2String(user, token string) string {
	return "user=" + user + "\x01auth=Bearer " + token + "\x01\x01"
}

// xoauth2Client is the client side of the exchange for one dial.
type xoauth2Client struct {
	user, token string
	challenged  bool
}

func newXoauth2Client(user, token string) sasl.Client {
	return &xoauth2Client{user: user, token: token}
}

func (c *xoauth2Client) Start() (string, []byte, error) {
	return xoauth2Mechanism, []byte(xoauth2String(c.user, c.token)), nil
}

// Next is reached only when the server refused the token: the challenge is a
// JSON document with a status and, at Gmail, the scope it wanted. The
// exchange is abandoned here rather than completed with an empty response,
// because the connection is closed either way and the status is what the
// caller needs. The error wraps ErrLogin so a caller trying several servers
// stops, as it does for a refused password.
func (c *xoauth2Client) Next(challenge []byte) ([]byte, error) {
	if c.challenged {
		return nil, sasl.ErrUnexpectedServerChallenge
	}
	c.challenged = true
	var why struct {
		Status string `json:"status"`
		Scope  string `json:"scope"`
	}
	_ = json.Unmarshal(challenge, &why)
	reason := strings.TrimSpace(why.Status)
	if reason == "" {
		reason = "the server refused the token"
	}
	if why.Scope != "" {
		reason += " (the server wants scope " + why.Scope + ")"
	}
	return nil, fmt.Errorf("%w: XOAUTH2 %s", ErrLogin, reason)
}
