// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package api

import (
	"context"
	"net/http"

	"github.com/Privasys/connectors/sdk/connector"
	"github.com/Privasys/connectors/sdk/provider"
)

// tokenSource hands the driver the access token in memory. Refreshing it
// from the kept refresh token comes with the sign-in clients.
func (s *Server) tokenSource(sub string) func(context.Context) (string, error) {
	return func(ctx context.Context) (string, error) {
		acct, err := s.credStore().Get(ctx, sub)
		if err != nil {
			return "", err
		}
		return acct.AccessToken, nil
	}
}

// signInStep is the second step for an address at Google or Microsoft. No
// sign-in client is configured in this deployment yet, so the honest answer
// is that the mailbox cannot be connected here.
func (p *setup) signInStep(_ *http.Request, who provider.Provider, user string) map[string]any {
	return notOfferedElicit(user, who)
}

// connectSignIn is the mint for such an address: the same answer.
func (p *setup) connectSignIn(r *http.Request, _ string, who provider.Provider, user string, _ map[string]any) (map[string]any, error) {
	return nil, &connector.ElicitError{Elicit: p.signInStep(r, who, user)}
}
