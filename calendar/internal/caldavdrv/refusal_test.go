package caldavdrv

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Google answers every CalDAV call with 403 SERVICE_DISABLED until the
// project's CalDAV API is enabled. That is the deployment's setup, not the
// holder's sign-in, and it must say so, with Google's own explanation.
func TestADisabledProviderAPIIsNotARefusedSignIn(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":{"code":403,"message":"CalDAV API has not been used in project 646468140007 before or it is disabled. Enable it by visiting https://console.developers.google.com/apis/api/caldav.googleapis.com/overview?project=646468140007 then retry.","status":"PERMISSION_DENIED","details":[{"reason":"SERVICE_DISABLED"}]}}`))
	}))
	defer srv.Close()
	_, err := Open(context.Background(), Config{
		Endpoint: srv.URL + "/caldav/v2/someone%40gmail.com/user", User: "someone@gmail.com", HTTPClient: srv.Client(),
		Token: func(context.Context) (string, error) { return "tok", nil },
	})
	if !errors.Is(err, ErrProviderSetup) {
		t.Fatalf("want ErrProviderSetup, got %v", err)
	}
	if errors.Is(err, ErrLogin) {
		t.Fatal("a disabled API must not read as a refused sign-in")
	}
	if !strings.Contains(err.Error(), "CalDAV API has not been used in project 646468140007") || strings.Contains(err.Error(), "Enable it by visiting") {
		t.Fatalf("want Google's first sentence and only that, got %v", err)
	}
}

// A plain 403 is still the credential being refused.
func TestAPlain403IsStillARefusedSignIn(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()
	_, err := Open(context.Background(), Config{Endpoint: srv.URL + "/dav/", User: "u", Password: "p", HTTPClient: srv.Client()})
	if !errors.Is(err, ErrLogin) || errors.Is(err, ErrProviderSetup) {
		t.Fatalf("want ErrLogin, got %v", err)
	}
}
