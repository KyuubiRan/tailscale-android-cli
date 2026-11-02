// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_debug

package localapi

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnauth"
	"tailscale.com/tstest"
)

// TestServeDebugReconfigPermissions exercises the LocalAPI endpoint without
// a real account or network map.
func TestServeDebugReconfigPermissions(t *testing.T) {
	for _, tt := range []struct {
		name, method, header string
		write                bool
		want                 int
	}{
		{"read-only", http.MethodPost, "", false, http.StatusForbidden},
		{"get", http.MethodGet, "", true, http.StatusMethodNotAllowed},
		{"write", http.MethodPost, "", true, http.StatusOK},
		{"origin", http.MethodPost, "Origin", true, http.StatusForbidden},
		{"referer", http.MethodPost, "Referer", true, http.StatusForbidden},
	} {
		t.Run(tt.name, func(t *testing.T) {
			h := handlerForTest(t, &Handler{
				PermitRead: true, PermitWrite: tt.write, b: newTestLocalBackend(t),
			})
			req := httptest.NewRequest(tt.method, "http://local-tailscaled.sock/localapi/v0/debug?action=reconfig", nil)
			if tt.header != "" {
				req.Header.Set(tt.header, "https://example.invalid/")
			}
			resp := httptest.NewRecorder()
			h.ServeHTTP(resp, req)
			if resp.Code != tt.want {
				t.Errorf("status = %d, want %d; body: %s", resp.Code, tt.want, resp.Body.String())
			}
		})
	}
}

// TestServeDevSetStateStore verifies writing state keys requires a local admin,
// not just PermitWrite; guards against bypassing serve-config's authz check.
func TestServeDevSetStateStore(t *testing.T) {
	tstest.Replace(t, &validLocalHostForTesting, true)

	profileID := ipn.ProfileID("test-profile")
	tests := []struct {
		desc        string
		permitWrite bool
		localAdmin  bool
		wantStatus  int
	}{
		{
			desc:        "no-permission",
			permitWrite: false,
			localAdmin:  false,
			wantStatus:  http.StatusForbidden,
		},
		{
			desc:        "write-not-admin",
			permitWrite: true,
			localAdmin:  false,
			wantStatus:  http.StatusUnauthorized,
		},
		{
			desc:        "write-admin",
			permitWrite: true,
			localAdmin:  true,
			wantStatus:  http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			h := handlerForTest(t, &Handler{
				PermitWrite: tt.permitWrite,
				Actor:       &ipnauth.TestActor{LocalAdmin: tt.localAdmin},
				b:           newTestLocalBackend(t),
			})
			s := httptest.NewServer(h)
			t.Cleanup(s.Close)

			form := url.Values{
				"key":   {string(ipn.ServeConfigKey(profileID))},
				"value": {"{}"},
			}
			res, err := s.Client().PostForm(s.URL+"/localapi/v0/dev-set-state-store", form)
			if err != nil {
				t.Fatal(err)
			}
			defer res.Body.Close()
			if res.StatusCode != tt.wantStatus {
				t.Errorf("res.StatusCode = %d, want %d", res.StatusCode, tt.wantStatus)
			}
		})
	}
}

func TestServeDebugLogGate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		desc        string
		permitRead  bool
		permitWrite bool
		wantStatus  int
	}{
		{
			desc:       "read-only-denied",
			permitRead: true,
			wantStatus: http.StatusForbidden,
		},
		{
			desc:        "write-allowed",
			permitRead:  true,
			permitWrite: true,
			wantStatus:  http.StatusNoContent,
		},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			h := handlerForTest(t, &Handler{
				PermitRead:  tt.permitRead,
				PermitWrite: tt.permitWrite,
				b:           newTestLocalBackend(t),
			})
			req := httptest.NewRequest("POST", "http://local-tailscaled.sock/localapi/v0/debug-log",
				strings.NewReader(`{"prefix":"test","lines":["line"]}`))
			resp := httptest.NewRecorder()
			h.serveDebugLog(resp, req)

			if resp.Code != tt.wantStatus {
				t.Errorf("resp.Code = %d, want %d; body: %s", resp.Code, tt.wantStatus, resp.Body.String())
			}
		})
	}
}
