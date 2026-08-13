package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestValidCategoryMatchesTheServerVocabulary(t *testing.T) {
	for _, c := range ticketCategories {
		if !validCategory(c) {
			t.Errorf("category %q rejected by its own list", c)
		}
	}
	for _, c := range []string{"", "HARDWARE", "urgent", "'; DROP TABLE"} {
		if validCategory(c) {
			t.Errorf("category %q accepted", c)
		}
	}
}

// The request must carry no device or organisation: the server derives both
// from the signing key, so a field here would be a way to ask about someone
// else's machine.
func TestTicketRequestNamesNoDeviceOrOrg(t *testing.T) {
	body, err := json.Marshal(ticketRequest{
		Category:     "network",
		Title:        "No wifi",
		Description:  "Dropped at 09:00",
		AgentVersion: "v0.4.1",
	})
	if err != nil {
		t.Fatal(err)
	}

	var fields map[string]any
	if err := json.Unmarshal(body, &fields); err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{
		"deviceId", "device_id", "orgId", "org_id",
		"organizationId", "equipmentId", "createdBy",
	} {
		if _, present := fields[forbidden]; present {
			t.Errorf("request carries %q, which the server must not accept", forbidden)
		}
	}
}

func TestPostTicketReportsTheServerOutcome(t *testing.T) {
	identity, _, err := loadOrCreateIdentity(t.TempDir()+"/key", "device-1")
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name         string
		status       int
		body         string
		wantErr      bool
		wantErrMatch string
		wantDedup    bool
	}{
		{
			name:   "opened",
			status: http.StatusOK,
			body:   `{"success":true,"data":{"ticketId":"t-1","deduplicated":false}}`,
		},
		{
			name:      "folded into an open ticket",
			status:    http.StatusOK,
			body:      `{"success":true,"data":{"ticketId":"t-1","deduplicated":true}}`,
			wantDedup: true,
		},
		{
			// A revoked device must be told to re-enrol, not left retrying.
			name:         "device no longer authorised",
			status:       http.StatusUnauthorized,
			body:         `{"success":false,"error":"Unauthorized"}`,
			wantErr:      true,
			wantErrMatch: "refused",
		},
		{
			name:         "daily cap reached surfaces the server's reason",
			status:       http.StatusTooManyRequests,
			body:         `{"success":false,"error":"This device has opened 5 tickets"}`,
			wantErr:      true,
			wantErrMatch: "5 tickets",
		},
		{
			// A proxy error page must not be echoed at the user verbatim.
			name:         "unparseable body falls back to the status code",
			status:       http.StatusBadGateway,
			body:         `<html>502 Bad Gateway</html>`,
			wantErr:      true,
			wantErrMatch: "502",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(
				func(w http.ResponseWriter, r *http.Request) {
					if got := r.Header.Get("Authorization"); !strings.HasPrefix(got, "Bearer ") {
						t.Errorf("no assertion sent: %q", got)
					}
					w.WriteHeader(tc.status)
					_, _ = w.Write([]byte(tc.body))
				}))
			defer srv.Close()

			resp, err := postTicket(context.Background(), srv.URL, identity, ticketRequest{
				Category: "network", Title: "No wifi", Description: "Dropped",
			})

			if tc.wantErr {
				if err == nil {
					t.Fatal("expected an error")
				}
				if !strings.Contains(err.Error(), tc.wantErrMatch) {
					t.Fatalf("error %q does not mention %q", err, tc.wantErrMatch)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if resp.Data.Deduplicated != tc.wantDedup {
				t.Errorf("deduplicated = %v, want %v", resp.Data.Deduplicated, tc.wantDedup)
			}
		})
	}
}

func TestCmdTicketRefusesAnIncompleteReport(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{"no title", []string{"--message", "something"}},
		{"no message", []string{"--title", "Broken"}},
		{"blank title", []string{"--title", "   ", "--message", "x"}},
		{"unknown category", []string{
			"--title", "Broken", "--message", "x", "--category", "nope"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Exit code 2 is "you asked for something impossible", distinct
			// from 1, which means the request was fine but did not land.
			if code := cmdTicket(context.Background(), tc.args); code != 2 {
				t.Fatalf("exit code = %d, want 2", code)
			}
		})
	}
}
