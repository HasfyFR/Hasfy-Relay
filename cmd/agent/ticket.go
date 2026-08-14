package main

// Opening a support ticket from the machine itself.
//
// The person in front of a misbehaving laptop should not have to find the web
// console to say so. `hasfy-agent ticket` posts one, authenticated by the same
// Ed25519 assertion everything else on the device path uses — no credential,
// nothing to steal off disk.
//
// Deliberately does NOT collect logs, command output or system state to attach.
// Those routinely carry credentials, and a ticket is read by more people than
// the machine it came from; the console can pull diagnostics on demand, under
// an operator's authority rather than automatically. What goes up is what the
// user typed, plus the agent version for support context.

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	ticketPath        = "/api/v1/device/tickets"
	ticketHTTPTimeout = 20 * time.Second
	ticketMaxTitle    = 150
	ticketMaxBody     = 2000
)

// Mirrors DEVICE_TICKET_CATEGORIES in Hasfy-App's core/device/tickets.ts.
// Checked locally so a typo costs a clear message instead of a 400 from a
// server the user may not be able to reach anyway.
var ticketCategories = []string{
	"hardware", "software", "network", "performance", "security", "other",
}

type ticketRequest struct {
	Category     string `json:"category"`
	Title        string `json:"title"`
	Description  string `json:"description"`
	AgentVersion string `json:"agentVersion"`
}

type ticketResponse struct {
	Success bool `json:"success"`
	Data    struct {
		TicketID     string `json:"ticketId"`
		Deduplicated bool   `json:"deduplicated"`
	} `json:"data"`
	Error string `json:"error"`
}

func validCategory(c string) bool {
	for _, known := range ticketCategories {
		if c == known {
			return true
		}
	}
	return false
}

// postTicket signs an assertion and submits one report.
//
// The request names no device and no organisation: the server derives both
// from the key that signed it, so this command cannot open a ticket about
// anything but the machine it runs on.
func postTicket(
	ctx context.Context,
	apiBase string,
	identity *deviceIdentity,
	req ticketRequest,
) (*ticketResponse, error) {
	assertion, err := identity.signAssertion()
	if err != nil {
		return nil, fmt.Errorf("sign assertion: %w", err)
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(ctx, ticketHTTPTimeout)
	defer cancel()

	resp, err := postJSON(ctx, strings.TrimRight(apiBase, "/")+ticketPath, assertion, nil, body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	payload, readErr := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if readErr != nil {
		return nil, readErr
	}

	var parsed ticketResponse
	// A body we cannot parse is not worth surfacing verbatim — it may be a
	// proxy error page. Fall back to the status code.
	_ = json.Unmarshal(payload, &parsed)

	switch resp.StatusCode {
	case http.StatusOK:
		return &parsed, nil
	case http.StatusUnauthorized:
		return nil, errDeviceRefused
	case http.StatusTooManyRequests:
		msg := parsed.Error
		if msg == "" {
			msg = "too many reports from this device recently"
		}
		return nil, errors.New(msg)
	default:
		if parsed.Error != "" {
			return nil, fmt.Errorf("%s (HTTP %d)", parsed.Error, resp.StatusCode)
		}
		return nil, fmt.Errorf("ticket HTTP %d", resp.StatusCode)
	}
}

// cmdTicket implements `hasfy-agent ticket`. Returns the process exit code.
func cmdTicket(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("ticket", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	category := fs.String("category", "other",
		"one of: "+strings.Join(ticketCategories, ", "))
	title := fs.String("title", "", "one-line summary (required)")
	description := fs.String("message", "", "what is happening (required)")
	asJSON := fs.Bool("json", false, "emit machine-readable JSON")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	*title = strings.TrimSpace(*title)
	*description = strings.TrimSpace(*description)

	switch {
	case *title == "":
		fmt.Fprintln(os.Stderr, "error: --title is required")
		return 2
	case *description == "":
		fmt.Fprintln(os.Stderr, "error: --message is required")
		return 2
	case !validCategory(*category):
		fmt.Fprintf(os.Stderr, "error: --category must be one of: %s\n",
			strings.Join(ticketCategories, ", "))
		return 2
	}

	// Truncate rather than refuse: someone describing a problem at length
	// should not lose what they wrote to a limit they could not see.
	if len(*title) > ticketMaxTitle {
		*title = (*title)[:ticketMaxTitle]
	}
	if len(*description) > ticketMaxBody {
		*description = (*description)[:ticketMaxBody]
	}

	apiURL, identity, err := loadDeviceContext()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: "+err.Error())
		return 1
	}

	resp, err := postTicket(ctx, apiURL, identity, ticketRequest{
		Category:     *category,
		Title:        *title,
		Description:  *description,
		AgentVersion: Version,
	})
	if err != nil {
		if errors.Is(err, errDeviceRefused) {
			fmt.Fprintln(os.Stderr,
				"error: this device is no longer authorised. Ask an administrator to re-enrol it.")
			return 1
		}
		fmt.Fprintln(os.Stderr, "error: "+err.Error())
		return 1
	}

	if *asJSON {
		out, _ := json.Marshal(map[string]any{
			"ticketId":     resp.Data.TicketID,
			"deduplicated": resp.Data.Deduplicated,
		})
		fmt.Println(string(out))
		return 0
	}

	if resp.Data.Deduplicated {
		// Not an error from the user's side: a technician is already looking
		// at this. Saying "already reported" is more useful than "created".
		fmt.Printf("Already reported — added to open ticket %s\n", resp.Data.TicketID)
		return 0
	}
	fmt.Printf("Ticket %s opened\n", resp.Data.TicketID)
	return 0
}

// loadDeviceContext reads the enrolment on disk and opens the device key.
//
// Read-only, and never creates a keypair: this runs as whoever typed the
// command, not as the daemon, so generating a key here would leave one owned
// by the wrong user for the daemon to trip over later. A device that has not
// enrolled yet is told so, which is the actionable answer.
func loadDeviceContext() (apiURL string, identity *deviceIdentity, err error) {
	envPath := os.Getenv("HASFY_ENV_FILE")
	if envPath == "" {
		envPath = defaultEnvFilePath()
	}
	keyPath := os.Getenv("HASFY_DEVICE_KEY_FILE")
	if keyPath == "" {
		keyPath = defaultKeyPath()
	}

	env, err := loadEnvFile(envPath)
	if err != nil {
		return "", nil, fmt.Errorf("read %s: %w", envPath, err)
	}
	if !isEnrolled(env) {
		return "", nil, errors.New(
			"this device is not enrolled yet; the agent enrols itself on first start")
	}

	if _, statErr := os.Stat(keyPath); statErr != nil {
		return "", nil, fmt.Errorf(
			"device key not readable at %s (the daemon owns it; try with sudo)", keyPath)
	}

	id, created, err := loadOrCreateIdentity(keyPath, env["HASFY_DEVICE_ID"])
	if err != nil {
		return "", nil, fmt.Errorf("device identity: %w", err)
	}
	if created {
		// The stat above passed, so reaching here means the file existed but
		// held no usable key. Signing with a fresh one would fail server-side
		// anyway — the public half was never registered.
		return "", nil, errors.New(
			"the device key is unusable; ask an administrator to re-enrol this machine")
	}

	return firstNonEmpty(env["HASFY_API_URL"], defaultAPIBaseURL), id, nil
}
