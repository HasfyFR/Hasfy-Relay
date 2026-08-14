package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"
)

// =============================================================================
// Shipping metrics to Elasticsearch
// =============================================================================
//
// Devices write straight to Elasticsearch rather than through Hasfy-App. The
// trade was made deliberately:
//
//   - metrics are per-minute per-device, so routing them through the app would
//     turn it into a high-throughput ingest proxy — an unbounded scaling
//     problem traded for a bounded credential one;
//   - the credential in question is near-powerless (`create_doc` on one
//     organisation's index pattern: append documents, nothing else) and never
//     touches disk.
//
// Inventory still goes through Hasfy-App precisely because it is hourly and
// low-volume, so the app can afford to be in that path and no ES credential is
// needed for it.

// esBulkResponse is the subset of the _bulk reply we act on.
type esBulkResponse struct {
	Errors bool `json:"errors"`
	Items  []map[string]struct {
		Status int             `json:"status"`
		Error  json.RawMessage `json:"error"`
	} `json:"items"`
}

// dailyIndex is the concrete index a sample lands in.
//
// One index per organisation per day: ILM can then roll and delete whole
// indices instead of running delete-by-query, and a tenant's data is
// physically separable.
func dailyIndex(prefix string, at time.Time) string {
	return fmt.Sprintf("%s-%s", prefix, at.UTC().Format("2006.01.02"))
}

// shipMetrics sends a batch of documents through the Elasticsearch _bulk API.
//
// Returns an error on transport failure or a non-2xx status. Per-document
// rejections are logged rather than retried: a document Elasticsearch refuses
// (a mapping conflict, say) will be refused again forever, and retrying it
// would block every later sample behind it.
func shipMetrics(
	ctx context.Context,
	log *slog.Logger,
	creds *ingestCredentials,
	docs []map[string]any,
) error {
	if len(docs) == 0 {
		return nil
	}

	index := dailyIndex(creds.IndexPrefix, time.Now())

	var body bytes.Buffer
	for _, doc := range docs {
		// `create` rather than `index`: the key only carries `create_doc`, and
		// append-only is what we want anyway — a device must not be able to
		// overwrite an existing document.
		meta := map[string]any{"create": map[string]any{"_index": index}}
		metaLine, err := json.Marshal(meta)
		if err != nil {
			return err
		}
		docLine, err := json.Marshal(doc)
		if err != nil {
			return err
		}
		body.Write(metaLine)
		body.WriteByte('\n')
		body.Write(docLine)
		body.WriteByte('\n')
	}

	ctx, cancel := context.WithTimeout(ctx, metricsHTTPTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		trimSlash(creds.ElasticsearchURL)+"/_bulk", &body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-ndjson")
	req.Header.Set("Authorization", "ApiKey "+creds.APIKey)
	req.Header.Set("User-Agent", "hasfy-agent/"+Version)

	resp, err := (&http.Client{Timeout: metricsHTTPTimeout}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		// The key was rotated or revoked. Signal it so the caller re-fetches
		// instead of retrying with a credential that will never work again.
		return errIngestUnauthorized
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("bulk HTTP %d", resp.StatusCode)
	}

	var out esBulkResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		// The write very likely succeeded; a body we cannot parse is not worth
		// re-sending the batch for.
		log.Warn("could not decode the bulk response", "err", err)
		return nil
	}
	if out.Errors {
		rejected := 0
		for _, item := range out.Items {
			for _, r := range item {
				if r.Status >= 300 {
					rejected++
				}
			}
		}
		log.Warn("elasticsearch rejected part of the batch",
			"rejected", rejected, "total", len(docs))
	}
	return nil
}

// errIngestUnauthorized means the ES key is no longer accepted — rotated,
// expired, or revoked. Recoverable by fetching a new one.
var errIngestUnauthorized = errors.New("elasticsearch rejected the ingest key")

// runMetricsReporter samples and ships on a schedule until ctx is done.
//
// Buffers on failure so a short Elasticsearch outage costs no data, but the
// buffer is bounded and drops oldest-first: recent metrics matter more than
// complete history, and an agent cut off for a week must not consume memory
// without limit.
func runMetricsReporter(
	ctx context.Context,
	log *slog.Logger,
	apiBase, deviceID, orgID string,
	identity *deviceIdentity,
) {
	var creds *ingestCredentials
	var credsFetchedAt time.Time
	var buffer []map[string]any

	timer := time.NewTimer(metricsInitialDelay)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}

		next := metricsInterval

		if creds == nil || time.Since(credsFetchedAt) > ingestCredentialsTTL {
			fresh, err := fetchIngestCredentials(ctx, apiBase, identity)
			switch {
			case errors.Is(err, errDeviceRefused):
				log.Error("metrics disabled: this device is no longer authorised")
				return
			case err != nil:
				if ctx.Err() != nil {
					return
				}
				log.Warn("could not obtain ingest credentials", "err", err,
					"retry_in", metricsRetryDelay.String())
				timer.Reset(metricsRetryDelay)
				continue
			default:
				creds = fresh
				credsFetchedAt = time.Now()
			}
		}

		// Sample everything first; a subsystem that fails just contributes
		// nothing rather than failing the cycle.
		batch := make([]map[string]any, 0, 8)
		if doc, err := collectMetrics(ctx, deviceID, orgID); err == nil {
			batch = append(batch, doc)
		} else {
			log.Warn("metric collection failed", "err", err)
		}
		batch = append(batch, collectFilesystemMetrics(ctx, deviceID, orgID)...)
		batch = append(batch, collectNetworkMetrics(ctx, deviceID, orgID)...)

		buffer = appendBounded(buffer, batch, maxBufferedSamples)
		if len(buffer) == 0 {
			timer.Reset(next)
			continue
		}

		err := shipMetrics(ctx, log, creds, buffer)
		switch {
		case errors.Is(err, errIngestUnauthorized):
			// Force a re-fetch on the next tick and keep the buffer: the
			// samples are still good, only the credential went stale.
			log.Info("ingest key rejected; requesting a new one")
			creds = nil
			next = metricsRetryDelay
		case err != nil:
			if ctx.Err() != nil {
				return
			}
			log.Warn("metric upload failed; buffering", "err", err,
				"buffered", len(buffer), "retry_in", metricsRetryDelay.String())
			next = metricsRetryDelay
		default:
			buffer = nil
		}

		timer.Reset(next)
	}
}

// appendBounded adds a batch to the buffer, dropping the oldest entries when
// the cap is exceeded.
func appendBounded(buffer, batch []map[string]any, cap int) []map[string]any {
	buffer = append(buffer, batch...)
	if len(buffer) > cap {
		buffer = buffer[len(buffer)-cap:]
	}
	return buffer
}
