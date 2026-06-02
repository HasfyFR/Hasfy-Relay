# Hasfy-Relay

Reverse-tunnel relay that replaces MeshCentral in the Hasfy stack.

- **Transport**: WebSocket over TLS (port 443) — no extra TCP load balancer, no SSH daemon to harden.
- **Targets**: Linux, macOS, Windows. Single Go binary for the agent across all three.
- **Surface**: CLI-only. No RDP, no VNC, no screen capture. Operators see a terminal embedded in the Hasfy web app.
- **Status**: Phase 1.1 scaffold. Not production yet.

## Components

```
cmd/
├── relay/    # Server pod running in K8s (namespace: relay)
└── agent/    # Cross-platform binary installed on managed devices

internal/
├── server/    # HTTP/WS handlers, routing, lifecycle
├── registry/  # In-memory map deviceId → live agent connection
├── auth/      # JWT verification (operator) + bearer/mTLS (agent)
├── audit/     # NDJSON append-only audit log → Filebeat → ES
└── proto/     # Wire protocol shared by agent + relay
```

## Threat model & hardening (phase 1)

| Vector | Mitigation |
|--------|------------|
| Agent impersonation | Bearer token issued by Hasfy-App at install time, rotated hourly via PoP refresh. Phase 1.4: mTLS via Vault PKI. |
| Operator → wrong device | Session token signed by relay, scoped `(org_id, device_id, session_id)`, TTL 5 min. |
| Cross-tenant lateral move | Hasfy-App only requests `(org_id, device_id)` tuples it has RBAC for. Relay re-validates against device's registered org. |
| Leaked session token replayed | One-time use. Bound to client IP and `User-Agent` SHA256. |
| Command injection from compromised relay | Agent never `eval`s shell metadata; commands are passed as `argv` arrays via JSON, not strings. |
| Long-lived session abuse | Hard cap 4 h, idle timeout 15 min, 1 active session per device. |
| Audit gaps | Every connect/disconnect/exec/output frame mirrored to NDJSON stdout. Filebeat ships to ES `hasfy-console-audit-*`. |
| Secrets in command output | DLP regex layer in `internal/audit/redact.go` masks API keys, JWTs, AWS creds, passwords. |
| Binary tampering | Agent binary built reproducibly via goreleaser, SHA256 published to S3, verified at install time. |

## Why not autossh / sshd?

| Concern | autossh + sshd | This (WS Go) |
|---------|----------------|--------------|
| Extra TCP LoadBalancer | yes (~10€/mo + open port range) | no, reuses existing 443 ingress |
| Audit log granularity | session-level only | command-level + DLP |
| mTLS path | manual cert deployment | cert-manager native |
| Cross-platform agent | OpenSSH client per OS, fragile on Windows | one Go binary, identical on all 3 |
| RBAC integration with Hasfy-App | none, must wrap | native, app issues session tokens |
| LOC to maintain | sshd config + jail + ProxyJump | ~800 LOC Go, all auditable |

## Local dev

```bash
go run ./cmd/relay -config config/dev.yaml
go run ./cmd/agent -relay wss://localhost:8443/agent/ws -token <devtoken>
```

## License

Proprietary — Hasfy SAS, all rights reserved.
