# Inline Keys

Inline Keys is a Codex plugin for collecting a user-supplied credential without placing its plaintext in chat or MCP results. It creates a short-lived form on `127.0.0.1` by default or on an explicitly requested private IPv4 interface, writes the submitted value directly to a confirmed dotenv or raw file, and exposes only request status to Codex.

## Security boundary

- Localhost mode binds only to `127.0.0.1` on an ephemeral port.
- LAN mode binds only to a private IPv4 address assigned to the host. It does not bind `0.0.0.0`, public addresses, or arbitrary hostnames.
- Every form URL contains a random, one-time capability and expires after a short TTL.
- POST requests require the exact origin and an explicit destination confirmation checkbox. LAN requests reject clients without a private IPv4 source address.
- Responses disable caching, framing, referrers, and unrelated browser capabilities.
- Secret values are never logged or returned through MCP.
- Writes reject symlink targets, resolve the parent directory before writing, use an atomic same-directory replacement, and set owner-only permissions where supported.
- Dotenv mode changes only one named variable and rejects ambiguous duplicate entries.
- Dotenv values use a deliberately small, portable encoding dialect; values that cannot be represented consistently must use raw mode or a credential store.

This protects secret entry and tool output. It does not prevent Codex—or any process running as the same OS user—from reading the destination file later. Use a file outside the workspace or a dedicated credential broker when stronger runtime isolation is required.

`INLINE_KEYS_ALLOWED_ROOTS` is an accident-prevention boundary, not a defense against a hostile process running as the same OS user. Node.js does not expose portable directory-handle-relative rename operations, so a same-user process that can replace ancestor directories can race pathname-based writes.

## MCP tools

- `request_secret`: create a pending localhost or explicitly requested private-LAN form for a dotenv entry or raw file.
- `get_secret_request`: return value-blind request status.
- `cancel_secret_request`: invalidate a pending form.

Optional environment configuration:

- `INLINE_KEYS_ALLOWED_ROOTS`: platform-delimited list of directories to which writes are restricted.
- `INLINE_KEYS_DEFAULT_TTL_SECONDS`: default form lifetime, from 60 to 900 seconds.
- `INLINE_KEYS_MAX_SECRET_BYTES`: maximum submitted secret size, from 1 KiB to 1 MiB.
- `INLINE_KEYS_TLS_CERT_FILE` and `INLINE_KEYS_TLS_KEY_FILE`: optional PEM files used together for HTTPS LAN forms. The certificate must cover the advertised private IP and be trusted by the submitting browser.

## LAN mode

Set `access: "lan"` only when the user explicitly asks to submit from another private-network device. Inline Keys auto-selects only an assigned RFC1918 address; `lan_host` can select a specific assigned private address. Shared `100.64.0.0/10` carrier/Tailscale space and IPv4 link-local addresses require explicit selection and must not be treated as automatically trusted.

If TLS certificate and key files are configured, LAN URLs use HTTPS. Without them, the request must explicitly set `allow_insecure_lan: true`, the form requires a separate user checkbox acknowledging unencrypted transport, and both the tool result and form identify the transport as `private_lan_http`. Unencrypted LAN mode keeps the value out of Codex chat, but it cannot prevent another device on the network from observing the URL or submitted credential. Do not use public port forwards or public tunnels.

## Development

Run `npm test` from this directory. The implementation uses only Node.js built-ins.
