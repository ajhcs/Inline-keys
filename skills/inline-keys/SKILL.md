---
name: inline-keys
description: Securely collect an API key, token, password, private key, or other credential through a one-time localhost or explicitly requested private-LAN form and save it to a dotenv or raw file without placing plaintext in Codex chat or MCP output. Use when a task needs a user-supplied secret written locally, including requests involving .env, .env.local, API credentials, database passwords, signing secrets, provider tokens, remote hosts, or LAN access.
---

# Inline Keys

Keep the plaintext value outside the conversation. Use the `inline_keys` MCP tools; never ask the user to paste a credential into chat or a normal user-input form.

## Workflow

1. Determine the exact destination from repository conventions without reading existing secret values. Prefer ignored, untracked credential files.
2. Use `request_secret` with an absolute `target_path`, a public label, and the correct format:
   - Use `dotenv` with `env_var` for `.env`-style files.
   - Use `raw` only when the entire file should contain the submitted value.
   - Omit `access` or use `localhost` by default.
   - When the user explicitly asks to open the form from another private-network device, use `access: "lan"`. State before the call that LAN mode may use observable HTTP unless TLS certificate paths are configured, then set `allow_insecure_lan: true` only for that explicit request. The page separately requires the user to confirm unencrypted transport.
   - Omit `lan_host` to auto-select an assigned RFC1918 address. Use a `100.64.0.0/10` address only when the user explicitly names an assigned trusted-overlay address such as their Tailscale IP; shared carrier space is not automatically trusted.
3. Present the returned URL as a clickable Markdown link. State the exact destination, `transport_security`, and that submission writes directly to it. For `private_lan_http`, repeat that another device on the network may observe the value; for `private_lan_https`, note that the browser must trust the configured certificate.
4. Stop and let the user submit the form. Do not open, fetch, inspect, or POST to the URL yourself.
5. After the user says the form was submitted, call `get_secret_request` and report only its status and destination metadata.
6. Continue the original task without displaying or verifying the plaintext value. Verify only through the consuming program when needed.

## Safety rules

- Never request, print, quote, summarize, or inspect a plaintext secret.
- Never use commands that reveal the destination file after submission, including `cat`, `sed`, `grep`, `rg`, `head`, `tail`, or shell expansion of the saved variable.
- Treat the URL as short-lived request capability metadata. Do not access it with browser, web, shell, or computer-use tools.
- Use `replace_existing: true` only when the user explicitly asked to replace a raw secret file. Dotenv mode updates do not use this flag.
- If the target is tracked by Git, warn the user and choose an ignored file unless they explicitly confirm the tracked destination.
- Do not claim that saving into a workspace file makes the credential permanently inaccessible to Codex. Inline Keys protects entry and MCP output; filesystem permissions still govern later access.
- Keep localhost as the default. Use LAN mode only for an explicit user request and only with a private IPv4 address assigned to the host.
- Never expose the form through a public address, router port-forward, public tunnel, or unrelated reverse proxy. A `100.64.0.0/10` address is allowed only when explicitly selected for a known trusted overlay.
- Never set `allow_insecure_lan` merely for convenience. It acknowledges that HTTP protects the secret from Codex chat but not from network observation.

## Failure handling

- If a request expires, create a fresh request rather than reusing its URL.
- If LAN mode reports `lan_unavailable` or `lan_host_not_assigned`, explain that the host has no usable assigned private address or that the requested address is not local. Retry without `lan_host` only when auto-selection is appropriate.
- If the page reports a path, symlink, duplicate-variable, or write error, correct the public destination metadata and create a new request. Never ask for the secret again in chat.
- If dotenv mode reports `unsupported_dotenv_value`, use raw mode only when the consuming application supports a one-secret file; otherwise direct the user to the application's credential store. Do not transform or inspect the secret.
- Use `cancel_secret_request` when the destination is wrong or the user declines.
