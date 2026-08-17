import { randomBytes, randomUUID } from 'node:crypto';
import { createServer } from 'node:http';
import { createServer as createHttpsServer } from 'node:https';
import {
  lstat,
  open,
  readFile,
  realpath,
  rename,
  stat,
  unlink,
} from 'node:fs/promises';
import { networkInterfaces } from 'node:os';
import path from 'node:path';

const DEFAULT_TTL_SECONDS = 300;
const MIN_TTL_SECONDS = 60;
const MAX_TTL_SECONDS = 900;
const DEFAULT_MAX_SECRET_BYTES = 64 * 1024;
const MIN_MAX_SECRET_BYTES = 1024;
const MAX_MAX_SECRET_BYTES = 1024 * 1024;
const MAX_DOTENV_BYTES = 2 * 1024 * 1024;
const MAX_PENDING_REQUESTS = 64;
const MAX_RECORDED_REQUESTS = 256;
const TERMINAL_RECORD_TTL_MS = 60 * 60 * 1000;
const IDLE_LISTENER_CLOSE_DELAY_MS = 5000;
const LOOPBACK_HOST = '127.0.0.1';
const targetWriteLocks = new Map();

export class InlineKeysError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'InlineKeysError';
    this.code = code;
  }
}

function boundedInteger(value, fallback, minimum, maximum) {
  const parsed = Number.parseInt(String(value ?? ''), 10);
  if (!Number.isInteger(parsed)) return fallback;
  return Math.min(maximum, Math.max(minimum, parsed));
}

function html(value) {
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

function safePublicText(value, field, maximum = 240) {
  if (typeof value !== 'string') throw new InlineKeysError('invalid_request', `${field} must be a string.`);
  const normalized = value.trim();
  if (!normalized || normalized.length > maximum || /[\u0000-\u001f\u007f]/u.test(normalized)) {
    throw new InlineKeysError('invalid_request', `${field} is empty or invalid.`);
  }
  return normalized;
}

function isWithin(root, candidate) {
  const relative = path.relative(root, candidate);
  return relative === '' || (!relative.startsWith(`..${path.sep}`) && relative !== '..' && !path.isAbsolute(relative));
}

function normalizeIpv4(address) {
  const value = String(address ?? '');
  return value.startsWith('::ffff:') ? value.slice(7) : value;
}

export function isPrivateIpv4(address) {
  const normalized = normalizeIpv4(address);
  if (!/^(?:\d{1,3}\.){3}\d{1,3}$/u.test(normalized)) return false;
  const parts = normalized.split('.').map((part) => Number.parseInt(part, 10));
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return false;
  const [first, second] = parts;
  return first === 10
    || (first === 172 && second >= 16 && second <= 31)
    || (first === 192 && second === 168)
    || (first === 100 && second >= 64 && second <= 127)
    || (first === 169 && second === 254);
}

function isRfc1918Ipv4(address) {
  const normalized = normalizeIpv4(address);
  if (!/^(?:\d{1,3}\.){3}\d{1,3}$/u.test(normalized)) return false;
  const [first, second] = normalized.split('.').map((part) => Number.parseInt(part, 10));
  return first === 10
    || (first === 172 && second >= 16 && second <= 31)
    || (first === 192 && second === 168);
}

function lanAddressRank(address) {
  if (address.startsWith('192.168.')) return 0;
  if (address.startsWith('10.')) return 1;
  if (address.startsWith('172.')) return 2;
  if (address.startsWith('100.')) return 3;
  return 4;
}

export function resolveLanHost(requestedHost, interfaces = networkInterfaces()) {
  const candidates = Object.values(interfaces)
    .flatMap((entries) => entries ?? [])
    .filter((entry) => (entry.family === 'IPv4' || entry.family === 4) && !entry.internal)
    .map((entry) => normalizeIpv4(entry.address))
    .filter(isPrivateIpv4);
  if (requestedHost !== undefined) {
    if (typeof requestedHost !== 'string' || !isPrivateIpv4(requestedHost)) {
      throw new InlineKeysError('invalid_lan_host', 'lan_host must be a private IPv4 address.');
    }
    if (!candidates.includes(requestedHost)) {
      throw new InlineKeysError('lan_host_not_assigned', 'lan_host is not assigned to this machine.');
    }
    return requestedHost;
  }
  const automaticallySelectable = candidates
    .filter(isRfc1918Ipv4)
    .sort((left, right) => lanAddressRank(left) - lanAddressRank(right) || left.localeCompare(right));
  if (automaticallySelectable.length === 0) {
    throw new InlineKeysError('lan_unavailable', 'This machine has no assigned RFC1918 private IPv4 interface.');
  }
  return automaticallySelectable[0];
}

async function existingType(target) {
  try {
    const details = await lstat(target);
    if (details.isSymbolicLink()) throw new InlineKeysError('symlink_target', 'The destination must not be a symbolic link.');
    if (!details.isFile()) throw new InlineKeysError('invalid_target', 'The destination must be a regular file.');
    return 'file';
  } catch (error) {
    if (error?.code === 'ENOENT') return 'missing';
    throw error;
  }
}

export async function resolveSafeTarget(targetPath, allowedRoots = []) {
  if (typeof targetPath !== 'string' || !path.isAbsolute(targetPath) || targetPath.includes('\u0000')) {
    throw new InlineKeysError('invalid_target', 'target_path must be an absolute path.');
  }
  const normalized = path.resolve(targetPath);
  const basename = path.basename(normalized);
  if (!basename || basename === '.' || basename === '..') {
    throw new InlineKeysError('invalid_target', 'target_path must name a file.');
  }

  const parent = await realpath(path.dirname(normalized)).catch((error) => {
    if (error?.code === 'ENOENT') throw new InlineKeysError('missing_parent', 'The destination directory does not exist.');
    throw error;
  });
  const resolved = path.join(parent, basename);
  await existingType(resolved);

  if (allowedRoots.length > 0) {
    const resolvedRoots = await Promise.all(allowedRoots.map(async (root) => realpath(root).catch(() => path.resolve(root))));
    if (!resolvedRoots.some((root) => isWithin(root, resolved))) {
      throw new InlineKeysError('outside_allowed_roots', 'The destination is outside INLINE_KEYS_ALLOWED_ROOTS.');
    }
  }
  return resolved;
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/gu, '\\$&');
}

function encodeDotenvValue(secret) {
  if (/^[A-Za-z0-9_./:@%+,=\-]+$/u.test(secret)) return secret;
  if (!secret.includes("'")) return `'${secret}'`;
  throw new InlineKeysError(
    'unsupported_dotenv_value',
    'This value cannot be represented portably in dotenv syntax. Use raw format or a credential store.',
  );
}

export function updateDotenv(source, envVar, secret) {
  if (!/^[A-Za-z_][A-Za-z0-9_]{0,127}$/u.test(envVar)) {
    throw new InlineKeysError('invalid_env_var', 'env_var must be a valid environment variable name.');
  }
  if (secret.includes('\u0000') || /[\r\n]/u.test(secret)) {
    throw new InlineKeysError('invalid_dotenv_value', 'Dotenv values must be a single line without NUL bytes.');
  }
  const newline = source.includes('\r\n') ? '\r\n' : '\n';
  const hadTrailingNewline = source.endsWith('\n');
  const lines = source.length === 0 ? [] : source.split(/\r?\n/u);
  if (hadTrailingNewline) lines.pop();
  const matcher = new RegExp(`^\\s*(?:export\\s+)?${escapeRegExp(envVar)}\\s*=`, 'u');
  const matches = lines.flatMap((line, index) => (matcher.test(line) ? [index] : []));
  if (matches.length > 1) {
    throw new InlineKeysError('duplicate_env_var', `The destination contains more than one ${envVar} entry.`);
  }
  const replacement = `${envVar}=${encodeDotenvValue(secret)}`;
  if (matches.length === 1) lines[matches[0]] = replacement;
  else lines.push(replacement);
  return `${lines.join(newline)}${newline}`;
}

async function atomicOwnerOnlyWrite(target, content) {
  const parent = path.dirname(target);
  const temp = path.join(parent, `.${path.basename(target)}.inline-keys-${randomBytes(12).toString('hex')}`);
  let handle;
  try {
    handle = await open(temp, 'wx', 0o600);
    await handle.writeFile(content);
    await handle.sync();
    await handle.close();
    handle = undefined;
    await rename(temp, target);
  } catch (error) {
    await handle?.close().catch(() => {});
    await unlink(temp).catch(() => {});
    throw error;
  }
}

async function withTargetWriteLock(target, operation) {
  const previous = targetWriteLocks.get(target) ?? Promise.resolve();
  let release;
  const current = new Promise((resolve) => {
    release = resolve;
  });
  targetWriteLocks.set(target, current);
  await previous;
  try {
    return await operation();
  } finally {
    release();
    if (targetWriteLocks.get(target) === current) targetWriteLocks.delete(target);
  }
}

export async function writeSecret({ targetPath, format, envVar, secret, replaceExisting, allowedRoots = [] }) {
  const target = await resolveSafeTarget(targetPath, allowedRoots);
  return withTargetWriteLock(target, async () => {
    const revalidatedTarget = await resolveSafeTarget(targetPath, allowedRoots);
    if (revalidatedTarget !== target) {
      throw new InlineKeysError('target_changed', 'The destination changed before the write began.');
    }
    const targetType = await existingType(target);
    if (format === 'raw') {
      if (targetType === 'file' && !replaceExisting) {
        throw new InlineKeysError('replace_not_approved', 'The raw destination already exists and replacement was not approved.');
      }
      await atomicOwnerOnlyWrite(target, secret);
      return { target_path: target, operation: targetType === 'file' ? 'replaced' : 'created' };
    }
    if (format !== 'dotenv') throw new InlineKeysError('invalid_format', 'format must be dotenv or raw.');
    let source = '';
    if (targetType === 'file') {
      const details = await stat(target);
      if (details.size > MAX_DOTENV_BYTES) throw new InlineKeysError('dotenv_too_large', 'The dotenv destination is too large to update safely.');
      source = await readFile(target, 'utf8');
    }
    const updated = updateDotenv(source, envVar, secret);
    await atomicOwnerOnlyWrite(target, updated);
    return { target_path: target, operation: targetType === 'file' ? 'updated' : 'created' };
  });
}

function commonHeaders(cspNonce) {
  return {
    'Cache-Control': 'no-store, max-age=0',
    'Content-Security-Policy': `default-src 'none'; style-src 'nonce-${cspNonce}'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'`,
    'Cross-Origin-Opener-Policy': 'same-origin',
    'Cross-Origin-Resource-Policy': 'same-origin',
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=(), usb=()',
    Pragma: 'no-cache',
    'Referrer-Policy': 'no-referrer',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
  };
}

function renderForm(request) {
  const nonce = randomBytes(18).toString('base64url');
  const field = request.format === 'dotenv'
    ? '<input id="secret" name="secret" type="password" autocomplete="new-password" spellcheck="false" required autofocus>'
    : '<textarea id="secret" name="secret" autocomplete="off" spellcheck="false" required autofocus rows="10"></textarea>';
  const destination = request.format === 'dotenv'
    ? `${html(request.env_var)} in ${html(request.target_path)}`
    : html(request.target_path);
  const transportMessage = request.access === 'lan'
    ? request.transport_security === 'private_lan_https'
      ? 'This form is available only on a private network interface and uses HTTPS.'
      : 'Warning: this private-network form uses unencrypted HTTP. Other devices on the network may be able to observe the submitted value.'
    : 'The value is sent only to this localhost process.';
  const transportClass = request.transport_security === 'private_lan_http' ? 'warning' : '';
  const insecureLanConfirmation = request.transport_security === 'private_lan_http'
    ? '<label class="confirm warning"><input name="confirm_insecure_lan" type="checkbox" value="yes" required><span>I understand this unencrypted HTTP submission may be observed by another device on the network.</span></label>'
    : '';
  const body = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Inline Keys</title>
  <style nonce="${nonce}">
    :root { color-scheme: light dark; font-family: ui-sans-serif, system-ui, sans-serif; }
    body { margin: 0; min-height: 100vh; display: grid; place-items: center; background: #0b1020; color: #eef2ff; }
    main { width: min(92vw, 34rem); background: #131a2d; border: 1px solid #334155; border-radius: 16px; padding: 1.5rem; box-shadow: 0 18px 60px #0008; }
    h1 { margin: 0 0 .35rem; font-size: 1.35rem; }
    p { color: #cbd5e1; line-height: 1.45; }
    .destination { overflow-wrap: anywhere; padding: .75rem; border-radius: 10px; background: #090e1a; color: #93c5fd; font-family: ui-monospace, monospace; }
    label { display: block; margin: 1rem 0 .4rem; font-weight: 650; }
    input, textarea { box-sizing: border-box; width: 100%; border: 1px solid #475569; border-radius: 10px; padding: .8rem; background: #070b14; color: #fff; font: inherit; }
    .confirm { display: flex; gap: .6rem; align-items: flex-start; font-weight: 400; color: #cbd5e1; }
    .confirm input { width: auto; margin-top: .2rem; }
    button { width: 100%; margin-top: 1rem; border: 0; border-radius: 10px; padding: .85rem; background: #2563eb; color: white; font: inherit; font-weight: 700; cursor: pointer; }
    small { display: block; margin-top: .8rem; color: #94a3b8; }
    .warning { color: #fca5a5; font-weight: 650; }
  </style>
</head>
<body>
  <main>
    <h1>${html(request.label)}</h1>
    <p>${html(request.reason || 'Save this credential without placing it in Codex chat.')}</p>
    <div class="destination">${destination}</div>
    <form method="post" autocomplete="off">
      <label for="secret">Secret value</label>
      ${field}
      <label class="confirm"><input name="confirm" type="checkbox" value="yes" required><span>I approve writing this value to the exact destination shown above.</span></label>
      ${insecureLanConfirmation}
      <button type="submit">Save securely</button>
    </form>
    <small class="${transportClass}">This one-time form expires at ${html(request.expires_at)}. ${html(transportMessage)}</small>
  </main>
</body>
</html>`;
  return { nonce, body };
}

function renderResult(title, message) {
  const nonce = randomBytes(18).toString('base64url');
  const body = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>${html(title)}</title><style nonce="${nonce}">:root{color-scheme:light dark;font-family:ui-sans-serif,system-ui,sans-serif}body{min-height:100vh;margin:0;display:grid;place-items:center;background:#0b1020;color:#eef2ff}main{width:min(90vw,32rem);padding:1.5rem;border:1px solid #334155;border-radius:16px;background:#131a2d}p{color:#cbd5e1;line-height:1.5}</style></head><body><main><h1>${html(title)}</h1><p>${html(message)}</p></main></body></html>`;
  return { nonce, body };
}

function parseAllowedRoots(value) {
  if (!value) return [];
  return String(value).split(path.delimiter).map((entry) => entry.trim()).filter(Boolean).map((entry) => path.resolve(entry));
}

export class InlineKeysService {
  constructor(options = {}) {
    this.allowedRoots = options.allowedRoots ?? parseAllowedRoots(process.env.INLINE_KEYS_ALLOWED_ROOTS);
    this.defaultTtlSeconds = boundedInteger(
      options.defaultTtlSeconds ?? process.env.INLINE_KEYS_DEFAULT_TTL_SECONDS,
      DEFAULT_TTL_SECONDS,
      MIN_TTL_SECONDS,
      MAX_TTL_SECONDS,
    );
    this.maxSecretBytes = boundedInteger(
      options.maxSecretBytes ?? process.env.INLINE_KEYS_MAX_SECRET_BYTES,
      DEFAULT_MAX_SECRET_BYTES,
      MIN_MAX_SECRET_BYTES,
      MAX_MAX_SECRET_BYTES,
    );
    this.tlsCertFile = options.tlsCertFile ?? process.env.INLINE_KEYS_TLS_CERT_FILE;
    this.tlsKeyFile = options.tlsKeyFile ?? process.env.INLINE_KEYS_TLS_KEY_FILE;
    this.getNetworkInterfaces = options.getNetworkInterfaces ?? networkInterfaces;
    this.requests = new Map();
    this.listeners = new Map();
    this.startPromises = new Map();
  }

  resolveEndpoint(input) {
    const access = input.access ?? 'localhost';
    if (!['localhost', 'lan'].includes(access)) {
      throw new InlineKeysError('invalid_access', 'access must be localhost or lan.');
    }
    if (access === 'localhost') {
      if (input.lan_host !== undefined || input.allow_insecure_lan !== undefined) {
        throw new InlineKeysError('invalid_request', 'LAN options require access set to lan.');
      }
      return {
        key: 'localhost',
        access,
        bind_host: LOOPBACK_HOST,
        advertise_host: LOOPBACK_HOST,
        protocol: 'http',
        transport_security: 'loopback_http',
      };
    }
    const host = resolveLanHost(input.lan_host, this.getNetworkInterfaces());
    const hasCertificate = Boolean(this.tlsCertFile);
    const hasKey = Boolean(this.tlsKeyFile);
    if (hasCertificate !== hasKey) {
      throw new InlineKeysError('incomplete_tls_configuration', 'Configure both INLINE_KEYS_TLS_CERT_FILE and INLINE_KEYS_TLS_KEY_FILE.');
    }
    if (!hasCertificate && input.allow_insecure_lan !== true) {
      throw new InlineKeysError(
        'insecure_lan_confirmation_required',
        'LAN mode has no TLS certificate. Set allow_insecure_lan only after the user explicitly requests unencrypted private-network access.',
      );
    }
    const protocol = hasCertificate ? 'https' : 'http';
    return {
      key: `lan:${protocol}:${host}`,
      access,
      bind_host: host,
      advertise_host: host,
      protocol,
      transport_security: hasCertificate ? 'private_lan_https' : 'private_lan_http',
    };
  }

  async ensureListener(configuration) {
    const existing = this.listeners.get(configuration.key);
    if (existing?.server.listening) {
      clearTimeout(existing.idle_close_timer);
      existing.idle_close_timer = undefined;
      return existing;
    }
    const pending = this.startPromises.get(configuration.key);
    if (pending) return pending;
    const startPromise = this.startListening(configuration);
    this.startPromises.set(configuration.key, startPromise);
    try {
      return await startPromise;
    } finally {
      if (this.startPromises.get(configuration.key) === startPromise) {
        this.startPromises.delete(configuration.key);
      }
    }
  }

  async startListening(configuration) {
    const endpoint = {
      ...configuration,
      port: undefined,
      origin: undefined,
      server: undefined,
      idle_close_timer: undefined,
    };
    let server;
    if (configuration.protocol === 'https') {
      const [cert, key] = await Promise.all([readFile(this.tlsCertFile), readFile(this.tlsKeyFile)]).catch(() => {
        throw new InlineKeysError('tls_configuration_unreadable', 'Inline Keys could not read the configured TLS certificate and key.');
      });
      server = createHttpsServer({ cert, key }, (request, response) => {
        void this.handleHttp(request, response, endpoint);
      });
    } else {
      server = createServer((request, response) => {
        void this.handleHttp(request, response, endpoint);
      });
    }
    endpoint.server = server;
    server.on('clientError', (_error, socket) => socket.destroy());
    try {
      await new Promise((resolve, reject) => {
        server.once('error', reject);
        server.listen(0, configuration.bind_host, () => {
          server.off('error', reject);
          resolve();
        });
      });
    } catch (error) {
      throw new InlineKeysError(
        'bind_failed',
        `Could not bind an Inline Keys listener to ${configuration.bind_host}.`,
      );
    }
    const address = server.address();
    if (!address || typeof address === 'string') {
      await new Promise((resolve) => server.close(() => resolve()));
      throw new InlineKeysError('bind_failed', 'Could not determine the Inline Keys listener port.');
    }
    endpoint.port = address.port;
    endpoint.origin = `${configuration.protocol}://${configuration.advertise_host}:${address.port}`;
    this.listeners.set(configuration.key, endpoint);
    return endpoint;
  }

  async close() {
    for (const request of this.requests.values()) clearTimeout(request.timer);
    this.requests.clear();
    const listeners = [...this.listeners.values()];
    this.listeners.clear();
    this.startPromises.clear();
    for (const endpoint of listeners) clearTimeout(endpoint.idle_close_timer);
    await Promise.all(listeners.map(({ server }) => new Promise((resolve) => server.close(() => resolve()))));
  }

  closeListenerIfIdle(endpointKey) {
    const hasActiveRequest = [...this.requests.values()].some((request) => (
      request.endpoint_key === endpointKey && ['pending', 'writing'].includes(request.status)
    ));
    if (hasActiveRequest) return;
    const endpoint = this.listeners.get(endpointKey);
    if (!endpoint) return;
    this.listeners.delete(endpointKey);
    clearTimeout(endpoint.idle_close_timer);
    endpoint.idle_close_timer = undefined;
    endpoint.server.close(() => {});
  }

  scheduleListenerCloseIfIdle(endpointKey) {
    const endpoint = this.listeners.get(endpointKey);
    if (!endpoint) return;
    clearTimeout(endpoint.idle_close_timer);
    endpoint.idle_close_timer = setTimeout(
      () => this.closeListenerIfIdle(endpointKey),
      IDLE_LISTENER_CLOSE_DELAY_MS,
    );
    endpoint.idle_close_timer.unref?.();
  }

  publicStatus(request) {
    return {
      request_id: request.id,
      status: request.status,
      label: request.label,
      target_path: request.target_path,
      format: request.format,
      env_var: request.env_var ?? null,
      access: request.access,
      bind_host: request.bind_host,
      transport_security: request.transport_security,
      operation: request.operation ?? null,
      error_code: request.error_code ?? null,
      created_at: request.created_at,
      expires_at: request.expires_at,
      completed_at: request.completed_at ?? null,
    };
  }

  pruneRequests() {
    const cutoff = Date.now() - TERMINAL_RECORD_TTL_MS;
    for (const [id, request] of this.requests) {
      if (request.status !== 'pending' && Date.parse(request.completed_at ?? request.expires_at) < cutoff) {
        this.requests.delete(id);
      }
    }
    if (this.requests.size <= MAX_RECORDED_REQUESTS) return;
    const terminal = [...this.requests.values()]
      .filter((request) => request.status !== 'pending')
      .sort((left, right) => Date.parse(left.created_at) - Date.parse(right.created_at));
    for (const request of terminal) {
      if (this.requests.size <= MAX_RECORDED_REQUESTS) break;
      this.requests.delete(request.id);
    }
  }

  async createRequest(input) {
    this.pruneRequests();
    const pendingCount = [...this.requests.values()].filter((request) => request.status === 'pending').length;
    if (pendingCount >= MAX_PENDING_REQUESTS) {
      throw new InlineKeysError('too_many_pending_requests', 'Cancel or complete an existing Inline Keys request first.');
    }
    const label = safePublicText(input.label, 'label', 120);
    const reason = input.reason === undefined ? '' : safePublicText(input.reason, 'reason', 300);
    const format = input.format ?? 'dotenv';
    if (!['dotenv', 'raw'].includes(format)) throw new InlineKeysError('invalid_format', 'format must be dotenv or raw.');
    const envVar = format === 'dotenv' ? safePublicText(input.env_var, 'env_var', 128) : undefined;
    if (envVar && !/^[A-Za-z_][A-Za-z0-9_]{0,127}$/u.test(envVar)) {
      throw new InlineKeysError('invalid_env_var', 'env_var must be a valid environment variable name.');
    }
    const target = await resolveSafeTarget(input.target_path, this.allowedRoots);
    const ttlSeconds = boundedInteger(input.ttl_seconds, this.defaultTtlSeconds, MIN_TTL_SECONDS, MAX_TTL_SECONDS);
    const endpointConfiguration = this.resolveEndpoint(input);
    const endpoint = await this.ensureListener(endpointConfiguration);
    const now = Date.now();
    const id = randomUUID();
    const browserToken = randomBytes(32).toString('base64url');
    const request = {
      id,
      browser_token: browserToken,
      label,
      reason,
      target_path: target,
      format,
      env_var: envVar,
      replace_existing: input.replace_existing === true,
      endpoint_key: endpoint.key,
      access: endpoint.access,
      bind_host: endpoint.bind_host,
      transport_security: endpoint.transport_security,
      status: 'pending',
      created_at: new Date(now).toISOString(),
      expires_at: new Date(now + ttlSeconds * 1000).toISOString(),
    };
    request.timer = setTimeout(() => {
      if (request.status === 'pending') {
        request.status = 'expired';
        request.browser_token = undefined;
        request.completed_at = new Date().toISOString();
        this.scheduleListenerCloseIfIdle(request.endpoint_key);
      }
    }, ttlSeconds * 1000);
    request.timer.unref?.();
    this.requests.set(id, request);
    return {
      ...this.publicStatus(request),
      open_url: `${endpoint.origin}/request/${id}/${browserToken}`,
    };
  }

  getRequest(id) {
    const request = this.requests.get(id);
    if (!request) throw new InlineKeysError('request_not_found', 'No Inline Keys request has that ID.');
    return this.publicStatus(request);
  }

  cancelRequest(id) {
    const request = this.requests.get(id);
    if (!request) throw new InlineKeysError('request_not_found', 'No Inline Keys request has that ID.');
    if (request.status === 'pending') {
      request.status = 'cancelled';
      request.browser_token = undefined;
      request.completed_at = new Date().toISOString();
      clearTimeout(request.timer);
      this.scheduleListenerCloseIfIdle(request.endpoint_key);
    }
    return this.publicStatus(request);
  }

  async readBody(incoming) {
    const chunks = [];
    let size = 0;
    for await (const chunk of incoming) {
      size += chunk.length;
      if (size > this.maxSecretBytes * 3 + 4096) throw new InlineKeysError('secret_too_large', 'The submitted value is too large.');
      chunks.push(chunk);
    }
    return Buffer.concat(chunks).toString('utf8');
  }

  sendHtml(response, status, page) {
    response.writeHead(status, {
      ...commonHeaders(page.nonce),
      'Content-Type': 'text/html; charset=utf-8',
    });
    response.end(page.body);
  }

  async handleHttp(incoming, response, endpoint) {
    try {
      const remoteAddress = normalizeIpv4(incoming.socket.remoteAddress);
      const allowedClient = endpoint.access === 'localhost'
        ? remoteAddress === LOOPBACK_HOST
        : remoteAddress === LOOPBACK_HOST || isPrivateIpv4(remoteAddress);
      if (!allowedClient) {
        response.writeHead(403, { 'Cache-Control': 'no-store' });
        response.end();
        return;
      }
      const expectedHost = `${endpoint.advertise_host}:${endpoint.port}`;
      if (incoming.headers.host !== expectedHost) {
        response.writeHead(421, { 'Cache-Control': 'no-store' });
        response.end();
        return;
      }
      const parsed = new URL(incoming.url ?? '/', endpoint.origin);
      const match = /^\/request\/([0-9a-f-]{36})\/([A-Za-z0-9_-]{43})$/u.exec(parsed.pathname);
      if (!match || parsed.search) {
        this.sendHtml(response, 404, renderResult('Not found', 'This Inline Keys form does not exist.'));
        return;
      }
      const request = this.requests.get(match[1]);
      if (!request || request.browser_token !== match[2] || request.endpoint_key !== endpoint.key) {
        this.sendHtml(response, 404, renderResult('Not found', 'This Inline Keys form does not exist.'));
        return;
      }
      if (request.status !== 'pending') {
        const message = request.status === 'saved'
          ? 'The credential was saved. Return to Codex and say that the form is complete.'
          : `This form is ${request.status} and cannot accept a value.`;
        this.sendHtml(response, request.status === 'saved' ? 200 : 410, renderResult('Inline Keys', message));
        return;
      }
      if (incoming.method === 'GET') {
        this.sendHtml(response, 200, renderForm(request));
        return;
      }
      if (incoming.method !== 'POST') {
        response.writeHead(405, { Allow: 'GET, POST', 'Cache-Control': 'no-store' });
        response.end();
        return;
      }
      if (incoming.headers.origin !== endpoint.origin) {
        this.sendHtml(response, 403, renderResult('Request rejected', 'The form submission did not come from the expected Inline Keys page.'));
        return;
      }
      const contentType = String(incoming.headers['content-type'] ?? '').split(';', 1)[0].trim().toLowerCase();
      if (contentType !== 'application/x-www-form-urlencoded') {
        this.sendHtml(response, 415, renderResult('Request rejected', 'Unsupported form encoding.'));
        return;
      }
      const body = await this.readBody(incoming);
      if (request.status === 'pending' && Date.now() >= Date.parse(request.expires_at)) {
        request.status = 'expired';
        request.browser_token = undefined;
        request.completed_at = new Date().toISOString();
        clearTimeout(request.timer);
        this.scheduleListenerCloseIfIdle(request.endpoint_key);
      }
      if (request.status !== 'pending'
        || request.browser_token !== match[2]
        || request.endpoint_key !== endpoint.key) {
        this.sendHtml(response, 410, renderResult('Form no longer active', 'This Inline Keys form was cancelled or expired before submission completed.'));
        return;
      }
      const fields = new URLSearchParams(body);
      const secret = fields.get('secret');
      if (fields.get('confirm') !== 'yes' || typeof secret !== 'string' || secret.length === 0) {
        this.sendHtml(response, 400, renderResult('Nothing saved', 'Enter a value and confirm the exact destination.'));
        return;
      }
      if (request.transport_security === 'private_lan_http' && fields.get('confirm_insecure_lan') !== 'yes') {
        this.sendHtml(response, 400, renderResult('Nothing saved', 'Confirm the unencrypted private-network transport before submitting.'));
        return;
      }
      if (Buffer.byteLength(secret, 'utf8') > this.maxSecretBytes) {
        this.sendHtml(response, 413, renderResult('Nothing saved', 'The submitted value exceeds the configured size limit.'));
        return;
      }
      request.status = 'writing';
      try {
        const result = await writeSecret({
          targetPath: request.target_path,
          format: request.format,
          envVar: request.env_var,
          secret,
          replaceExisting: request.replace_existing,
          allowedRoots: this.allowedRoots,
        });
        request.status = 'saved';
        request.browser_token = undefined;
        request.operation = result.operation;
        request.error_code = undefined;
        request.completed_at = new Date().toISOString();
        clearTimeout(request.timer);
        this.sendHtml(response, 200, renderResult('Credential saved', 'Return to Codex and say that the Inline Keys form is complete.'));
        this.scheduleListenerCloseIfIdle(request.endpoint_key);
      } catch (error) {
        request.status = Date.now() >= Date.parse(request.expires_at) ? 'expired' : 'pending';
        if (request.status === 'expired') {
          request.browser_token = undefined;
          request.completed_at = new Date().toISOString();
          this.scheduleListenerCloseIfIdle(request.endpoint_key);
        }
        request.error_code = error instanceof InlineKeysError ? error.code : 'write_failed';
        this.sendHtml(response, 400, renderResult('Nothing saved', `Inline Keys could not write the destination (${request.error_code}). Correct the destination and create a new request.`));
      }
    } catch (error) {
      const code = error instanceof InlineKeysError ? error.code : 'request_failed';
      this.sendHtml(response, 400, renderResult('Nothing saved', `Inline Keys rejected the request (${code}).`));
    }
  }
}
