import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, stat, symlink, writeFile } from 'node:fs/promises';
import { request as httpRequest } from 'node:http';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { parseEnv } from 'node:util';
import {
  InlineKeysError,
  InlineKeysService,
  isPrivateIpv4,
  resolveLanHost,
  resolveSafeTarget,
  updateDotenv,
  writeSecret,
} from '../mcp/inline-keys.mjs';

async function temporaryDirectory() {
  return mkdtemp(path.join(os.tmpdir(), 'inline-keys-test-'));
}

function extractFormToken(source) {
  const match = /name="form_token" type="hidden" value="([A-Za-z0-9_-]{43})"/u.exec(source);
  assert.ok(match, 'form contains a random anti-CSRF token');
  return match[1];
}

const TEST_INTERFACES = {
  eth0: [{ address: '172.20.0.4', family: 'IPv4', internal: false }],
  wifi: [{ address: '192.168.50.9', family: 'IPv4', internal: false }],
  public: [{ address: '203.0.113.8', family: 'IPv4', internal: false }],
};

test('updateDotenv creates and updates one named entry', () => {
  const created = updateDotenv('PORT=3000\n', 'SERVICE_API_KEY', 'example-token');
  assert.equal(created, 'PORT=3000\nSERVICE_API_KEY=example-token\n');
  const updated = updateDotenv(created, 'SERVICE_API_KEY', 'replacement-token');
  assert.equal(updated, 'PORT=3000\nSERVICE_API_KEY=replacement-token\n');
});

test('updateDotenv rejects ambiguous duplicate entries', () => {
  assert.throws(
    () => updateDotenv('TOKEN=one\nexport TOKEN=two\n', 'TOKEN', 'replacement'),
    (error) => error instanceof InlineKeysError && error.code === 'duplicate_env_var',
  );
});

test('updateDotenv preserves common punctuation under Node dotenv parsing', () => {
  const secrets = ['price$with\\backslash', 'space # hash $ dollar \\ slash " quote'];
  let source = '';
  for (const [index, secret] of secrets.entries()) {
    const name = `SECRET_${index}`;
    source = updateDotenv(source, name, secret);
    assert.equal(parseEnv(source)[name], secret);
  }
  assert.equal(updateDotenv('', 'SHELL_ACTIVE', 'value$HOME;next'), "SHELL_ACTIVE='value$HOME;next'\n");
  assert.throws(
    () => updateDotenv('', 'SECRET', "space and ' apostrophe"),
    (error) => error instanceof InlineKeysError && error.code === 'unsupported_dotenv_value',
  );
});

test('concurrent dotenv writes to one file preserve every update', async () => {
  const root = await temporaryDirectory();
  const target = path.join(root, '.env');
  await Promise.all([
    writeSecret({ targetPath: target, format: 'dotenv', envVar: 'FIRST_KEY', secret: 'first', allowedRoots: [root] }),
    writeSecret({ targetPath: target, format: 'dotenv', envVar: 'SECOND_KEY', secret: 'second', allowedRoots: [root] }),
  ]);
  assert.deepEqual(parseEnv(await readFile(target, 'utf8')), { FIRST_KEY: 'first', SECOND_KEY: 'second' });
});

test('resolveSafeTarget rejects symlink targets and paths outside allowed roots', async () => {
  const root = await temporaryDirectory();
  const outside = await temporaryDirectory();
  await writeFile(path.join(root, 'real.env'), '', { mode: 0o600 });
  await symlink(path.join(root, 'real.env'), path.join(root, 'linked.env'));
  await assert.rejects(
    resolveSafeTarget(path.join(root, 'linked.env'), [root]),
    (error) => error instanceof InlineKeysError && error.code === 'symlink_target',
  );
  await assert.rejects(
    resolveSafeTarget(path.join(outside, '.env'), [root]),
    (error) => error instanceof InlineKeysError && error.code === 'outside_allowed_roots',
  );
});

test('LAN host selection accepts only assigned private IPv4 interfaces', () => {
  assert.equal(resolveLanHost(undefined, TEST_INTERFACES), '192.168.50.9');
  assert.equal(resolveLanHost('172.20.0.4', TEST_INTERFACES), '172.20.0.4');
  assert.equal(isPrivateIpv4('100.64.1.2'), true);
  assert.equal(isPrivateIpv4('203.0.113.8'), false);
  assert.throws(
    () => resolveLanHost('203.0.113.8', TEST_INTERFACES),
    (error) => error instanceof InlineKeysError && error.code === 'invalid_lan_host',
  );
  assert.throws(
    () => resolveLanHost('192.168.50.10', TEST_INTERFACES),
    (error) => error instanceof InlineKeysError && error.code === 'lan_host_not_assigned',
  );
  assert.throws(
    () => resolveLanHost(undefined, {
      tailscale0: [{ address: '100.64.1.2', family: 'IPv4', internal: false }],
    }),
    (error) => error instanceof InlineKeysError && error.code === 'lan_unavailable',
  );
  assert.equal(resolveLanHost('100.64.1.2', {
    tailscale0: [{ address: '100.64.1.2', family: 'IPv4', internal: false }],
  }), '100.64.1.2');
});

test('LAN mode requires explicit insecure transport confirmation when TLS is absent', () => {
  const service = new InlineKeysService({ getNetworkInterfaces: () => TEST_INTERFACES });
  assert.throws(
    () => service.resolveEndpoint({ access: 'lan' }),
    (error) => error instanceof InlineKeysError && error.code === 'insecure_lan_confirmation_required',
  );
  assert.equal(service.resolveEndpoint({ access: 'lan', allow_insecure_lan: true }).transport_security, 'private_lan_http');
  const tlsService = new InlineKeysService({
    getNetworkInterfaces: () => TEST_INTERFACES,
    tlsCertFile: '/configured/cert.pem',
    tlsKeyFile: '/configured/key.pem',
  });
  assert.equal(tlsService.resolveEndpoint({ access: 'lan' }).transport_security, 'private_lan_https');
});

test('localhost form saves a dotenv value without reflecting it', async (context) => {
  const root = await temporaryDirectory();
  const target = path.join(root, '.env.local');
  const service = new InlineKeysService({ allowedRoots: [root], defaultTtlSeconds: 60 });
  context.after(() => service.close());
  const request = await service.createRequest({
    label: 'Service API key',
    reason: 'Integration test',
    target_path: target,
    format: 'dotenv',
    env_var: 'SERVICE_API_KEY',
  });
  const page = await fetch(request.open_url);
  assert.equal(page.status, 200);
  assert.equal(page.headers.get('cache-control'), 'no-store, max-age=0');
  const formToken = extractFormToken(await page.text());

  const secret = 'test-value-not-for-output';
  const submitted = await fetch(request.open_url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({ form_token: formToken, secret, confirm: 'yes' }),
  });
  const responseBody = await submitted.text();
  assert.equal(submitted.status, 200);
  assert.equal(responseBody.includes(secret), false);
  const status = service.getRequest(request.request_id);
  assert.equal(status.status, 'saved');
  assert.equal(status.operation, 'created');
  assert.equal(JSON.stringify(status).includes(secret), false);
  const saved = await readFile(target, 'utf8');
  assert.equal(saved, `SERVICE_API_KEY=${secret}\n`);
  if (process.platform !== 'win32') assert.equal((await stat(target)).mode & 0o777, 0o600);

  const replay = await fetch(request.open_url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      Origin: new URL(request.open_url).origin,
    },
    body: new URLSearchParams({ form_token: formToken, secret: 'second-value', confirm: 'yes' }),
  });
  assert.equal(replay.status, 404);
  assert.equal(await readFile(target, 'utf8'), `SERVICE_API_KEY=${secret}\n`);
});

test('raw mode refuses replacement unless it was explicitly requested', async (context) => {
  const root = await temporaryDirectory();
  const target = path.join(root, 'credential.txt');
  await writeFile(target, 'existing', { mode: 0o600 });
  const service = new InlineKeysService({ allowedRoots: [root], defaultTtlSeconds: 60 });
  context.after(() => service.close());
  const request = await service.createRequest({
    label: 'Raw credential',
    target_path: target,
    format: 'raw',
  });
  const formToken = extractFormToken(await (await fetch(request.open_url)).text());
  const submitted = await fetch(request.open_url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      Origin: new URL(request.open_url).origin,
    },
    body: new URLSearchParams({ form_token: formToken, secret: 'replacement', confirm: 'yes' }),
  });
  assert.equal(submitted.status, 400);
  assert.equal(service.getRequest(request.request_id).error_code, 'replace_not_approved');
  assert.equal(await readFile(target, 'utf8'), 'existing');
});

test('form rejects a mismatched origin', async (context) => {
  const root = await temporaryDirectory();
  await mkdir(path.join(root, 'nested'));
  const service = new InlineKeysService({ allowedRoots: [root], defaultTtlSeconds: 60 });
  context.after(() => service.close());
  const request = await service.createRequest({
    label: 'Database password',
    target_path: path.join(root, 'nested', '.env'),
    format: 'dotenv',
    env_var: 'DATABASE_PASSWORD',
  });
  const formToken = extractFormToken(await (await fetch(request.open_url)).text());
  const submitted = await fetch(request.open_url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      Origin: 'http://example.invalid',
    },
    body: new URLSearchParams({ form_token: formToken, secret: 'not-written', confirm: 'yes' }),
  });
  assert.equal(submitted.status, 403);
  assert.equal(service.getRequest(request.request_id).status, 'pending');
});

test('form rejects a missing or invalid page token when Origin is unavailable', async (context) => {
  const root = await temporaryDirectory();
  const target = path.join(root, '.env');
  const service = new InlineKeysService({ allowedRoots: [root], defaultTtlSeconds: 60 });
  context.after(() => service.close());
  const request = await service.createRequest({
    label: 'Protected API key',
    target_path: target,
    format: 'dotenv',
    env_var: 'PROTECTED_API_KEY',
  });
  const submitted = await fetch(request.open_url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ form_token: 'invalid', secret: 'not-written', confirm: 'yes' }),
  });
  assert.equal(submitted.status, 403);
  assert.equal(service.getRequest(request.request_id).status, 'pending');
  await assert.rejects(readFile(target, 'utf8'), (error) => error?.code === 'ENOENT');
});

test('cancelling an in-flight POST prevents a delayed secret write', async (context) => {
  const root = await temporaryDirectory();
  const target = path.join(root, '.env');
  let signalBodyStart;
  const bodyStarted = new Promise((resolve) => { signalBodyStart = resolve; });
  class ObservedInlineKeysService extends InlineKeysService {
    async readBody(incoming) {
      signalBodyStart();
      return super.readBody(incoming);
    }
  }
  const service = new ObservedInlineKeysService({ allowedRoots: [root], defaultTtlSeconds: 60 });
  context.after(() => service.close());
  const request = await service.createRequest({
    label: 'Delayed request',
    target_path: target,
    format: 'dotenv',
    env_var: 'DELAYED_SECRET',
  });
  const formToken = extractFormToken(await (await fetch(request.open_url)).text());
  let outgoing;
  const responsePromise = new Promise((resolve, reject) => {
    outgoing = httpRequest(request.open_url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Origin: new URL(request.open_url).origin,
      },
    }, (response) => {
      response.resume();
      response.once('end', () => resolve(response.statusCode));
    });
    outgoing.once('error', reject);
    outgoing.write(`form_token=${encodeURIComponent(formToken)}&secret=delayed-sentinel`);
  });
  await bodyStarted;
  service.cancelRequest(request.request_id);
  outgoing.end('&confirm=yes');
  assert.equal(await responsePromise, 410);
  assert.equal(service.getRequest(request.request_id).status, 'cancelled');
  await assert.rejects(readFile(target, 'utf8'), (error) => error?.code === 'ENOENT');
});

test('concurrent request creation waits for one shared localhost listener', async (context) => {
  const root = await temporaryDirectory();
  const service = new InlineKeysService({ allowedRoots: [root], defaultTtlSeconds: 60 });
  context.after(() => service.close());
  const requests = await Promise.all([
    service.createRequest({ label: 'First', target_path: path.join(root, '.env'), format: 'dotenv', env_var: 'FIRST' }),
    service.createRequest({ label: 'Second', target_path: path.join(root, '.env'), format: 'dotenv', env_var: 'SECOND' }),
  ]);
  assert.equal(new URL(requests[0].open_url).port, new URL(requests[1].open_url).port);
  assert.notEqual(new URL(requests[0].open_url).port, 'undefined');
});

test('a new request cancels an idle listener close before returning its URL', async (context) => {
  const root = await temporaryDirectory();
  const service = new InlineKeysService({ allowedRoots: [root], defaultTtlSeconds: 60 });
  context.after(() => service.close());
  const first = await service.createRequest({
    label: 'First',
    target_path: path.join(root, '.env'),
    format: 'dotenv',
    env_var: 'FIRST',
  });
  service.cancelRequest(first.request_id);
  assert.notEqual(service.listeners.get('localhost').idle_close_timer, undefined);
  const second = await service.createRequest({
    label: 'Second',
    target_path: path.join(root, '.env'),
    format: 'dotenv',
    env_var: 'SECOND',
  });
  assert.equal(service.listeners.get('localhost').idle_close_timer, undefined);
  assert.equal((await fetch(second.open_url)).status, 200);
});

test('private-LAN form binds an assigned interface and writes without reflection', async (context) => {
  let lanHost;
  try {
    lanHost = resolveLanHost();
  } catch (error) {
    if (error instanceof InlineKeysError && error.code === 'lan_unavailable') {
      context.skip('No assigned private IPv4 interface is available in this test environment.');
      return;
    }
    throw error;
  }
  const root = await temporaryDirectory();
  const target = path.join(root, '.env.lan');
  const service = new InlineKeysService({ allowedRoots: [root], defaultTtlSeconds: 60 });
  context.after(() => service.close());
  const request = await service.createRequest({
    label: 'LAN API key',
    target_path: target,
    format: 'dotenv',
    env_var: 'LAN_API_KEY',
    access: 'lan',
    lan_host: lanHost,
    allow_insecure_lan: true,
  });
  assert.equal(new URL(request.open_url).hostname, lanHost);
  assert.equal(request.access, 'lan');
  assert.equal(request.bind_host, lanHost);
  assert.equal(request.transport_security, 'private_lan_http');
  const page = await fetch(request.open_url);
  assert.equal(page.status, 200);
  const pageBody = await page.text();
  assert.match(pageBody, /unencrypted HTTP/u);
  const formToken = extractFormToken(pageBody);

  const secret = 'lan-sentinel-not-for-output';
  const unconfirmed = await fetch(request.open_url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      Origin: 'null',
    },
    body: new URLSearchParams({ form_token: formToken, secret, confirm: 'yes' }),
  });
  assert.equal(unconfirmed.status, 400);
  assert.equal(service.getRequest(request.request_id).status, 'pending');

  const submitted = await fetch(request.open_url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({ form_token: formToken, secret, confirm: 'yes', confirm_insecure_lan: 'yes' }),
  });
  assert.equal(submitted.status, 200);
  assert.equal((await submitted.text()).includes(secret), false);
  assert.equal(service.getRequest(request.request_id).status, 'saved');
  assert.equal(await readFile(target, 'utf8'), `LAN_API_KEY=${secret}\n`);
});
