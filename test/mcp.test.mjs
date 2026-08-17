import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import readline from 'node:readline';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const TEST_DIRECTORY = path.dirname(fileURLToPath(import.meta.url));

test('MCP transcript remains value-blind through form submission', async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'inline-keys-mcp-test-'));
  const child = spawn(process.execPath, ['--no-warnings', './mcp/server.mjs', '--stdio'], {
    cwd: path.resolve(TEST_DIRECTORY, '..'),
    env: {
      ...process.env,
      INLINE_KEYS_ALLOWED_ROOTS: root,
    },
    stdio: ['pipe', 'pipe', 'pipe'],
  });
  context.after(() => {
    if (child.exitCode === null) child.kill('SIGTERM');
  });

  const pending = new Map();
  const transcript = [];
  let stderr = '';
  child.stderr.setEncoding('utf8');
  child.stderr.on('data', (chunk) => { stderr += chunk; });
  const lines = readline.createInterface({ input: child.stdout, crlfDelay: Infinity });
  lines.on('line', (line) => {
    transcript.push(line);
    const message = JSON.parse(line);
    const waiter = pending.get(message.id);
    if (waiter) {
      pending.delete(message.id);
      waiter.resolve(message);
    }
  });

  let nextId = 1;
  const request = (method, params = undefined) => new Promise((resolve, reject) => {
    const id = nextId;
    nextId += 1;
    const timer = setTimeout(() => {
      pending.delete(id);
      reject(new Error(`Timed out waiting for ${method}`));
    }, 3000);
    pending.set(id, {
      resolve: (message) => {
        clearTimeout(timer);
        resolve(message);
      },
    });
    child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id, method, params })}\n`);
  });

  const initialized = await request('initialize', {
    protocolVersion: '2025-06-18',
    capabilities: {},
    clientInfo: { name: 'inline-keys-test', version: '1.0.0' },
  });
  assert.equal(initialized.result.serverInfo.name, 'inline-keys');

  const tools = await request('tools/list');
  const requestSecret = tools.result.tools.find((tool) => tool.name === 'request_secret');
  assert.deepEqual(requestSecret.inputSchema.properties.access.enum, ['localhost', 'lan']);
  assert.equal(requestSecret.inputSchema.properties.allow_insecure_lan.type, 'boolean');
  assert.equal(requestSecret.annotations.openWorldHint, true);

  const resources = await request('resources/list');
  assert.deepEqual(resources.result.resources, []);

  const created = await request('tools/call', {
    name: 'request_secret',
    arguments: {
      label: 'Transcript test key',
      target_path: path.join(root, '.env.local'),
      format: 'dotenv',
      env_var: 'TRANSCRIPT_TEST_KEY',
    },
  });
  const metadata = created.result.structuredContent;
  assert.equal(metadata.status, 'pending');
  const page = await fetch(metadata.open_url);
  const pageBody = await page.text();
  const formTokenMatch = /name="form_token" type="hidden" value="([A-Za-z0-9_-]{43})"/u.exec(pageBody);
  assert.ok(formTokenMatch);

  const secret = 'mcp-transcript-sentinel-value';
  const submitted = await fetch(metadata.open_url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({ form_token: formTokenMatch[1], secret, confirm: 'yes' }),
  });
  assert.equal(submitted.status, 200);

  const checked = await request('tools/call', {
    name: 'get_secret_request',
    arguments: { request_id: metadata.request_id },
  });
  assert.equal(checked.result.structuredContent.status, 'saved');
  if (transcript.join('\n').includes(secret)) assert.fail('MCP transcript exposed the submitted value');
  assert.equal(stderr, '');

  child.stdin.end();
  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('MCP server did not exit after stdin closed')), 3000);
    child.once('exit', (code) => {
      clearTimeout(timer);
      if (code === 0) resolve();
      else reject(new Error(`MCP server exited with code ${code}`));
    });
  });
});
