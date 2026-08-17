#!/usr/bin/env node

import readline from 'node:readline';
import { InlineKeysError, InlineKeysService } from './inline-keys.mjs';

const MCP_PROTOCOL_VERSION = '2025-06-18';
const SUPPORTED_PROTOCOL_VERSIONS = new Set(['2025-06-18', '2025-03-26', '2024-11-05']);
let negotiatedProtocolVersion = MCP_PROTOCOL_VERSION;
const service = new InlineKeysService();

const TOOLS = [
  {
    name: 'request_secret',
    title: 'Open a private secret form',
    description: 'Create a short-lived localhost or explicitly requested private-LAN form that writes a user-entered secret directly to a dotenv entry or raw file. The plaintext is never returned through MCP. Do not open or submit the returned URL on the user\'s behalf.',
    inputSchema: {
      type: 'object',
      properties: {
        label: { type: 'string', minLength: 1, maxLength: 120, description: 'Public label shown above the secret field.' },
        reason: { type: 'string', minLength: 1, maxLength: 300, description: 'Public explanation of why the project needs this credential.' },
        target_path: { type: 'string', minLength: 1, description: 'Absolute destination file path shown to the user for approval.' },
        format: { type: 'string', enum: ['dotenv', 'raw'], default: 'dotenv' },
        env_var: { type: 'string', pattern: '^[A-Za-z_][A-Za-z0-9_]{0,127}$', description: 'Required for dotenv format; omitted for raw format.' },
        replace_existing: { type: 'boolean', default: false, description: 'Required to replace an existing raw file. Dotenv updates do not use this flag.' },
        ttl_seconds: { type: 'integer', minimum: 60, maximum: 900, default: 300 },
        access: { type: 'string', enum: ['localhost', 'lan'], default: 'localhost', description: 'Use lan only when the user explicitly asks to open the form from another private-network device.' },
        lan_host: { type: 'string', description: 'Optional private IPv4 address assigned to this machine. Omit to auto-select a private interface.' },
        allow_insecure_lan: { type: 'boolean', default: false, description: 'Acknowledge unencrypted private-LAN HTTP when TLS is not configured. Set true only after the user explicitly requests LAN access and understands the network-observation risk.' },
      },
      required: ['label', 'target_path', 'format'],
      additionalProperties: false,
    },
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
  },
  {
    name: 'get_secret_request',
    title: 'Check a secret request',
    description: 'Return value-blind status and destination metadata for an Inline Keys request.',
    inputSchema: {
      type: 'object',
      properties: { request_id: { type: 'string', format: 'uuid' } },
      required: ['request_id'],
      additionalProperties: false,
    },
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
  },
  {
    name: 'cancel_secret_request',
    title: 'Cancel a secret request',
    description: 'Invalidate a pending Inline Keys form without writing a value.',
    inputSchema: {
      type: 'object',
      properties: { request_id: { type: 'string', format: 'uuid' } },
      required: ['request_id'],
      additionalProperties: false,
    },
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
  },
];

function send(message) {
  process.stdout.write(`${JSON.stringify(message)}\n`);
}

function toolResult(result) {
  return {
    content: [{ type: 'text', text: JSON.stringify(result) }],
    structuredContent: result,
  };
}

function validateRequestInput(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    throw new InlineKeysError('invalid_request', 'Tool arguments must be an object.');
  }
  const allowed = new Set([
    'label',
    'reason',
    'target_path',
    'format',
    'env_var',
    'replace_existing',
    'ttl_seconds',
    'access',
    'lan_host',
    'allow_insecure_lan',
  ]);
  if (Object.keys(input).some((key) => !allowed.has(key))) {
    throw new InlineKeysError('invalid_request', 'Tool arguments contain an unsupported field.');
  }
  if ((input.format ?? 'dotenv') === 'dotenv' && !input.env_var) {
    throw new InlineKeysError('invalid_env_var', 'env_var is required for dotenv format.');
  }
  if ((input.format ?? 'dotenv') === 'raw' && input.env_var !== undefined) {
    throw new InlineKeysError('invalid_env_var', 'env_var must be omitted for raw format.');
  }
  if (input.replace_existing !== undefined && typeof input.replace_existing !== 'boolean') {
    throw new InlineKeysError('invalid_request', 'replace_existing must be a boolean.');
  }
  if (input.ttl_seconds !== undefined
    && (!Number.isInteger(input.ttl_seconds) || input.ttl_seconds < 60 || input.ttl_seconds > 900)) {
    throw new InlineKeysError('invalid_request', 'ttl_seconds must be an integer from 60 to 900.');
  }
  const access = input.access ?? 'localhost';
  if (!['localhost', 'lan'].includes(access)) {
    throw new InlineKeysError('invalid_access', 'access must be localhost or lan.');
  }
  if (input.lan_host !== undefined && typeof input.lan_host !== 'string') {
    throw new InlineKeysError('invalid_lan_host', 'lan_host must be a string.');
  }
  if (input.allow_insecure_lan !== undefined && typeof input.allow_insecure_lan !== 'boolean') {
    throw new InlineKeysError('invalid_request', 'allow_insecure_lan must be a boolean.');
  }
  if (access !== 'lan' && (input.lan_host !== undefined || input.allow_insecure_lan !== undefined)) {
    throw new InlineKeysError('invalid_request', 'LAN options require access set to lan.');
  }
}

async function callTool(name, args) {
  if (name === 'request_secret') {
    validateRequestInput(args);
    return service.createRequest(args);
  }
  if (name === 'get_secret_request') return service.getRequest(args?.request_id);
  if (name === 'cancel_secret_request') return service.cancelRequest(args?.request_id);
  throw new InlineKeysError('unknown_tool', `Unknown tool: ${name}`);
}

async function handle(message) {
  if (!message || message.jsonrpc !== '2.0') return;
  if (message.method === 'notifications/initialized' || message.method === 'notifications/cancelled') return;
  if (message.id === undefined) return;
  try {
    if (message.method === 'initialize') {
      const requested = message.params?.protocolVersion;
      negotiatedProtocolVersion = SUPPORTED_PROTOCOL_VERSIONS.has(requested) ? requested : MCP_PROTOCOL_VERSION;
      send({
        jsonrpc: '2.0',
        id: message.id,
        result: {
          protocolVersion: negotiatedProtocolVersion,
          capabilities: { tools: { listChanged: false } },
          serverInfo: { name: 'inline-keys', title: 'Inline Keys', version: '0.1.0' },
        },
      });
      return;
    }
    if (message.method === 'ping') {
      send({ jsonrpc: '2.0', id: message.id, result: {} });
      return;
    }
    if (message.method === 'tools/list') {
      send({ jsonrpc: '2.0', id: message.id, result: { tools: TOOLS } });
      return;
    }
    if (message.method === 'resources/list') {
      send({ jsonrpc: '2.0', id: message.id, result: { resources: [] } });
      return;
    }
    if (message.method === 'resources/templates/list') {
      send({ jsonrpc: '2.0', id: message.id, result: { resourceTemplates: [] } });
      return;
    }
    if (message.method === 'tools/call') {
      try {
        const result = await callTool(message.params?.name, message.params?.arguments ?? {});
        send({ jsonrpc: '2.0', id: message.id, result: toolResult(result) });
      } catch (error) {
        const body = {
          ok: false,
          code: error instanceof InlineKeysError ? error.code : 'internal_error',
          error: error instanceof Error ? error.message : String(error),
        };
        send({
          jsonrpc: '2.0',
          id: message.id,
          result: { isError: true, content: [{ type: 'text', text: JSON.stringify(body) }] },
        });
      }
      return;
    }
    send({ jsonrpc: '2.0', id: message.id, error: { code: -32601, message: 'Method not found' } });
  } catch (error) {
    send({
      jsonrpc: '2.0',
      id: message.id,
      error: { code: -32603, message: error instanceof Error ? error.message : String(error) },
    });
  }
}

const input = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });
const inflight = new Set();
input.on('line', (line) => {
  if (!line.trim()) return;
  try {
    const pending = handle(JSON.parse(line));
    inflight.add(pending);
    void pending.finally(() => inflight.delete(pending));
  } catch {
    send({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } });
  }
});
input.on('close', () => {
  void Promise.allSettled([...inflight]).finally(() => service.close());
});
