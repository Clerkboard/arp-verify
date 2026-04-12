#!/usr/bin/env node
/**
 * ARP Endpoint Verification CLI
 *
 * Runs a sequence of checks against a live ARP endpoint and reports
 * pass/fail for each one. Exits 0 if all pass, 1 if any fail.
 *
 * Usage:
 *   npx arp-verify agents.mycompany.com
 *   npx arp-verify agents.mycompany.com --agent order-processor
 *   npx arp-verify localhost:3141
 */

import crypto from 'node:crypto';
import bs58 from 'bs58';
import _canonicalize from 'canonicalize';
const canonicalize = _canonicalize as unknown as (obj: unknown) => string | undefined;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface AgentCard {
  arp: string;
  name: string;
  did: string;
  inbox: string;
  publicKey: string;
  description: string;
  capabilities: Array<{
    name: string;
    description: string;
    schema: Record<string, unknown>;
    responseSchema: Record<string, unknown>;
  }>;
  auth: {
    required: boolean;
    methods: string[];
    openAccess: boolean;
    allowlist: string[];
    denylist: string[];
  };
  rateLimit?: { requests: number; window: string };
  contact?: string;
}

interface AgentIndex {
  domain: string;
  protocol: string;
  agents: Array<{
    name: string;
    url: string;
    summary: string;
    tags?: string[];
  }>;
  pagination?: { hasMore: boolean; total: number };
}

interface DIDDocument {
  '@context': string;
  id: string;
  verificationMethod: Array<{
    id: string;
    type: string;
    controller: string;
    publicKeyMultibase: string;
  }>;
  authentication: string[];
  service: Array<{
    id: string;
    type: string;
    serviceEndpoint: string;
  }>;
}

interface ARPMessage {
  arp: string;
  id: string;
  type: string;
  from: string;
  to: string;
  capability?: string;
  correlationId?: string;
  createdAt: string;
  expiresAt?: string;
  body: Record<string, unknown>;
  signature?: string;
}

interface CheckResult {
  name: string;
  passed: boolean;
  message: string;
  warning?: boolean;
}

// ---------------------------------------------------------------------------
// Crypto helpers (same approach as arp-server-ts)
// ---------------------------------------------------------------------------

const ED25519_SPKI_HEADER = Buffer.from('302a300506032b6570032100', 'hex');

function rawPublicKey(publicKey: crypto.KeyObject): Buffer {
  const spki = publicKey.export({ type: 'spki', format: 'der' }) as Buffer;
  return spki.subarray(spki.length - 32);
}

function encodeMultibase(raw: Buffer): string {
  return 'z' + bs58.encode(raw);
}

function decodeMultibase(mb: string): Buffer {
  if (!mb.startsWith('z')) {
    throw new Error(`Unsupported multibase prefix: ${mb[0]}`);
  }
  return Buffer.from(bs58.decode(mb.slice(1)));
}

function importPublicKey(keyOrMultibase: string | Buffer): crypto.KeyObject {
  const raw = typeof keyOrMultibase === 'string'
    ? decodeMultibase(keyOrMultibase)
    : keyOrMultibase;
  if (raw.length !== 32) {
    throw new Error(`Expected 32-byte Ed25519 public key, got ${raw.length} bytes`);
  }
  return crypto.createPublicKey({
    key: Buffer.concat([ED25519_SPKI_HEADER, raw]),
    format: 'der',
    type: 'spki',
  });
}

function generateKeyPair(): { privateKey: crypto.KeyObject; publicKeyMultibase: string; did: string } {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const pubMultibase = encodeMultibase(rawPublicKey(publicKey));
  const did = `did:key:${pubMultibase}`;
  return { privateKey, publicKeyMultibase: pubMultibase, did };
}

function signMessage(message: ARPMessage, privateKey: crypto.KeyObject): ARPMessage {
  const { signature: _sig, ...rest } = message;
  const canonical = canonicalize(rest);
  if (canonical === undefined) {
    throw new Error('JCS canonicalization returned undefined');
  }
  const payload = Buffer.from(canonical, 'utf-8');
  const sig = crypto.sign(null, payload, privateKey);
  message.signature = encodeMultibase(sig);
  return message;
}

function verifyMessageSignature(message: ARPMessage, publicKey: crypto.KeyObject): boolean {
  if (!message.signature) return false;
  const sigBytes = decodeMultibase(message.signature);
  const { signature: _sig, ...rest } = message;
  const canonical = canonicalize(rest);
  if (canonical === undefined) return false;
  const payload = Buffer.from(canonical, 'utf-8');
  return crypto.verify(null, payload, publicKey, sigBytes);
}

function newMessageId(): string {
  return `msg_${crypto.randomUUID()}`;
}

function nowISO(): string {
  return new Date().toISOString();
}

// ---------------------------------------------------------------------------
// CLI argument parsing
// ---------------------------------------------------------------------------

function parseArgs(): { domain: string; agentName?: string } {
  const args = process.argv.slice(2);
  if (args.length === 0 || args.includes('--help') || args.includes('-h')) {
    console.log(`
ARP Endpoint Verification CLI

Usage:
  arp-verify <domain[:port]> [--agent <name>]

Examples:
  arp-verify agents.mycompany.com
  arp-verify agents.mycompany.com --agent order-processor
  arp-verify localhost:3141

Options:
  --agent <name>   Test a specific agent (default: first from index)
  --help, -h       Show this help
`);
    process.exit(0);
  }

  const domain = args[0];
  let agentName: string | undefined;

  const agentIdx = args.indexOf('--agent');
  if (agentIdx !== -1 && agentIdx + 1 < args.length) {
    agentName = args[agentIdx + 1];
  }

  return { domain, agentName };
}

// ---------------------------------------------------------------------------
// URL helpers
// ---------------------------------------------------------------------------

function isLocalhost(domain: string): boolean {
  const host = domain.split(':')[0];
  return host === 'localhost' || host === '127.0.0.1';
}

function baseUrl(domain: string): string {
  const scheme = isLocalhost(domain) ? 'http' : 'https';
  return `${scheme}://${domain}`;
}

// ---------------------------------------------------------------------------
// HTTP helper with timeout
// ---------------------------------------------------------------------------

async function fetchJSON(url: string, options?: RequestInit): Promise<{ status: number; body: unknown; ok: boolean }> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 10_000);
  try {
    const res = await fetch(url, { ...options, signal: controller.signal });
    let body: unknown;
    const ct = res.headers.get('content-type') ?? '';
    if (ct.includes('json')) {
      body = await res.json();
    } else {
      body = await res.text();
    }
    return { status: res.status, body, ok: res.ok };
  } finally {
    clearTimeout(timeout);
  }
}

// ---------------------------------------------------------------------------
// Check runners
// ---------------------------------------------------------------------------

const results: CheckResult[] = [];

function pass(name: string, message: string) {
  results.push({ name, passed: true, message });
}

function fail(name: string, message: string) {
  results.push({ name, passed: false, message });
}

function warn(name: string, message: string) {
  results.push({ name, passed: true, message, warning: true });
}

// ---------------------------------------------------------------------------
// Main verification flow
// ---------------------------------------------------------------------------

async function run() {
  const { domain, agentName: requestedAgent } = parseArgs();
  const base = baseUrl(domain);

  console.log('');
  console.log('ARP Endpoint Verification');
  console.log(`Target: ${domain}`);
  console.log('');

  // -- State shared across checks --
  let agentIndex: AgentIndex | undefined;
  let agentCard: AgentCard | undefined;
  let didDoc: DIDDocument | undefined;
  let agentName: string | undefined;
  let serverPublicKey: crypto.KeyObject | undefined;

  // 1. agents.txt
  try {
    const url = `${base}/agents.txt`;
    const res = await fetchJSON(url);
    const text = typeof res.body === 'string' ? res.body : JSON.stringify(res.body);
    if (!res.ok) {
      fail('agents.txt', `HTTP ${res.status} from ${url}. Ensure your server exposes GET /agents.txt returning a text file with an "arp-index:" line.`);
    } else if (!text.includes('arp-index:')) {
      fail('agents.txt', `File found but missing "arp-index:" directive. The agents.txt file must contain a line like: arp-index: ${base}/.well-known/arp/index.json`);
    } else {
      pass('agents.txt', 'agents.txt found');
      if (!text.includes('arp-version:')) {
        warn('agents.txt', 'Missing "arp-version:" field. Recommended: arp-version: 1.0');
      }
      if (!text.includes('arp-docs:')) {
        warn('agents.txt', 'Missing "arp-docs:" field. Recommended: link to protocol documentation for AI agent discovery.');
      }
    }
  } catch (err) {
    fail('agents.txt', `Could not reach ${base}/agents.txt — ${(err as Error).message}. Is the server running at ${domain}?`);
  }

  // 2. Agent Index
  try {
    const url = `${base}/.well-known/arp/index.json`;
    const res = await fetchJSON(url);
    if (!res.ok) {
      fail('Agent Index', `HTTP ${res.status} from ${url}. Ensure your server exposes GET /.well-known/arp/index.json returning the agent index.`);
    } else {
      const data = res.body as Record<string, unknown>;
      const missing: string[] = [];
      if (!data.domain) missing.push('domain');
      if (!data.protocol) missing.push('protocol');
      if (!Array.isArray(data.agents)) missing.push('agents (array)');
      if (missing.length > 0) {
        fail('Agent Index', `Index JSON is missing required fields: ${missing.join(', ')}. The index must contain: domain, protocol, and an agents array.`);
      } else {
        agentIndex = data as unknown as AgentIndex;
        const count = agentIndex.agents.length;
        pass('Agent Index', `Agent index valid (${count} agent${count !== 1 ? 's' : ''})`);
      }
    }
  } catch (err) {
    fail('Agent Index', `Could not fetch agent index — ${(err as Error).message}. Ensure /.well-known/arp/index.json is served.`);
  }

  // Determine which agent to test
  if (requestedAgent) {
    agentName = requestedAgent;
  } else if (agentIndex && agentIndex.agents.length > 0) {
    agentName = agentIndex.agents[0].name;
  }

  if (!agentName) {
    fail('Agent Card', 'Cannot determine agent name. Either pass --agent <name> or ensure the index has at least one agent entry.');
    printResults();
    return;
  }

  // 3. Agent Card
  try {
    const url = `${base}/.well-known/arp/${agentName}.json`;
    const res = await fetchJSON(url);
    if (!res.ok) {
      fail('Agent Card', `HTTP ${res.status} from ${url}. Ensure your server exposes the agent card at /.well-known/arp/${agentName}.json`);
    } else {
      const data = res.body as Record<string, unknown>;
      const required = ['arp', 'name', 'did', 'inbox', 'publicKey', 'description', 'capabilities', 'auth'];
      const missing = required.filter(f => data[f] === undefined || data[f] === null);
      if (missing.length > 0) {
        fail('Agent Card', `Agent card missing required fields: ${missing.join(', ')}. See the ARP spec for the full AgentCard schema.`);
      } else {
        agentCard = data as unknown as AgentCard;
        pass('Agent Card', `Agent Card valid: ${agentName}`);
      }
    }
  } catch (err) {
    fail('Agent Card', `Could not fetch agent card — ${(err as Error).message}`);
  }

  // 4. DID Document
  try {
    const url = `${base}/${agentName}/did.json`;
    const res = await fetchJSON(url);
    if (!res.ok) {
      fail('DID Document', `HTTP ${res.status} from ${url}. Ensure your server exposes GET /${agentName}/did.json returning the DID document.`);
    } else {
      const data = res.body as Record<string, unknown>;
      const required = ['@context', 'id', 'verificationMethod', 'authentication', 'service'];
      const missing = required.filter(f => data[f] === undefined || data[f] === null);
      if (missing.length > 0) {
        fail('DID Document', `DID document missing required fields: ${missing.join(', ')}. The document must include @context, id, verificationMethod, authentication, and service.`);
      } else {
        didDoc = data as unknown as DIDDocument;
        pass('DID Document', 'DID document valid');
      }
    }
  } catch (err) {
    fail('DID Document', `Could not fetch DID document — ${(err as Error).message}`);
  }

  // 5. Key Consistency
  if (agentCard && didDoc) {
    const cardKey = agentCard.publicKey;
    const vm = didDoc.verificationMethod;
    if (!vm || vm.length === 0) {
      fail('Key Consistency', 'DID document has no verificationMethod entries. Add at least one Ed25519VerificationKey2020 entry.');
    } else {
      const didKey = vm[0].publicKeyMultibase;
      if (cardKey === didKey) {
        pass('Key Consistency', 'Agent Card matches DID doc');
        try {
          serverPublicKey = importPublicKey(cardKey);
        } catch (err) {
          fail('Key Consistency', `Key is present but invalid: ${(err as Error).message}`);
        }
      } else {
        fail('Key Consistency', `Agent Card key (${cardKey.slice(0, 8)}...) does not match DID doc key (${didKey.slice(0, 8)}...). Both must use the same Ed25519 public key.`);
        // Still try to import for subsequent checks
        try {
          serverPublicKey = importPublicKey(cardKey);
        } catch {
          // ignore
        }
      }
    }
  } else {
    fail('Key Consistency', 'Cannot check key consistency — Agent Card or DID document was not retrieved. Fix the previous failures first.');
  }

  // 6. Inbox Reachable (unsigned POST)
  const inboxUrl = agentCard?.inbox ?? `${base}/${agentName}/inbox`;
  try {
    const unsignedMsg = {
      arp: '1.0',
      id: newMessageId(),
      type: 'request',
      from: 'did:key:test-unsigned',
      to: agentCard?.did ?? `did:web:${domain}:${agentName}`,
      createdAt: nowISO(),
      body: { test: true },
    };
    const res = await fetchJSON(inboxUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/arp+json' },
      body: JSON.stringify(unsignedMsg),
    });
    if (res.status === 404) {
      fail('Inbox Reachable', `Inbox returned 404 at ${inboxUrl}. Ensure the inbox route is configured and accessible.`);
    } else {
      // We expect a structured error (SCHEMA_INVALID for missing signature, or FIRST_CONTACT_REQUIRED, etc.)
      const body = res.body as Record<string, unknown>;
      const innerBody = body?.body as Record<string, unknown> | undefined;
      if (innerBody && typeof innerBody.code === 'string') {
        pass('Inbox Reachable', 'Inbox reachable (returns structured errors)');
      } else if (typeof body === 'object' && body !== null) {
        pass('Inbox Reachable', 'Inbox reachable (returns structured errors)');
      } else {
        fail('Inbox Reachable', `Inbox returned HTTP ${res.status} but the response is not a structured ARP error. The inbox should return ARP error messages (with body.code) for invalid requests.`);
      }
    }
  } catch (err) {
    fail('Inbox Reachable', `Could not reach inbox at ${inboxUrl} — ${(err as Error).message}. Ensure the server is running and the inbox URL is correct.`);
  }

  // 7. Signature Verification / Negotiate (first-contact)
  const clientKeys = generateKeyPair();
  const agentDid = agentCard?.did ?? `did:web:${domain}:${agentName}`;

  let negotiateOk = false;
  try {
    const negotiateMsg: ARPMessage = {
      arp: '1.0',
      id: newMessageId(),
      type: 'negotiate',
      from: clientKeys.did,
      to: agentDid,
      createdAt: nowISO(),
      body: {
        firstContact: true,
        publicKey: clientKeys.publicKeyMultibase,
      },
    };
    signMessage(negotiateMsg, clientKeys.privateKey);

    const res = await fetchJSON(inboxUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/arp+json' },
      body: JSON.stringify(negotiateMsg),
    });

    if (res.status === 200) {
      const body = res.body as ARPMessage;
      if (body.type === 'acknowledge') {
        negotiateOk = true;
        pass('First-Contact Negotiate', 'First-contact negotiate accepted');
      } else {
        fail('First-Contact Negotiate', `Server returned 200 but type="${body.type}" instead of "acknowledge". The negotiate response should be type "acknowledge".`);
      }
    } else {
      const body = res.body as Record<string, unknown>;
      const innerBody = body?.body as Record<string, unknown> | undefined;
      const errMsg = innerBody?.message ?? JSON.stringify(body);
      fail('First-Contact Negotiate', `Server returned HTTP ${res.status}: ${errMsg}. A signed negotiate message with firstContact=true should be accepted with 200.`);
    }
  } catch (err) {
    fail('First-Contact Negotiate', `Negotiate request failed — ${(err as Error).message}`);
  }

  // 8. Echo Test
  const hasEcho = agentCard?.capabilities?.some(c => c.name === 'echo') ?? false;
  let echoResponse: ARPMessage | undefined;

  if (!hasEcho) {
    pass('Echo Test', 'Echo capability not listed — skipped');
  } else if (!negotiateOk) {
    fail('Echo Test', 'Skipped — negotiate failed. Fix the negotiate check first.');
  } else {
    try {
      const echoMsg: ARPMessage = {
        arp: '1.0',
        id: newMessageId(),
        type: 'request',
        from: clientKeys.did,
        to: agentDid,
        capability: 'echo',
        createdAt: nowISO(),
        body: { ping: 'hello', timestamp: Date.now() },
      };
      signMessage(echoMsg, clientKeys.privateKey);

      const res = await fetchJSON(inboxUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/arp+json' },
        body: JSON.stringify(echoMsg),
      });

      if (res.status === 200) {
        const body = res.body as ARPMessage;
        if (body.type === 'response') {
          echoResponse = body;
          pass('Echo Test', 'Echo capability works');
        } else {
          fail('Echo Test', `Server returned 200 but type="${body.type}" instead of "response". Echo requests should return type "response".`);
        }
      } else {
        fail('Echo Test', `Echo request returned HTTP ${res.status}. A signed request with capability "echo" should return 200 with the echoed body.`);
      }
    } catch (err) {
      fail('Echo Test', `Echo request failed — ${(err as Error).message}`);
    }
  }

  // 9. Signature on Response
  if (!serverPublicKey) {
    fail('Server Signatures', 'Cannot verify — server public key not available. Fix the Agent Card or Key Consistency check first.');
  } else if (!echoResponse && !negotiateOk) {
    fail('Server Signatures', 'Cannot verify — no successful response to check. Fix previous failures first.');
  } else {
    // Try to verify the echo response first, fall back to getting a fresh negotiate response
    let responseToCheck: ARPMessage | undefined = echoResponse;

    if (!responseToCheck) {
      // Use a fresh negotiate to get a signed response
      try {
        const checkKeys = generateKeyPair();
        const msg: ARPMessage = {
          arp: '1.0',
          id: newMessageId(),
          type: 'negotiate',
          from: checkKeys.did,
          to: agentDid,
          createdAt: nowISO(),
          body: {
            firstContact: true,
            publicKey: checkKeys.publicKeyMultibase,
          },
        };
        signMessage(msg, checkKeys.privateKey);

        const res = await fetchJSON(inboxUrl, {
          method: 'POST',
          headers: { 'Content-Type': 'application/arp+json' },
          body: JSON.stringify(msg),
        });
        if (res.status === 200) {
          responseToCheck = res.body as ARPMessage;
        }
      } catch {
        // fall through
      }
    }

    if (!responseToCheck) {
      fail('Server Signatures', 'No response available to verify. This may indicate a server issue.');
    } else if (!responseToCheck.signature) {
      fail('Server Signatures', 'Server response is missing a "signature" field. All ARP responses must be signed by the server.');
    } else {
      const valid = verifyMessageSignature(responseToCheck, serverPublicKey);
      if (valid) {
        pass('Server Signatures', 'Server signatures valid');
      } else {
        fail('Server Signatures', 'Server response signature is invalid. Verify the server is signing with the same key advertised in the Agent Card and DID document.');
      }
    }
  }

  // 10. First-Contact Enforcement
  try {
    const newKeys = generateKeyPair();
    const reqMsg: ARPMessage = {
      arp: '1.0',
      id: newMessageId(),
      type: 'request',
      from: newKeys.did,
      to: agentDid,
      capability: 'echo',
      createdAt: nowISO(),
      body: { test: 'first-contact-enforcement' },
    };
    signMessage(reqMsg, newKeys.privateKey);

    const res = await fetchJSON(inboxUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/arp+json' },
      body: JSON.stringify(reqMsg),
    });

    if (res.status === 403) {
      const body = res.body as ARPMessage;
      const innerBody = body?.body as Record<string, unknown> | undefined;
      if (innerBody?.code === 'FIRST_CONTACT_REQUIRED') {
        pass('First-Contact Enforcement', 'First-contact enforcement working');
      } else {
        pass('First-Contact Enforcement', `First-contact enforcement working (403 returned, code: ${innerBody?.code ?? 'unknown'})`);
      }
    } else {
      fail('First-Contact Enforcement', `Server returned HTTP ${res.status} instead of 403 for a request from an unknown sender. Requests from senders who have not completed negotiate should return FIRST_CONTACT_REQUIRED (HTTP 403).`);
    }
  } catch (err) {
    fail('First-Contact Enforcement', `Request failed — ${(err as Error).message}`);
  }

  // 11. Expired Message Rejection
  if (!negotiateOk) {
    fail('Expired Message Rejection', 'Skipped — negotiate failed. Fix the negotiate check first.');
  } else {
    try {
      const pastDate = new Date(Date.now() - 60_000).toISOString(); // 1 minute ago
      const expiredMsg: ARPMessage = {
        arp: '1.0',
        id: newMessageId(),
        type: 'request',
        from: clientKeys.did,
        to: agentDid,
        capability: 'echo',
        createdAt: nowISO(),
        expiresAt: pastDate,
        body: { test: 'expired' },
      };
      signMessage(expiredMsg, clientKeys.privateKey);

      const res = await fetchJSON(inboxUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/arp+json' },
        body: JSON.stringify(expiredMsg),
      });

      if (res.status === 400) {
        const body = res.body as ARPMessage;
        const innerBody = body?.body as Record<string, unknown> | undefined;
        if (innerBody?.code === 'MESSAGE_EXPIRED') {
          pass('Expired Message Rejection', 'Expired message rejected');
        } else {
          pass('Expired Message Rejection', `Expired message rejected (400 returned, code: ${innerBody?.code ?? 'unknown'})`);
        }
      } else {
        fail('Expired Message Rejection', `Server returned HTTP ${res.status} instead of 400 for an expired message. Messages with expiresAt in the past should return MESSAGE_EXPIRED (HTTP 400).`);
      }
    } catch (err) {
      fail('Expired Message Rejection', `Request failed — ${(err as Error).message}`);
    }
  }

  // 12. Content-Type Check
  try {
    const res = await fetchJSON(inboxUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'text/plain' },
      body: 'not json',
    });

    if (res.status === 415) {
      pass('Content-Type Enforcement', 'Content-Type enforced');
    } else if (res.status >= 400 && res.status < 500) {
      // Some servers return 400 for parse errors instead of 415
      pass('Content-Type Enforcement', `Content-Type enforced (HTTP ${res.status})`);
    } else {
      fail('Content-Type Enforcement', `Server returned HTTP ${res.status} for text/plain Content-Type instead of 415 or 400. The inbox should reject non-JSON content types.`);
    }
  } catch (err) {
    fail('Content-Type Enforcement', `Request failed — ${(err as Error).message}`);
  }

  printResults();
}

// ---------------------------------------------------------------------------
// Output
// ---------------------------------------------------------------------------

function printResults() {
  console.log('');
  const passed = results.filter(r => r.passed).length;
  const total = results.length;

  for (const r of results) {
    const icon = r.warning ? '\x1b[33m\u26a0\x1b[0m' : r.passed ? '\x1b[32m\u2713\x1b[0m' : '\x1b[31m\u2717\x1b[0m';
    console.log(`  ${icon} ${r.message}`);
  }

  console.log('');
  if (passed === total) {
    console.log(`  \x1b[32m${passed}/${total} checks passed \u2014 endpoint is ARP compliant\x1b[0m`);
  } else {
    const failed = total - passed;
    console.log(`  \x1b[31m${passed}/${total} checks passed, ${failed} failed\x1b[0m`);
  }
  console.log('');

  process.exit(passed === total ? 0 : 1);
}

// ---------------------------------------------------------------------------
// Entry
// ---------------------------------------------------------------------------

run().catch((err) => {
  console.error(`Fatal error: ${err.message}`);
  process.exit(1);
});
