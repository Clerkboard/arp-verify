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
const canonicalize = _canonicalize;
// ---------------------------------------------------------------------------
// Crypto helpers
// ---------------------------------------------------------------------------
const ED25519_SPKI_HEADER = Buffer.from('302a300506032b6570032100', 'hex');
const ED25519_PKCS8_HEADER = Buffer.from('302e020100300506032b657004220420', 'hex');
const ED25519_MULTICODEC_PREFIX = Buffer.from([0xed, 0x01]);
// ---------------------------------------------------------------------------
// Verifier test identity
//
// arp-verify ships with a fixed did:web test identity. The private key below
// is INTENTIONALLY PUBLIC — this is a conformance tool, not a trusted agent.
// Signatures from did:web:agentrelationsprotocol.com:arp-verify prove only
// that a message was sent via arp-verify (or a tool using the same keys).
// Receivers MUST treat this identity as any other unknown sender — via the
// first-contact handshake — and MUST NOT grant privileges based on this DID.
//
// Spec Section 4.5 mandates did:web for all agent identities. A conformance
// CLI cannot host per-run ephemeral DID docs, so the test identity is pinned.
// ---------------------------------------------------------------------------
const VERIFIER_DID = 'did:web:agentrelationsprotocol.com:arp-verify';
const VERIFIER_PUBLIC_KEY_MULTIBASE = 'z6MkiFuoGib9ZwcE3fpVBNXqfMR4R3uKpPbr5Kx9YgWLikD7';
const VERIFIER_PRIVATE_SEED_B64 = 'fM/RlM4qHVQMqs9jEIA6dnVz70yZGJVG51rfSnuSGls=';
function rawPublicKey(publicKey) {
    const spki = publicKey.export({ type: 'spki', format: 'der' });
    return spki.subarray(spki.length - 32);
}
/** Encode an Ed25519 public key as multibase with 0xed01 multicodec prefix (spec §4.3.1). */
function encodeKeyMultibase(raw32) {
    if (raw32.length !== 32) {
        throw new Error(`Ed25519 public key must be 32 bytes, got ${raw32.length}`);
    }
    return 'z' + bs58.encode(Buffer.concat([ED25519_MULTICODEC_PREFIX, raw32]));
}
/** Encode a signature as multibase (no multicodec prefix, spec §4.3.1). */
function encodeSignatureMultibase(sig) {
    return 'z' + bs58.encode(sig);
}
function decodeMultibase(mb) {
    if (!mb.startsWith('z')) {
        throw new Error(`Unsupported multibase prefix: ${mb[0]}`);
    }
    return Buffer.from(bs58.decode(mb.slice(1)));
}
function importPublicKey(keyOrMultibase) {
    let raw = typeof keyOrMultibase === 'string'
        ? decodeMultibase(keyOrMultibase)
        : keyOrMultibase;
    // Strip multicodec Ed25519 prefix (0xed01) if present
    if (raw.length === 34 && raw[0] === 0xed && raw[1] === 0x01) {
        raw = raw.subarray(2);
    }
    if (raw.length !== 32) {
        throw new Error(`Expected 32-byte Ed25519 public key, got ${raw.length} bytes`);
    }
    return crypto.createPublicKey({
        key: Buffer.concat([ED25519_SPKI_HEADER, raw]),
        format: 'der',
        type: 'spki',
    });
}
/** Build an Ed25519 private KeyObject from a 32-byte seed. */
function importPrivateSeed(seed32) {
    if (seed32.length !== 32) {
        throw new Error(`Ed25519 seed must be 32 bytes, got ${seed32.length}`);
    }
    return crypto.createPrivateKey({
        key: Buffer.concat([ED25519_PKCS8_HEADER, seed32]),
        format: 'der',
        type: 'pkcs8',
    });
}
/** Load the bundled did:web verifier identity. */
function loadVerifierIdentity() {
    const seed = Buffer.from(VERIFIER_PRIVATE_SEED_B64, 'base64');
    const privateKey = importPrivateSeed(seed);
    return {
        privateKey,
        publicKeyMultibase: VERIFIER_PUBLIC_KEY_MULTIBASE,
        did: VERIFIER_DID,
    };
}
function signMessage(message, privateKey) {
    const { signature: _sig, ...rest } = message;
    const canonical = canonicalize(rest);
    if (canonical === undefined) {
        throw new Error('JCS canonicalization returned undefined');
    }
    const payload = Buffer.from(canonical, 'utf-8');
    const sig = crypto.sign(null, payload, privateKey);
    message.signature = encodeSignatureMultibase(sig);
    return message;
}
function verifyMessageSignature(message, publicKey) {
    if (!message.signature)
        return false;
    const sigBytes = decodeMultibase(message.signature);
    const { signature: _sig, ...rest } = message;
    const canonical = canonicalize(rest);
    if (canonical === undefined)
        return false;
    const payload = Buffer.from(canonical, 'utf-8');
    return crypto.verify(null, payload, publicKey, sigBytes);
}
function newMessageId() {
    return `msg_${crypto.randomUUID()}`;
}
function nowISO() {
    return new Date().toISOString();
}
// ---------------------------------------------------------------------------
// CLI argument parsing
// ---------------------------------------------------------------------------
function parseArgs() {
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
    let agentName;
    const agentIdx = args.indexOf('--agent');
    if (agentIdx !== -1 && agentIdx + 1 < args.length) {
        agentName = args[agentIdx + 1];
    }
    return { domain, agentName };
}
// ---------------------------------------------------------------------------
// URL helpers
// ---------------------------------------------------------------------------
function isLocalhost(domain) {
    const host = domain.split(':')[0];
    return host === 'localhost' || host === '127.0.0.1';
}
function baseUrl(domain) {
    const scheme = isLocalhost(domain) ? 'http' : 'https';
    return `${scheme}://${domain}`;
}
/**
 * Resolve a did:web identifier to its DID document URL per the did:web spec.
 *
 *   did:web:example.com            → https://example.com/.well-known/did.json
 *   did:web:example.com:agent      → https://example.com/agent/did.json
 *   did:web:host:a:b:c             → https://host/a/b/c/did.json
 *   did:web:localhost%3A3141:agent → http://localhost:3141/agent/did.json
 */
function resolveDidWebUrl(did) {
    if (!did.startsWith('did:web:')) {
        throw new Error(`Not a did:web identifier: ${did}`);
    }
    const parts = did.slice('did:web:'.length).split(':').map(p => decodeURIComponent(p));
    const [host, ...path] = parts;
    if (!host) {
        throw new Error(`Invalid did:web (no host): ${did}`);
    }
    const scheme = isLocalhost(host) ? 'http' : 'https';
    if (path.length === 0) {
        return `${scheme}://${host}/.well-known/did.json`;
    }
    return `${scheme}://${host}/${path.join('/')}/did.json`;
}
// ---------------------------------------------------------------------------
// HTTP helper with timeout
// ---------------------------------------------------------------------------
async function fetchJSON(url, options) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 10_000);
    try {
        const res = await fetch(url, { ...options, signal: controller.signal });
        let body;
        const ct = res.headers.get('content-type') ?? '';
        if (ct.includes('json')) {
            body = await res.json();
        }
        else {
            body = await res.text();
        }
        return { status: res.status, body, ok: res.ok };
    }
    finally {
        clearTimeout(timeout);
    }
}
// ---------------------------------------------------------------------------
// Check runners
// ---------------------------------------------------------------------------
const results = [];
function pass(name, message) {
    results.push({ name, passed: true, message });
}
function fail(name, message) {
    results.push({ name, passed: false, message });
}
function warn(name, message) {
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
    let agentIndex;
    let agentCard;
    let didDoc;
    let agentName;
    let serverPublicKey;
    // Bundled did:web test identity — see constants at top of file.
    // All signed tests use this single identity. See README for semantics
    // and the known limitation about first-contact-enforcement on repeat runs.
    const verifier = loadVerifierIdentity();
    // 1. agents.txt
    try {
        const url = `${base}/agents.txt`;
        const res = await fetchJSON(url);
        const text = typeof res.body === 'string' ? res.body : JSON.stringify(res.body);
        if (!res.ok) {
            fail('agents.txt', `HTTP ${res.status} from ${url}. Ensure your server exposes GET /agents.txt returning a text file with an "arp-directory:" line.`);
        }
        else if (!text.includes('arp-directory:')) {
            if (text.includes('arp-index:')) {
                fail('agents.txt', 'File uses deprecated "arp-index:" field. Rename to "arp-directory:" per v0.4.0 spec.');
            }
            else {
                fail('agents.txt', `File found but missing "arp-directory:" directive. The agents.txt file must contain a line like: arp-directory: ${base}/.well-known/arp/index.json`);
            }
        }
        else {
            pass('agents.txt', 'agents.txt found with arp-directory');
            if (!text.includes('arp-version:')) {
                warn('agents.txt', 'Missing "arp-version:" field (RECOMMENDED)');
            }
            if (!text.includes('open-capabilities:')) {
                warn('agents.txt', 'Missing "open-capabilities:" field. List capabilities that accept stateless queries.');
            }
        }
    }
    catch (err) {
        fail('agents.txt', `Could not reach ${base}/agents.txt — ${err.message}. Is the server running at ${domain}?`);
    }
    // 2. Agent Index
    try {
        const url = `${base}/.well-known/arp/index.json`;
        const res = await fetchJSON(url);
        if (!res.ok) {
            fail('Agent Index', `HTTP ${res.status} from ${url}. Ensure your server exposes GET /.well-known/arp/index.json returning the agent index.`);
        }
        else {
            const data = res.body;
            const missing = [];
            if (!data.domain)
                missing.push('domain');
            if (!data.protocol)
                missing.push('protocol');
            if (!Array.isArray(data.agents))
                missing.push('agents (array)');
            if (missing.length > 0) {
                fail('Agent Index', `Index JSON is missing required fields: ${missing.join(', ')}. The index must contain: domain, protocol, and an agents array.`);
            }
            else {
                agentIndex = data;
                const count = agentIndex.agents.length;
                pass('Agent Index', `Agent index valid (${count} agent${count !== 1 ? 's' : ''})`);
            }
        }
    }
    catch (err) {
        fail('Agent Index', `Could not fetch agent index — ${err.message}. Ensure /.well-known/arp/index.json is served.`);
    }
    // Determine which agent to test
    if (requestedAgent) {
        agentName = requestedAgent;
    }
    else if (agentIndex && agentIndex.agents.length > 0) {
        agentName = agentIndex.agents[0].name;
    }
    if (!agentName) {
        fail('Agent Card', 'Cannot determine agent name. Either pass --agent <name> or ensure the index has at least one agent entry.');
        printResults();
        return;
    }
    // 3. Agent Card
    // Prefer the URL advertised in the directory manifest (supports subdomain-per-agent layouts);
    // fall back to the conventional /.well-known/arp/<name>.json under the base domain.
    const indexEntry = agentIndex?.agents.find(a => a.name === agentName);
    const cardUrl = indexEntry?.url ?? `${base}/.well-known/arp/${agentName}.json`;
    try {
        const res = await fetchJSON(cardUrl);
        if (!res.ok) {
            fail('Agent Card', `HTTP ${res.status} from ${cardUrl}. Ensure the card URL advertised in the directory index (or /.well-known/arp/${agentName}.json under ${base}) returns a valid Agent Card.`);
        }
        else {
            const data = res.body;
            const required = ['arp', 'name', 'did', 'inbox', 'publicKey', 'description', 'capabilities', 'auth'];
            const missing = required.filter(f => data[f] === undefined || data[f] === null);
            if (missing.length > 0) {
                fail('Agent Card', `Agent card missing required fields: ${missing.join(', ')}. See the ARP spec for the full AgentCard schema.`);
            }
            else {
                agentCard = data;
                pass('Agent Card', `Agent Card valid: ${agentName}`);
            }
        }
    }
    catch (err) {
        fail('Agent Card', `Could not fetch agent card — ${err.message}`);
    }
    // 4. DID Document
    // Resolve the DID URL from the agent card's `did` field using did:web rules.
    // This correctly handles both single-host and subdomain-per-agent deployments.
    let didUrl;
    if (agentCard?.did) {
        if (agentCard.did.startsWith('did:web:')) {
            try {
                didUrl = resolveDidWebUrl(agentCard.did);
            }
            catch (err) {
                fail('DID Document', `Could not parse agent DID "${agentCard.did}": ${err.message}`);
            }
        }
        else {
            fail('DID Document', `Agent Card declares non-did:web identifier "${agentCard.did}" — spec §4.5 mandates did:web for all agent identities.`);
        }
    }
    else {
        // No card fetched — try a legacy single-host fallback so we at least produce a clear error.
        didUrl = `${base}/${agentName}/did.json`;
    }
    try {
        if (!didUrl) {
            // A DID-parse failure already recorded above — skip the fetch.
            throw new Error('__skip__');
        }
        const res = await fetchJSON(didUrl);
        if (!res.ok) {
            fail('DID Document', `HTTP ${res.status} from ${didUrl}. Ensure the DID document is served at the path derived from the agent's did:web identifier (${agentCard?.did ?? 'unknown'}).`);
        }
        else {
            const data = res.body;
            const required = ['@context', 'id', 'verificationMethod', 'authentication', 'service'];
            const missing = required.filter(f => data[f] === undefined || data[f] === null);
            if (missing.length > 0) {
                fail('DID Document', `DID document missing required fields: ${missing.join(', ')}. The document must include @context, id, verificationMethod, authentication, and service.`);
            }
            else {
                didDoc = data;
                pass('DID Document', 'DID document valid');
            }
        }
    }
    catch (err) {
        const msg = err.message;
        if (msg !== '__skip__') {
            fail('DID Document', `Could not fetch DID document — ${msg}`);
        }
    }
    // 5. Key Consistency
    if (agentCard && didDoc) {
        const cardKey = agentCard.publicKey;
        const vm = didDoc.verificationMethod;
        if (!vm || vm.length === 0) {
            fail('Key Consistency', 'DID document has no verificationMethod entries. Add at least one Ed25519VerificationKey2020 entry.');
        }
        else {
            const didKey = vm[0].publicKeyMultibase;
            if (cardKey === didKey) {
                pass('Key Consistency', 'Agent Card matches DID doc');
                try {
                    serverPublicKey = importPublicKey(cardKey);
                }
                catch (err) {
                    fail('Key Consistency', `Key is present but invalid: ${err.message}`);
                }
            }
            else {
                fail('Key Consistency', `Agent Card key (${cardKey.slice(0, 8)}...) does not match DID doc key (${didKey.slice(0, 8)}...). Both must use the same Ed25519 public key.`);
                // Still try to import for subsequent checks
                try {
                    serverPublicKey = importPublicKey(cardKey);
                }
                catch {
                    // ignore
                }
            }
        }
    }
    else {
        fail('Key Consistency', 'Cannot check key consistency — Agent Card or DID document was not retrieved. Fix the previous failures first.');
    }
    // 6. Inbox Reachable (unsigned POST)
    const inboxUrl = agentCard?.inbox ?? `${base}/${agentName}/inbox`;
    try {
        const unsignedMsg = {
            arp: '1.0',
            id: newMessageId(),
            type: 'request',
            from: 'did:web:arp-verify.invalid:unsigned-test',
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
        }
        else {
            // We expect a structured error (SCHEMA_INVALID for missing signature, or FIRST_CONTACT_REQUIRED, etc.)
            const body = res.body;
            const innerBody = body?.body;
            if (innerBody && typeof innerBody.code === 'string') {
                pass('Inbox Reachable', 'Inbox reachable (returns structured errors)');
            }
            else if (typeof body === 'object' && body !== null) {
                pass('Inbox Reachable', 'Inbox reachable (returns structured errors)');
            }
            else {
                fail('Inbox Reachable', `Inbox returned HTTP ${res.status} but the response is not a structured ARP error. The inbox should return ARP error messages (with body.code) for invalid requests.`);
            }
        }
    }
    catch (err) {
        fail('Inbox Reachable', `Could not reach inbox at ${inboxUrl} — ${err.message}. Ensure the server is running and the inbox URL is correct.`);
    }
    // 7. Signature Verification / Negotiate (first-contact)
    const clientKeys = verifier;
    const agentDid = agentCard?.did ?? `did:web:${domain}:${agentName}`;
    let negotiateOk = false;
    try {
        const negotiateMsg = {
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
            const body = res.body;
            if (body.type === 'acknowledge') {
                negotiateOk = true;
                pass('First-Contact Negotiate', 'First-contact negotiate accepted');
            }
            else {
                fail('First-Contact Negotiate', `Server returned 200 but type="${body.type}" instead of "acknowledge". The negotiate response should be type "acknowledge".`);
            }
        }
        else {
            const body = res.body;
            const innerBody = body?.body;
            const errMsg = innerBody?.message ?? JSON.stringify(body);
            fail('First-Contact Negotiate', `Server returned HTTP ${res.status}: ${errMsg}. A signed negotiate message with firstContact=true should be accepted with 200.`);
        }
    }
    catch (err) {
        fail('First-Contact Negotiate', `Negotiate request failed — ${err.message}`);
    }
    // 8. Echo Test
    const hasEcho = agentCard?.capabilities?.some(c => c.name === 'echo') ?? false;
    let echoResponse;
    if (!hasEcho) {
        pass('Echo Test', 'Echo capability not listed — skipped');
    }
    else if (!negotiateOk) {
        fail('Echo Test', 'Skipped — negotiate failed. Fix the negotiate check first.');
    }
    else {
        try {
            const echoMsg = {
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
                const body = res.body;
                if (body.type === 'response') {
                    echoResponse = body;
                    pass('Echo Test', 'Echo capability works');
                }
                else {
                    fail('Echo Test', `Server returned 200 but type="${body.type}" instead of "response". Echo requests should return type "response".`);
                }
            }
            else {
                fail('Echo Test', `Echo request returned HTTP ${res.status}. A signed request with capability "echo" should return 200 with the echoed body.`);
            }
        }
        catch (err) {
            fail('Echo Test', `Echo request failed — ${err.message}`);
        }
    }
    // 9. Signature on Response
    if (!serverPublicKey) {
        fail('Server Signatures', 'Cannot verify — server public key not available. Fix the Agent Card or Key Consistency check first.');
    }
    else if (!echoResponse && !negotiateOk) {
        fail('Server Signatures', 'Cannot verify — no successful response to check. Fix previous failures first.');
    }
    else {
        // Try to verify the echo response first, fall back to getting a fresh negotiate response
        let responseToCheck = echoResponse;
        if (!responseToCheck) {
            // Use a fresh negotiate to get a signed response
            try {
                const checkKeys = verifier;
                const msg = {
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
                    responseToCheck = res.body;
                }
            }
            catch {
                // fall through
            }
        }
        if (!responseToCheck) {
            fail('Server Signatures', 'No response available to verify. This may indicate a server issue.');
        }
        else if (!responseToCheck.signature) {
            fail('Server Signatures', 'Server response is missing a "signature" field. All ARP responses must be signed by the server.');
        }
        else {
            const valid = verifyMessageSignature(responseToCheck, serverPublicKey);
            if (valid) {
                pass('Server Signatures', 'Server signatures valid');
            }
            else {
                fail('Server Signatures', 'Server response signature is invalid. Verify the server is signing with the same key advertised in the Agent Card and DID document.');
            }
        }
    }
    // 10. Open Capability (v0.4.0) — request without negotiate should work on open capabilities
    const openCap = agentCard?.capabilities?.find(c => c.open === true);
    if (!openCap) {
        warn('Open Capability', 'No open capabilities declared — skipped');
    }
    else {
        try {
            const openKeys = verifier;
            const openMsg = {
                arp: '1.0',
                id: newMessageId(),
                type: 'request',
                from: openKeys.did,
                to: agentDid,
                capability: openCap.name,
                createdAt: nowISO(),
                body: { test: 'open-capability', publicKey: openKeys.publicKeyMultibase },
            };
            signMessage(openMsg, openKeys.privateKey);
            const res = await fetchJSON(inboxUrl, {
                method: 'POST',
                headers: { 'Content-Type': 'application/arp+json' },
                body: JSON.stringify(openMsg),
            });
            if (res.status === 200) {
                const body = res.body;
                if (body.type === 'response') {
                    pass('Open Capability', `Open capability "${openCap.name}" accepts requests without negotiate`);
                }
                else {
                    fail('Open Capability', `Server returned 200 but type="${body.type}" instead of "response".`);
                }
            }
            else {
                fail('Open Capability', `Server returned HTTP ${res.status} for open capability request without negotiate. Open capabilities should accept authenticated requests without prior handshake.`);
            }
        }
        catch (err) {
            fail('Open Capability', `Request failed — ${err.message}`);
        }
    }
    // 11. First-Contact Enforcement on non-open capability
    const nonOpenCap = agentCard?.capabilities?.find(c => !c.open);
    if (nonOpenCap) {
        try {
            const newKeys = verifier;
            const reqMsg = {
                arp: '1.0',
                id: newMessageId(),
                type: 'request',
                from: newKeys.did,
                to: agentDid,
                capability: nonOpenCap.name,
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
                const body = res.body;
                const innerBody = body?.body;
                if (innerBody?.code === 'FIRST_CONTACT_REQUIRED') {
                    pass('First-Contact Enforcement', `Non-open capability "${nonOpenCap.name}" requires first contact`);
                }
                else {
                    pass('First-Contact Enforcement', `First-contact enforcement working (403, code: ${innerBody?.code ?? 'unknown'})`);
                }
            }
            else {
                fail('First-Contact Enforcement', `Server returned HTTP ${res.status} instead of 403 for non-open capability from unknown sender.`);
            }
        }
        catch (err) {
            fail('First-Contact Enforcement', `Request failed — ${err.message}`);
        }
    }
    else {
        // Fallback: test with a made-up capability name
        try {
            const newKeys = verifier;
            const reqMsg = {
                arp: '1.0',
                id: newMessageId(),
                type: 'request',
                from: newKeys.did,
                to: agentDid,
                capability: '__nonexistent__',
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
                pass('First-Contact Enforcement', 'First-contact enforcement working');
            }
            else {
                fail('First-Contact Enforcement', `Server returned HTTP ${res.status} instead of 403 for request from unknown sender.`);
            }
        }
        catch (err) {
            fail('First-Contact Enforcement', `Request failed — ${err.message}`);
        }
    }
    // 11. Expired Message Rejection
    if (!negotiateOk) {
        fail('Expired Message Rejection', 'Skipped — negotiate failed. Fix the negotiate check first.');
    }
    else {
        try {
            const pastDate = new Date(Date.now() - 60_000).toISOString(); // 1 minute ago
            const expiredMsg = {
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
                const body = res.body;
                const innerBody = body?.body;
                if (innerBody?.code === 'MESSAGE_EXPIRED') {
                    pass('Expired Message Rejection', 'Expired message rejected');
                }
                else {
                    pass('Expired Message Rejection', `Expired message rejected (400 returned, code: ${innerBody?.code ?? 'unknown'})`);
                }
            }
            else {
                fail('Expired Message Rejection', `Server returned HTTP ${res.status} instead of 400 for an expired message. Messages with expiresAt in the past should return MESSAGE_EXPIRED (HTTP 400).`);
            }
        }
        catch (err) {
            fail('Expired Message Rejection', `Request failed — ${err.message}`);
        }
    }
    // 12. Relation in Negotiate Response (v0.4.0)
    if (negotiateOk && echoResponse) {
        const echoBody = echoResponse.body;
        if (typeof echoBody.trustLevel === 'string') {
            pass('Trust Annotations', `Server returns trust level: "${echoBody.trustLevel}"`);
        }
        else {
            warn('Trust Annotations', 'Server does not include trustLevel in responses (RECOMMENDED in v0.4.0)');
        }
    }
    // 13. JSON-LD Agent Card (v0.4.0)
    if (agentCard) {
        const ctx = agentCard['@context'];
        const type = agentCard['@type'];
        if (ctx && type === 'SoftwareApplication') {
            pass('JSON-LD Agent Card', 'Agent Card has @context and @type: SoftwareApplication');
        }
        else if (ctx && !type) {
            warn('JSON-LD Agent Card', 'Agent Card has @context but missing @type: SoftwareApplication');
        }
        else if (!ctx && !type) {
            warn('JSON-LD Agent Card', 'Agent Card missing JSON-LD fields (@context, @type). SHOULD include for search engine indexing.');
        }
        else {
            warn('JSON-LD Agent Card', `Unexpected JSON-LD: @type="${type}"`);
        }
    }
    // 14. JSON-LD Agent Directory (v0.4.0)
    if (agentIndex) {
        const ctx = agentIndex['@context'];
        const type = agentIndex['@type'];
        if (ctx && type === 'CollectionPage') {
            pass('JSON-LD Directory', 'Directory manifest has @context and @type: CollectionPage');
        }
        else if (!ctx && !type) {
            warn('JSON-LD Directory', 'Directory manifest missing JSON-LD fields. SHOULD include for crawler indexing.');
        }
        else {
            warn('JSON-LD Directory', `Unexpected JSON-LD: @type="${type}"`);
        }
    }
    // 15. Content-Type Check
    try {
        const res = await fetchJSON(inboxUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'text/plain' },
            body: 'not json',
        });
        if (res.status === 415) {
            pass('Content-Type Enforcement', 'Content-Type enforced');
        }
        else if (res.status >= 400 && res.status < 500) {
            // Some servers return 400 for parse errors instead of 415
            pass('Content-Type Enforcement', `Content-Type enforced (HTTP ${res.status})`);
        }
        else {
            fail('Content-Type Enforcement', `Server returned HTTP ${res.status} for text/plain Content-Type instead of 415 or 400. The inbox should reject non-JSON content types.`);
        }
    }
    catch (err) {
        fail('Content-Type Enforcement', `Request failed — ${err.message}`);
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
    }
    else {
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
