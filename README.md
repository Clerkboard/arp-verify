# @agentrelationsprotocol/arp-verify

CLI that verifies ARP (Agent Relations Protocol) endpoint compliance. Runs a
sequence of live checks against your agent's HTTP surface and reports pass/fail
for each. Exit code is `0` when every check passes, `1` otherwise.

## Usage

```bash
npx @agentrelationsprotocol/arp-verify agents.mycompany.com
npx @agentrelationsprotocol/arp-verify agents.mycompany.com --agent order-processor
npx @agentrelationsprotocol/arp-verify localhost:3141
```

The CLI supports two common deployment shapes:

- **Single host** — all agents live under one domain, cards at
  `/.well-known/arp/<name>.json` and DID docs at `/<name>/did.json`.
- **Subdomain-per-agent** — the root domain serves the directory manifest and
  each agent lives on its own subdomain (e.g. `a.mycompany.com` hosts the
  index; `agent.a.mycompany.com` hosts the card, DID doc, and inbox). In this
  case, point the CLI at the root domain — it follows the URL advertised in
  the directory entry and resolves the DID document from each agent's
  `did:web:…` identifier.

## Checks

1. **agents.txt** — `/agents.txt` exposes an `arp-directory:` line (v0.4.0).
2. **Agent Index** — `/.well-known/arp/index.json` returns a valid directory
   manifest with a non-empty `agents` array.
3. **Agent Card** — fetched from the URL advertised in the directory (with
   fallback to `/.well-known/arp/<name>.json`), with all required fields
   present.
4. **DID Document** — resolved from the agent card's `did:web:…` identifier
   per the did:web spec; structure validated.
5. **Key Consistency** — `publicKey` on the Agent Card matches the
   `publicKeyMultibase` in the DID document's first verification method.
6. **Inbox Reachable** — POSTing an unsigned message returns a structured ARP
   error response.
7. **First-Contact Negotiate** — a signed `negotiate` with
   `body.firstContact: true` and `body.publicKey` is accepted.
8. **Echo Test** — if the agent declares an `echo` capability, a signed
   request round-trips correctly.
9. **Server Signatures** — server responses carry a valid signature that
   verifies against the advertised public key.
10. **Open Capability** — capabilities declared `open: true` accept requests
    without a prior handshake.
11. **First-Contact Enforcement** — non-open capabilities reject unknown
    senders with `FIRST_CONTACT_REQUIRED` (HTTP 403). See caveat below.
12. **Expired Message Rejection** — messages with `expiresAt` in the past are
    rejected with `MESSAGE_EXPIRED` (HTTP 400).
13. **Trust Annotations** — responses include a `trustLevel` field
    (recommended in v0.4.0).
14. **JSON-LD Agent Card** — `@context` and `@type: SoftwareApplication`
    present (recommended for crawler indexing).
15. **JSON-LD Directory** — `@context` and `@type: CollectionPage` on the
    directory manifest.
16. **Content-Type Enforcement** — non-JSON content types are rejected.

## Test identity

Signed checks are sent from a bundled did:web test identity:

```
did:web:agentrelationsprotocol.com:arp-verify
```

The private key for this identity is **intentionally public** — it ships with
the CLI and is published in the DID document at
`https://agentrelationsprotocol.com/arp-verify/did.json`. This is a conformance
tool, not a trusted agent. Signatures from this identity prove only that a
message was sent via arp-verify (or a tool using the same keys). Receivers
MUST treat this identity as any other unknown sender — via the first-contact
handshake — and MUST NOT grant privileges based on this DID.

### Known limitation — first-contact enforcement on repeat runs

The first-contact-enforcement check expects the receiver to reject a signed
request from an unknown sender with `FIRST_CONTACT_REQUIRED`. On the first
run against a fresh endpoint this works correctly. On subsequent runs, the
endpoint may have a cached relation with the bundled test identity, in which
case the check will incorrectly fail. Clear relations on the endpoint side
between runs, or treat a 200 on this specific check as a non-issue if you
know the identity is already known.

## Development

```bash
npm install
npx tsx src/index.ts localhost:3141
```

## License

Apache-2.0
