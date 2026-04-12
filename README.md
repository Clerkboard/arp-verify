# acp-verify

Verify ACP (Agent Communication Protocol) endpoint compliance.

## Usage

```bash
npx acp-verify agents.mycompany.com
npx acp-verify agents.mycompany.com --agent order-processor
npx acp-verify localhost:3141
```

## Checks

1. **agents.txt** -- Fetch `/agents.txt`, verify it contains an `acp-index:` line
2. **Agent Index** -- Fetch `/.well-known/acp/index.json`, verify structure
3. **Agent Card** -- Fetch `/.well-known/acp/{agent}.json`, verify required fields
4. **DID Document** -- Fetch `/{agent}/did.json`, verify structure
5. **Key Consistency** -- Check Agent Card `publicKey` matches DID doc `publicKeyMultibase`
6. **Inbox Reachable** -- POST unsigned message, verify structured error response
7. **First-Contact Negotiate** -- Send signed negotiate, verify 200 + acknowledge
8. **Echo Test** -- If agent has echo capability, test it
9. **Server Signatures** -- Verify response signatures against Agent Card public key
10. **First-Contact Enforcement** -- New key without negotiate returns FIRST_CONTACT_REQUIRED
11. **Expired Message Rejection** -- Message with past `expiresAt` is rejected
12. **Content-Type Enforcement** -- Wrong Content-Type is rejected

## Development

```bash
npm install
npx tsx src/index.ts localhost:3141
```
