# arp-verify

Verify ARP (Agent Relations Protocol) endpoint compliance.

## Usage

```bash
npx arp-verify agents.mycompany.com
npx arp-verify agents.mycompany.com --agent order-processor
npx arp-verify localhost:3141
```

## Checks

1. **agents.txt** -- Fetch `/agents.txt`, verify it contains an `arp-index:` line
2. **Agent Index** -- Fetch `/.well-known/arp/index.json`, verify structure
3. **Agent Card** -- Fetch `/.well-known/arp/{agent}.json`, verify required fields
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
