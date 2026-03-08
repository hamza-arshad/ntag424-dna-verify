# AGENTS.md

## Commands

```bash
npm install          # install deps (jest only, no production deps)
npm test             # run all 47 tests
npx jest --verbose   # run with full output
npx jest --watch     # watch mode
npx jest test/crypto.test.js           # run one suite
npx jest -t "verifies a valid tap"     # run one test by name
```

## Project overview

Node.js library for verifying NTAG 424 DNA NFC tags using Secure Dynamic Messaging (SDM). Zero production dependencies — only Node's built-in `crypto` module.

The library does three things:
1. Parse a URL that an NFC tag generates when tapped (contains encrypted PICCData + CMAC)
2. Decrypt the PICCData to extract the tag's UID and read counter
3. Validate the CMAC to prove the tag is genuine, not cloned

Two key strategies are supported: direct per-tag keys and diversified keys derived from a master key + UID.

## Architecture

```
src/
  index.js    → public API, re-exports everything
  crypto.js   → AES-128-CBC, AES-CMAC (RFC 4493), key diversification (NXP AN10922)
  parser.js   → URL parsing, auto-detects standard and compact SDM URL formats
  verify.js   → main verification logic, PICCData decryption, CMAC validation, replay detection
test/
  crypto.test.js   → RFC 4493 test vectors, key diversification, round-trip tests
  parser.test.js   → both URL formats, edge cases, error messages
  verify.test.js   → full flow tests using self-consistent test vectors (createTestTapUrl helper)
examples/
  express-server.js → minimal verification endpoint
  debug-tap.js      → CLI to decode tapped URLs
```

## Code style

- `'use strict'` at the top of every file
- CommonJS (`require`/`module.exports`), not ESM. This is intentional for maximum Node version compatibility (>=14).
- No semicolon-free style. Semicolons everywhere.
- Single quotes for strings.
- Keep functions small. Each file has a clear single responsibility.
- JSDoc comments on public functions. Internal helpers can skip JSDoc but should have a one-line comment if the purpose isn't obvious.
- Error messages should be specific and actionable. Include what was expected vs what was received. Example: `"Key must be 16 bytes (AES-128)"` not `"Invalid key"`.

## Testing

- Test framework is Jest.
- Crypto tests use official RFC 4493 test vectors. Do not change these — they validate correctness against the spec.
- Verification tests use `createTestTapUrl()` helper in `test/verify.test.js` to generate self-consistent URLs with valid PICCData and CMAC. Use this helper when adding new verification tests instead of hardcoding hex strings.
- Every public function should have tests covering: happy path, bad inputs, edge cases.
- Run the full suite before committing. All 47 tests must pass.

## Domain knowledge

Things an agent needs to know about NTAG 424 DNA and SDM:

- **PICCData** is 16 bytes encrypted with AES-128-CBC (zero IV). Byte 0 is always `0xC7`. Bytes 1-7 are the 7-byte UID. Bytes 8-10 are the read counter in little-endian. Rest is padding.
- **CMAC** is computed over the URL string up to but not including the CMAC value itself. The tag uses AES-CMAC (RFC 4493) and only the first 8 bytes of the 16-byte result are used.
- **Read counter** increments on every tap. A counter value <= last known value means the tag was cloned or the tap is being replayed.
- **Key diversification** (NXP AN10922) derives per-tag keys from a master key + UID using AES-CMAC. The diversification input format is: `0x01 || label || 0x00 || UID || 0x00 || 0x80`.
- Standard URL format: `https://domain.com/verify?picc_data=<32 hex>&cmac=<16 hex>`
- Compact URL format: `https://domain.com/t?e=<32 hex>&m=<16 hex>`

## Boundaries

**Always:**
- Run `npm test` after any code change
- Keep zero production dependencies. Only `crypto` from Node stdlib.
- Maintain backward compatibility of the public API in `src/index.js`
- Use Buffer for all binary data, never raw strings for keys or encrypted data

**Never:**
- Add production dependencies. This library ships with zero deps and that's a feature.
- Modify RFC 4493 test vectors in `test/crypto.test.js`
- Change the public API signature of `verifyTag()` without updating all tests and README
- Store or log keys, UIDs, or any sensitive data in error messages beyond what's needed for debugging
- Use `console.log` in `src/` files. Examples can log, library code cannot.

**Ask first:**
- Before adding a new file to `src/` — the current 4-file structure is intentional
- Before changing the CMAC input computation logic — this must match NXP's spec exactly
- Before adding async operations — the library is currently fully synchronous by design
