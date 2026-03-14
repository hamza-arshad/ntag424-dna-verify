# ntag424-dna-verify

Verify **NTAG 424 DNA** tag authenticity using **Secure Dynamic Messaging (SDM)**.

Zero dependencies. Pure Node.js. Production-tested.

Built by [Hamza Arshad](https://github.com/hamza-arshad). Production-tested at [tethered.services](https://tethered.services) and [tetheredart.com](https://tetheredart.com).

---

## What This Does

When a phone taps an NTAG 424 DNA tag, the tag dynamically generates a URL containing encrypted data and a cryptographic signature (CMAC). This library:

1. **Parses** the tapped URL to extract `PICCData` and `CMAC`
2. **Decrypts** the `PICCData` to recover the tag's UID and read counter
3. **Validates** the CMAC to confirm the tag is genuine (not cloned)
4. **Detects** replay attacks via read counter tracking

If the CMAC matches, the tap is authentic. If it doesn't, the tag is counterfeit or tampered with.

---

## How It Works

```
┌──────────────┐     ┌──────────────┐     ┌──────────────────┐
│  NFC Tag      │     │  Phone       │     │  Your Server     │
│  (424 DNA)    │────▶│  (Reader)    │────▶│  (This Library)  │
│               │     │              │     │                  │
│ On each tap:  │     │ Reads NDEF   │     │ 1. Parse URL     │
│ • Encrypts    │     │ URL and      │     │ 2. Decrypt PICC  │
│   UID+Counter │     │ opens it in  │     │ 3. Validate CMAC │
│ • Generates   │     │ browser/app  │     │ 4. Check counter │
│   fresh CMAC  │     │              │     │ 5. Return result │
└──────────────┘     └──────────────┘     └──────────────────┘
```

**Key concepts:**

- **SDM (Secure Dynamic Messaging):** The tag modifies parts of its NDEF message on every tap, inserting encrypted data and a fresh CMAC.
- **PICCData:** Encrypted blob containing the tag's 7-byte UID and a 3-byte read counter. Encrypted with AES-128-CBC.
- **CMAC:** An AES-CMAC (RFC 4493) computed over parts of the URL. Changes every tap because the counter increments.
- **SUN (Secure Unique NFC):** NXP's name for the overall authentication scheme.

---

## Installation

```bash
npm install github:hamza-arshad/ntag424-dna-verify
```

No dependencies — uses only Node.js built-in `crypto` module.

---

## Quick Start

### Option 1: Direct Keys (per-tag keys stored in your database)

```javascript
const { verifyTag } = require('ntag424-dna-verify');

const result = verifyTag(
  'https://your-domain.com/verify?picc_data=EF963FF7828658A599F3041510671E88&cmac=94EED9EE65337086',
  {
    sdmMetaReadKey: Buffer.from('00000000000000000000000000000000', 'hex'),
    sdmFileReadKey: Buffer.from('00112233445566778899AABBCCDDEEFF', 'hex'),
    lastKnownCounter: 41, // Optional: detect replay attacks
  }
);

console.log(result);
// {
//   authentic: true,
//   reason: 'valid',
//   uid: '04A23BC1D52A80',
//   readCounter: 42,
//   piccDataHex: 'EF963FF7828658A599F3041510671E88',
//   cmacHex: '94EED9EE65337086',
//   counterWarning: null
// }
```

### Option 2: Diversified Keys (derived from a master key + tag UID)

```javascript
const { verifyTag } = require('ntag424-dna-verify');

const result = verifyTag(
  'https://your-domain.com/verify?picc_data=...&cmac=...',
  {
    masterKey: Buffer.from('AABBCCDDEEFF00112233445566778899', 'hex'),
    fileKeyLabel: 'file', // Optional diversification label
  }
);
```

The library automatically derives per-tag keys from the master key and the UID extracted from PICCData.

---

## URL Format Support

The library auto-detects two common URL formats:

**Standard format:**
```
https://domain.com/verify?picc_data=EF963FF7...&cmac=94EED9EE...
```

**Compact format:**
```
https://domain.com/t?e=EF963FF7...&m=94EED9EE...
```

**Custom parameters:**
```javascript
verifyTag(url, {
  sdmMetaReadKey: key1,
  sdmFileReadKey: key2,
  piccDataParam: 'enc',  // Your custom param name
  cmacParam: 'mac',      // Your custom param name
});
```

---

## Express.js Example

```javascript
const express = require('express');
const { verifyTag } = require('ntag424-dna-verify');
const app = express();

// In production: store per-tag keys in a database
const TAGS = new Map();
TAGS.set('04A23BC1D52A80', {
  sdmMetaReadKey: Buffer.from('...', 'hex'),
  sdmFileReadKey: Buffer.from('...', 'hex'),
  productId: 'artwork-001',
  lastCounter: 0,
});

app.get('/verify', (req, res) => {
  const fullUrl = `${req.protocol}://${req.get('host')}${req.originalUrl}`;

  // Try verification against registered tags
  for (const [uid, tag] of TAGS) {
    const result = verifyTag(fullUrl, {
      sdmMetaReadKey: tag.sdmMetaReadKey,
      sdmFileReadKey: tag.sdmFileReadKey,
      lastKnownCounter: tag.lastCounter,
    });

    if (result.authentic) {
      tag.lastCounter = result.readCounter;
      return res.json({ authentic: true, product: tag.productId });
    }

    if (result.reason === 'counter_replay') {
      return res.json({ authentic: false, reason: 'possible_clone' });
    }
  }

  res.json({ authentic: false, reason: 'unknown_tag' });
});

app.listen(3000);
```

See `examples/express-server.js` for a full working server.

---

## API Reference

### `verifyTag(url, options)` → `object`

Main entry point. Parses URL, decrypts PICCData, validates CMAC, checks counter.

**Options (provide one key strategy):**

| Option | Type | Description |
|--------|------|-------------|
| `sdmMetaReadKey` | `Buffer` | 16-byte AES key for PICCData decryption |
| `sdmFileReadKey` | `Buffer` | 16-byte AES key for CMAC verification |
| `masterKey` | `Buffer` | 16-byte master key (alternative to direct keys) |
| `fileKeyLabel` | `string` | Diversification label for file key (default: `'file'`) |
| `piccDataParam` | `string` | Custom URL param name for PICCData |
| `cmacParam` | `string` | Custom URL param name for CMAC |
| `lastKnownCounter` | `number` | Last seen counter for replay detection |

**Returns:**

```javascript
{
  authentic: true | false,
  reason: 'valid' | 'cmac_mismatch' | 'counter_replay' | 'picc_decryption_failed',
  uid: '04A23BC1D52A80',       // 7-byte UID as hex string
  readCounter: 42,              // Current read counter
  piccDataHex: 'EF963FF7...',   // Raw PICCData hex
  cmacHex: '94EED9EE...',       // Raw CMAC hex
  counterWarning: null | string // Warning message if counter issue detected
}
```

### `decodeTag(url, sdmMetaReadKey, options?)` → `object`

Decrypt PICCData without verifying CMAC. Useful for debugging.

### `diversifyKey(masterKey, uid, label?)` → `Buffer`

Derive a per-tag key from a master key and UID (NXP AN10922 method).

### `aesCmac(message, key)` → `Buffer`

Compute AES-CMAC per RFC 4493. Validated against official test vectors.

### `generateRandomKey()` → `Buffer`

Generate a cryptographically random 16-byte AES key.

### `parseSdmUrl(url, options?)` → `object`

Parse an SDM URL into its components. Auto-detects standard and compact formats.

---

## Debugging a Tap

Use the included debug script:

```bash
# Decode PICCData (shows UID + counter)
node examples/debug-tap.js "https://example.com/verify?picc_data=...&cmac=..." <meta-key-hex>

# Full verification (add file key as 3rd arg)
node examples/debug-tap.js "https://..." <meta-key-hex> <file-key-hex>
```

---

## Security Notes

- **Never hardcode keys.** Store SDM keys in a secrets manager or encrypted database.
- **Always check the read counter.** A cloned tag can't increment the real tag's counter.
- **Use diversified keys in production.** One compromised key shouldn't compromise all tags.
- **HTTPS only.** The CMAC proves the tag is real, but without HTTPS, the URL could be intercepted.
- **Rate limit your verify endpoint.** Prevent brute-force CMAC guessing.

---

## Project Structure

```
├── src/
│   ├── index.js     # Public API exports
│   ├── verify.js    # Core verification logic
│   ├── crypto.js    # AES-128, AES-CMAC (RFC 4493), key diversification
│   └── parser.js    # URL parsing with auto-format detection
├── test/
│   ├── crypto.test.js   # RFC 4493 test vectors + crypto tests
│   ├── parser.test.js   # URL format detection + parsing tests
│   └── verify.test.js   # Full verification flow + edge cases
├── examples/
│   ├── express-server.js  # Minimal verification server
│   └── debug-tap.js       # CLI tool to decode tapped URLs
├── package.json
├── LICENSE              # MIT
└── README.md
```

---

## Tests

```bash
npm test         # Run all 47 tests
npm run test:watch  # Watch mode
```

AES-CMAC implementation is validated against [RFC 4493](https://tools.ietf.org/html/rfc4493) official test vectors.

---

## Resources

- [NTAG 424 DNA Datasheet (NXP)](https://www.nxp.com/docs/en/data-sheet/NT4H2421Gx.pdf)
- [AN12196 — NTAG 424 DNA and TagTamper Application Note](https://www.nxp.com/docs/en/application-note/AN12196.pdf)
- [AN10922 — AES Key Diversification](https://www.nxp.com/docs/en/application-note/AN10922.pdf)
- [RFC 4493 — AES-CMAC Algorithm](https://tools.ietf.org/html/rfc4493)

---

## About

Built by **[Hamza Arshad](https://github.com/hamza-arshad)**. Based on production NFC authentication work done at **[Tethered](https://tethered.services)** and **[TetheredArt](https://tetheredart.com)**, where NTAG 424 DNA verifies physical products and artwork.

I consult on NFC architecture and implementation. Reach out via [LinkedIn](https://www.linkedin.com/in/hamzaarshad) or [email](mailto:sheikh.hamza.arshad@gmail.com).

---

## License

Apache-2.0 — see LICENSE and NOTICE
