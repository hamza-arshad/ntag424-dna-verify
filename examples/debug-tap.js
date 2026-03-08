'use strict';

/**
 * Decode a tapped URL for debugging.
 *
 *   node examples/debug-tap.js <url> [meta-key-hex] [file-key-hex]
 */

const { decodeTag, verifyTag, parseSdmUrl } = require('../src');

const url = process.argv[2];
const keyHex = process.argv[3] || '00000000000000000000000000000000';

if (!url) {
  console.log('Usage: node debug-tap.js <tapped-url> [meta-key-hex] [file-key-hex]');
  process.exit(1);
}

const metaKey = Buffer.from(keyHex, 'hex');

console.log('=== NTAG 424 DNA Tap Debugger ===\n');

// Parse
console.log('1. URL:');
try {
  const p = parseSdmUrl(url);
  console.log(`   Base:      ${p.baseUrl}`);
  console.log(`   PICCData:  ${p.piccDataHex}`);
  console.log(`   CMAC:      ${p.cmacHex}`);
} catch (err) {
  console.log(`   FAILED: ${err.message}`);
  process.exit(1);
}

// Decrypt
console.log('\n2. PICCData:');
try {
  const d = decodeTag(url, metaKey);
  console.log(`   UID:       ${d.uid}`);
  console.log(`   Counter:   ${d.readCounter}`);
} catch (err) {
  console.log(`   FAILED: ${err.message}`);
  console.log('   Check your meta read key.');
  process.exit(1);
}

// Verify (optional)
const fileKeyHex = process.argv[4];
if (fileKeyHex) {
  console.log('\n3. CMAC:');
  const r = verifyTag(url, { sdmMetaReadKey: metaKey, sdmFileReadKey: Buffer.from(fileKeyHex, 'hex') });
  console.log(r.authentic ? '   VALID' : `   INVALID (${r.reason})`);
} else {
  console.log('\n3. CMAC: skipped (pass file-key-hex as 3rd arg)');
}

console.log('');
