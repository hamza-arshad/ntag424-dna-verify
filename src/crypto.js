'use strict';

const crypto = require('crypto');

const BLOCK_SIZE = 16;
const ZERO_IV = Buffer.alloc(BLOCK_SIZE, 0);

/**
 * AES-128-CBC decrypt with zero IV.
 */
function aesDecrypt(data, key) {
  if (key.length !== 16) throw new Error('Key must be 16 bytes (AES-128)');
  const decipher = crypto.createDecipheriv('aes-128-cbc', key, ZERO_IV);
  decipher.setAutoPadding(false);
  return Buffer.concat([decipher.update(data), decipher.final()]);
}

/**
 * AES-128-CBC encrypt with zero IV.
 */
function aesEncrypt(data, key) {
  if (key.length !== 16) throw new Error('Key must be 16 bytes (AES-128)');
  const cipher = crypto.createCipheriv('aes-128-cbc', key, ZERO_IV);
  cipher.setAutoPadding(false);
  return Buffer.concat([cipher.update(data), cipher.final()]);
}

function leftShift(buf) {
  const output = Buffer.alloc(buf.length);
  let carry = 0;
  for (let i = buf.length - 1; i >= 0; i--) {
    const nextCarry = (buf[i] >> 7) & 1;
    output[i] = ((buf[i] << 1) | carry) & 0xff;
    carry = nextCarry;
  }
  return output;
}

function xor(a, b) {
  if (a.length !== b.length) {
    throw new Error(`XOR buffers must be same length (got ${a.length} and ${b.length})`);
  }
  const result = Buffer.alloc(a.length);
  for (let i = 0; i < a.length; i++) {
    result[i] = a[i] ^ b[i];
  }
  return result;
}

/**
 * Generate AES-CMAC subkeys per RFC 4493.
 */
function generateSubkeys(key) {
  const RB = Buffer.alloc(16, 0);
  RB[15] = 0x87;

  const L = aesEncrypt(Buffer.alloc(16, 0), key);

  let k1 = leftShift(L);
  if (L[0] & 0x80) k1 = xor(k1, RB);

  let k2 = leftShift(k1);
  if (k1[0] & 0x80) k2 = xor(k2, RB);

  return { k1, k2 };
}

/**
 * AES-CMAC per RFC 4493.
 */
function aesCmac(message, key) {
  if (key.length !== 16) throw new Error('Key must be 16 bytes (AES-128)');

  const { k1, k2 } = generateSubkeys(key);
  const n = Math.ceil(message.length / BLOCK_SIZE) || 1;
  const lastBlockComplete = (message.length > 0) && (message.length % BLOCK_SIZE === 0);

  let lastBlock;
  if (lastBlockComplete) {
    lastBlock = xor(message.subarray((n - 1) * BLOCK_SIZE), k1);
  } else {
    const padded = Buffer.alloc(BLOCK_SIZE, 0);
    const lastStart = (n - 1) * BLOCK_SIZE;
    const remaining = message.subarray(lastStart);
    remaining.copy(padded, 0);
    padded[remaining.length] = 0x80;
    lastBlock = xor(padded, k2);
  }

  let x = Buffer.alloc(BLOCK_SIZE, 0);
  for (let i = 0; i < n - 1; i++) {
    const block = message.subarray(i * BLOCK_SIZE, (i + 1) * BLOCK_SIZE);
    x = aesEncrypt(xor(x, block), key);
  }
  x = aesEncrypt(xor(x, lastBlock), key);

  return x;
}

/**
 * Derive a per-tag key from a master key and UID.
 * Uses NXP AN10922 key diversification.
 */
function diversifyKey(masterKey, uid, label = '') {
  if (masterKey.length !== 16) throw new Error('Master key must be 16 bytes');
  if (uid.length !== 7) throw new Error('UID must be 7 bytes');

  const labelBuf = Buffer.from(label, 'utf8');
  const divInput = Buffer.alloc(1 + labelBuf.length + 1 + uid.length + 2);

  let offset = 0;
  divInput[offset++] = 0x01;
  labelBuf.copy(divInput, offset);
  offset += labelBuf.length;
  divInput[offset++] = 0x00;
  uid.copy(divInput, offset);
  offset += uid.length;
  divInput[offset++] = 0x00;
  divInput[offset++] = 0x80;

  return aesCmac(divInput, masterKey);
}

function generateRandomKey() {
  return crypto.randomBytes(16);
}

module.exports = { aesDecrypt, aesEncrypt, aesCmac, diversifyKey, generateRandomKey, xor };
