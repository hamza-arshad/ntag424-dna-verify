'use strict';

const { aesDecrypt, aesCmac, diversifyKey } = require('./crypto');
const { parseSdmUrl } = require('./parser');

const PICC_DATA_TAG = 0xc7;

/**
 * Decrypt PICCData to extract tag UID and read counter.
 *
 * Decrypted structure (16 bytes):
 *   Byte 0:     Tag byte (0xC7)
 *   Bytes 1-7:  7-byte UID
 *   Bytes 8-10: 3-byte read counter (little-endian)
 *   Bytes 11-15: Padding
 */
function decryptPiccData(encryptedPiccData, sdmMetaReadKey) {
  if (encryptedPiccData.length !== 16) {
    throw new Error(`PICCData must be 16 bytes, got ${encryptedPiccData.length}`);
  }
  if (sdmMetaReadKey.length !== 16) {
    throw new Error('SDM Meta Read Key must be 16 bytes');
  }

  const decrypted = aesDecrypt(encryptedPiccData, sdmMetaReadKey);
  const tagByte = decrypted[0];

  if (tagByte !== PICC_DATA_TAG) {
    throw new Error(
      `Invalid PICCData tag byte: expected 0x${PICC_DATA_TAG.toString(16)}, ` +
      `got 0x${tagByte.toString(16)}. Wrong decryption key?`
    );
  }

  const uid = decrypted.subarray(1, 8);
  const readCounter = decrypted[8] | (decrypted[9] << 8) | (decrypted[10] << 16);

  return { uid, readCounter, tagByte };
}

/**
 * Compute expected CMAC. Returns first 8 bytes of the full AES-CMAC.
 */
function computeSdmCmac(cmacInput, sdmFileReadKey) {
  const fullCmac = aesCmac(cmacInput, sdmFileReadKey);
  return fullCmac.subarray(0, 8);
}

/**
 * Verify an NTAG 424 DNA tag tap.
 *
 * Two key strategies supported:
 *   1. Direct keys:      { sdmMetaReadKey, sdmFileReadKey }
 *   2. Diversified keys: { masterKey } — per-tag keys derived from master + UID
 */
function verifyTag(url, options = {}) {
  if (!url || typeof url !== 'string') {
    throw new Error('URL must be a non-empty string');
  }

  const useDiversifiedKeys = !!options.masterKey;
  const useDirectKeys = !!(options.sdmMetaReadKey && options.sdmFileReadKey);

  if (!useDiversifiedKeys && !useDirectKeys) {
    throw new Error(
      'Provide either { sdmMetaReadKey, sdmFileReadKey } for direct keys, ' +
      'or { masterKey } for diversified keys'
    );
  }

  // Parse URL
  const parsed = parseSdmUrl(url, {
    piccDataParam: options.piccDataParam,
    cmacParam: options.cmacParam,
  });

  // Determine meta key
  let sdmMetaReadKey = useDiversifiedKeys ? options.masterKey : options.sdmMetaReadKey;

  // Decrypt PICCData
  let piccResult;
  try {
    piccResult = decryptPiccData(parsed.piccData, sdmMetaReadKey);
  } catch (err) {
    return {
      authentic: false,
      reason: 'picc_decryption_failed',
      error: err.message,
    };
  }

  // Determine file read key
  let sdmFileReadKey;
  if (useDiversifiedKeys) {
    const fileLabel = options.fileKeyLabel || 'file';
    sdmFileReadKey = diversifyKey(options.masterKey, piccResult.uid, fileLabel);
  } else {
    sdmFileReadKey = options.sdmFileReadKey;
  }

  // Verify CMAC
  const expectedCmac = computeSdmCmac(parsed.cmacInput, sdmFileReadKey);
  const cmacValid = expectedCmac.equals(parsed.cmac);

  if (!cmacValid) {
    return {
      authentic: false,
      reason: 'cmac_mismatch',
      uid: piccResult.uid.toString('hex').toUpperCase(),
      readCounter: piccResult.readCounter,
    };
  }

  // Counter replay check
  let counterValid = true;
  let counterWarning = null;

  if (typeof options.lastKnownCounter === 'number') {
    if (piccResult.readCounter <= options.lastKnownCounter) {
      counterValid = false;
      counterWarning = `Counter ${piccResult.readCounter} is not greater than last known ${options.lastKnownCounter}. Possible clone or replay.`;
    }
  }

  return {
    authentic: cmacValid && counterValid,
    reason: !counterValid ? 'counter_replay' : 'valid',
    uid: piccResult.uid.toString('hex').toUpperCase(),
    readCounter: piccResult.readCounter,
    piccDataHex: parsed.piccDataHex,
    cmacHex: parsed.cmacHex,
    counterWarning,
  };
}

/**
 * Decode a tap URL without full verification.
 * Decrypts PICCData but does NOT check the CMAC. Useful for debugging.
 */
function decodeTag(url, sdmMetaReadKey, options = {}) {
  const parsed = parseSdmUrl(url, options);
  const piccResult = decryptPiccData(parsed.piccData, sdmMetaReadKey);

  return {
    uid: piccResult.uid.toString('hex').toUpperCase(),
    readCounter: piccResult.readCounter,
    piccDataHex: parsed.piccDataHex,
    cmacHex: parsed.cmacHex,
    baseUrl: parsed.baseUrl,
  };
}

module.exports = { verifyTag, decodeTag, decryptPiccData, computeSdmCmac, PICC_DATA_TAG };
