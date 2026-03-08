'use strict';

const { verifyTag, decodeTag, decryptPiccData, computeSdmCmac, PICC_DATA_TAG } = require('../src/verify');
const { aesEncrypt, aesCmac } = require('../src/crypto');

// Builds a self-consistent test URL simulating a real tag tap
function createTestTapUrl(opts = {}) {
  const uid = opts.uid || Buffer.from('04A23BC1D52A80', 'hex');
  const readCounter = opts.readCounter || 42;
  const sdmMetaReadKey = opts.sdmMetaReadKey || Buffer.alloc(16, 0);
  const sdmFileReadKey = opts.sdmFileReadKey || Buffer.from('00112233445566778899AABBCCDDEEFF', 'hex');
  const baseUrl = opts.baseUrl || 'https://example.com/verify';

  const plaintext = Buffer.alloc(16, 0);
  plaintext[0] = PICC_DATA_TAG;
  uid.copy(plaintext, 1);
  plaintext[8] = readCounter & 0xff;
  plaintext[9] = (readCounter >> 8) & 0xff;
  plaintext[10] = (readCounter >> 16) & 0xff;

  const encPicc = aesEncrypt(plaintext, sdmMetaReadKey);
  const piccHex = encPicc.toString('hex').toUpperCase();
  const urlBeforeCmac = `${baseUrl}?picc_data=${piccHex}&cmac=`;
  const cmacHex = aesCmac(Buffer.from(urlBeforeCmac, 'utf8'), sdmFileReadKey)
    .subarray(0, 8).toString('hex').toUpperCase();

  return { url: `${urlBeforeCmac}${cmacHex}`, uid, readCounter, sdmMetaReadKey, sdmFileReadKey, piccHex, cmacHex };
}

describe('verify', () => {
  describe('decryptPiccData', () => {
    it('decrypts valid PICCData', () => {
      const uid = Buffer.from('04A23BC1D52A80', 'hex');
      const key = Buffer.alloc(16, 0);
      const pt = Buffer.alloc(16, 0);
      pt[0] = PICC_DATA_TAG;
      uid.copy(pt, 1);
      pt[8] = 42;

      const r = decryptPiccData(aesEncrypt(pt, key), key);
      expect(r.uid).toEqual(uid);
      expect(r.readCounter).toBe(42);
    });

    it('handles large counter values', () => {
      const key = Buffer.alloc(16, 0);
      const pt = Buffer.alloc(16, 0);
      pt[0] = PICC_DATA_TAG;
      pt[8] = 0x56; pt[9] = 0x34; pt[10] = 0x12;

      expect(decryptPiccData(aesEncrypt(pt, key), key).readCounter).toBe(0x123456);
    });

    it('throws on wrong key', () => {
      const key = Buffer.alloc(16, 0);
      const pt = Buffer.alloc(16, 0);
      pt[0] = PICC_DATA_TAG;
      expect(() => decryptPiccData(aesEncrypt(pt, key), Buffer.alloc(16, 0xff))).toThrow('tag byte');
    });

    it('throws on bad length', () => {
      expect(() => decryptPiccData(Buffer.alloc(8), Buffer.alloc(16))).toThrow('16 bytes');
    });
  });

  describe('verifyTag', () => {
    it('verifies a valid tap (direct keys)', () => {
      const t = createTestTapUrl();
      const r = verifyTag(t.url, { sdmMetaReadKey: t.sdmMetaReadKey, sdmFileReadKey: t.sdmFileReadKey });
      expect(r.authentic).toBe(true);
      expect(r.reason).toBe('valid');
      expect(r.uid).toBe('04A23BC1D52A80');
      expect(r.readCounter).toBe(42);
    });

    it('rejects tampered CMAC', () => {
      const t = createTestTapUrl();
      const bad = t.url.replace(/cmac=[0-9A-F]+/, 'cmac=0000000000000000');
      const r = verifyTag(bad, { sdmMetaReadKey: t.sdmMetaReadKey, sdmFileReadKey: t.sdmFileReadKey });
      expect(r.authentic).toBe(false);
      expect(r.reason).toBe('cmac_mismatch');
    });

    it('rejects wrong file read key', () => {
      const t = createTestTapUrl();
      const r = verifyTag(t.url, { sdmMetaReadKey: t.sdmMetaReadKey, sdmFileReadKey: Buffer.alloc(16, 0xff) });
      expect(r.authentic).toBe(false);
      expect(r.reason).toBe('cmac_mismatch');
    });

    it('rejects wrong meta read key', () => {
      const t = createTestTapUrl();
      const r = verifyTag(t.url, { sdmMetaReadKey: Buffer.alloc(16, 0xff), sdmFileReadKey: t.sdmFileReadKey });
      expect(r.authentic).toBe(false);
      expect(r.reason).toBe('picc_decryption_failed');
    });

    it('detects counter replay (same counter)', () => {
      const t = createTestTapUrl({ readCounter: 42 });
      const r = verifyTag(t.url, { sdmMetaReadKey: t.sdmMetaReadKey, sdmFileReadKey: t.sdmFileReadKey, lastKnownCounter: 42 });
      expect(r.authentic).toBe(false);
      expect(r.reason).toBe('counter_replay');
    });

    it('detects counter going backwards', () => {
      const t = createTestTapUrl({ readCounter: 10 });
      const r = verifyTag(t.url, { sdmMetaReadKey: t.sdmMetaReadKey, sdmFileReadKey: t.sdmFileReadKey, lastKnownCounter: 50 });
      expect(r.authentic).toBe(false);
      expect(r.reason).toBe('counter_replay');
    });

    it('passes when counter is ahead', () => {
      const t = createTestTapUrl({ readCounter: 100 });
      const r = verifyTag(t.url, { sdmMetaReadKey: t.sdmMetaReadKey, sdmFileReadKey: t.sdmFileReadKey, lastKnownCounter: 50 });
      expect(r.authentic).toBe(true);
    });

    it('skips counter check when not provided', () => {
      const t = createTestTapUrl({ readCounter: 1 });
      const r = verifyTag(t.url, { sdmMetaReadKey: t.sdmMetaReadKey, sdmFileReadKey: t.sdmFileReadKey });
      expect(r.authentic).toBe(true);
      expect(r.counterWarning).toBeNull();
    });

    it('works with compact URL format', () => {
      const uid = Buffer.from('04A23BC1D52A80', 'hex');
      const metaKey = Buffer.alloc(16, 0);
      const fileKey = Buffer.from('00112233445566778899AABBCCDDEEFF', 'hex');

      const pt = Buffer.alloc(16, 0);
      pt[0] = PICC_DATA_TAG;
      uid.copy(pt, 1);
      pt[8] = 5;

      const piccHex = aesEncrypt(pt, metaKey).toString('hex').toUpperCase();
      const before = `https://x.com/t?e=${piccHex}&m=`;
      const cmacHex = aesCmac(Buffer.from(before, 'utf8'), fileKey).subarray(0, 8).toString('hex').toUpperCase();

      const r = verifyTag(`${before}${cmacHex}`, { sdmMetaReadKey: metaKey, sdmFileReadKey: fileKey, piccDataParam: 'e', cmacParam: 'm' });
      expect(r.authentic).toBe(true);
      expect(r.readCounter).toBe(5);
    });

    it('works with diversified keys', () => {
      const masterKey = Buffer.from('AABBCCDDEEFF00112233445566778899', 'hex');
      const uid = Buffer.from('04A23BC1D52A80', 'hex');
      const { diversifyKey } = require('../src/crypto');
      const fileKey = diversifyKey(masterKey, uid, 'file');

      const t = createTestTapUrl({ uid, sdmMetaReadKey: masterKey, sdmFileReadKey: fileKey });
      const r = verifyTag(t.url, { masterKey, fileKeyLabel: 'file' });
      expect(r.authentic).toBe(true);
    });

    it('throws on missing keys', () => {
      expect(() => verifyTag('https://x.com/v?picc_data=AA&cmac=BB', {})).toThrow('Provide either');
    });

    it('throws on empty URL', () => {
      expect(() => verifyTag('', {})).toThrow('non-empty');
    });
  });

  describe('decodeTag', () => {
    it('decodes without verifying CMAC', () => {
      const t = createTestTapUrl();
      const r = decodeTag(t.url, t.sdmMetaReadKey);
      expect(r.uid).toBe('04A23BC1D52A80');
      expect(r.readCounter).toBe(42);
    });
  });

  describe('computeSdmCmac', () => {
    it('returns 8 bytes', () => {
      expect(computeSdmCmac(Buffer.from('test'), Buffer.alloc(16, 0xaa)).length).toBe(8);
    });

    it('is input-dependent', () => {
      const key = Buffer.alloc(16, 0xaa);
      expect(computeSdmCmac(Buffer.from('a'), key)).not.toEqual(computeSdmCmac(Buffer.from('b'), key));
    });
  });
});
