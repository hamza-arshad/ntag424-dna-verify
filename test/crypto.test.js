'use strict';

const { aesDecrypt, aesEncrypt, aesCmac, diversifyKey, generateRandomKey, xor } = require('../src/crypto');

describe('crypto', () => {
  describe('aesEncrypt / aesDecrypt', () => {
    it('round-trips correctly', () => {
      const key = Buffer.from('2b7e151628aed2a6abf7158809cf4f3c', 'hex');
      const plaintext = Buffer.alloc(16, 0);
      const encrypted = aesEncrypt(plaintext, key);
      const decrypted = aesDecrypt(encrypted, key);
      expect(decrypted).toEqual(plaintext);
    });

    it('rejects non-16-byte keys', () => {
      expect(() => aesEncrypt(Buffer.alloc(16), Buffer.alloc(8))).toThrow('16 bytes');
      expect(() => aesDecrypt(Buffer.alloc(16), Buffer.alloc(32))).toThrow('16 bytes');
    });
  });

  // RFC 4493 Section 4 test vectors
  describe('aesCmac (RFC 4493)', () => {
    const key = Buffer.from('2b7e151628aed2a6abf7158809cf4f3c', 'hex');

    it('empty message', () => {
      const expected = Buffer.from('bb1d6929e95937287fa37d129b756746', 'hex');
      expect(aesCmac(Buffer.alloc(0), key)).toEqual(expected);
    });

    it('16-byte message', () => {
      const msg = Buffer.from('6bc1bee22e409f96e93d7e117393172a', 'hex');
      const expected = Buffer.from('070a16b46b4d4144f79bdd9dd04a287c', 'hex');
      expect(aesCmac(msg, key)).toEqual(expected);
    });

    it('40-byte message', () => {
      const msg = Buffer.from(
        '6bc1bee22e409f96e93d7e117393172a' +
        'ae2d8a571e03ac9c9eb76fac45af8e51' +
        '30c81c46a35ce411', 'hex'
      );
      const expected = Buffer.from('dfa66747de9ae63030ca32611497c827', 'hex');
      expect(aesCmac(msg, key)).toEqual(expected);
    });

    it('64-byte message', () => {
      const msg = Buffer.from(
        '6bc1bee22e409f96e93d7e117393172a' +
        'ae2d8a571e03ac9c9eb76fac45af8e51' +
        '30c81c46a35ce411e5fbc1191a0a52ef' +
        'f69f2445df4f9b17ad2b417be66c3710', 'hex'
      );
      const expected = Buffer.from('51f0bebf7e3b9d92fc49741779363cfe', 'hex');
      expect(aesCmac(msg, key)).toEqual(expected);
    });
  });

  describe('diversifyKey', () => {
    const master = Buffer.alloc(16, 0xaa);
    const uid = Buffer.from('04A23BC1D52A80', 'hex');

    it('produces 16-byte output', () => {
      expect(diversifyKey(master, uid).length).toBe(16);
    });

    it('different UIDs produce different keys', () => {
      const uid2 = Buffer.from('04B34CD2E63B91', 'hex');
      expect(diversifyKey(master, uid)).not.toEqual(diversifyKey(master, uid2));
    });

    it('different labels produce different keys', () => {
      expect(diversifyKey(master, uid, 'meta')).not.toEqual(diversifyKey(master, uid, 'file'));
    });

    it('is deterministic', () => {
      expect(diversifyKey(master, uid, 'x')).toEqual(diversifyKey(master, uid, 'x'));
    });

    it('rejects bad inputs', () => {
      expect(() => diversifyKey(Buffer.alloc(8), Buffer.alloc(7))).toThrow('Master key');
      expect(() => diversifyKey(Buffer.alloc(16), Buffer.alloc(4))).toThrow('UID');
    });
  });

  describe('generateRandomKey', () => {
    it('returns 16 bytes', () => {
      expect(generateRandomKey().length).toBe(16);
    });

    it('is not deterministic', () => {
      expect(generateRandomKey()).not.toEqual(generateRandomKey());
    });
  });

  describe('xor', () => {
    it('works', () => {
      const a = Buffer.from('ff00ff00', 'hex');
      const b = Buffer.from('0f0f0f0f', 'hex');
      expect(xor(a, b)).toEqual(Buffer.from('f00ff00f', 'hex'));
    });

    it('rejects different lengths', () => {
      expect(() => xor(Buffer.alloc(4), Buffer.alloc(8))).toThrow('same length');
    });
  });
});
