'use strict';

const { parseSdmUrl, detectFormat } = require('../src/parser');

const PICC = 'EF963FF7828658A599F3041510671E88';
const CMAC = '94EED9EE65337086';

describe('parser', () => {
  describe('detectFormat', () => {
    it('detects standard format', () => {
      const f = detectFormat(`https://x.com/v?picc_data=${PICC}&cmac=${CMAC}`, {});
      expect(f.piccDataParam).toBe('picc_data');
    });

    it('detects compact format', () => {
      const f = detectFormat(`https://x.com/t?e=${PICC}&m=${CMAC}`, {});
      expect(f.piccDataParam).toBe('e');
    });

    it('respects explicit options', () => {
      const f = detectFormat('https://x.com/t?enc=aa&mac=bb', { piccDataParam: 'enc', cmacParam: 'mac' });
      expect(f.piccDataParam).toBe('enc');
    });
  });

  describe('parseSdmUrl', () => {
    it('parses standard format', () => {
      const r = parseSdmUrl(`https://x.com/v?picc_data=${PICC}&cmac=${CMAC}`);
      expect(r.piccData.length).toBe(16);
      expect(r.cmac.length).toBe(8);
      expect(r.piccDataHex).toBe(PICC);
      expect(r.cmacHex).toBe(CMAC);
      expect(r.baseUrl).toBe('https://x.com/v');
    });

    it('parses compact format', () => {
      const r = parseSdmUrl(`https://x.com/t?e=${PICC}&m=${CMAC}`);
      expect(r.piccData.length).toBe(16);
      expect(r.cmac.length).toBe(8);
    });

    it('parses custom param names', () => {
      const r = parseSdmUrl(`https://x.com/s?enc=${PICC}&mac=${CMAC}`, { piccDataParam: 'enc', cmacParam: 'mac' });
      expect(r.piccDataHex).toBe(PICC);
    });

    it('computes CMAC input correctly', () => {
      const url = `https://x.com/v?picc_data=${PICC}&cmac=${CMAC}`;
      const r = parseSdmUrl(url);
      expect(r.cmacInput.toString('utf8')).toBe(`https://x.com/v?picc_data=${PICC}&cmac=`);
    });

    it('handles extra query params', () => {
      const r = parseSdmUrl(`https://x.com/v?id=1&picc_data=${PICC}&cmac=${CMAC}&x=y`);
      expect(r.piccDataHex).toBe(PICC);
    });

    it('normalizes lowercase hex', () => {
      const r = parseSdmUrl(`https://x.com/v?picc_data=${PICC.toLowerCase()}&cmac=${CMAC.toLowerCase()}`);
      expect(r.piccDataHex).toBe(PICC);
    });

    it('throws on missing picc_data', () => {
      expect(() => parseSdmUrl(`https://x.com/v?cmac=${CMAC}`)).toThrow('PICCData');
    });

    it('throws on missing cmac', () => {
      expect(() => parseSdmUrl(`https://x.com/v?picc_data=${PICC}`)).toThrow('CMAC');
    });

    it('throws on bad picc_data length', () => {
      expect(() => parseSdmUrl(`https://x.com/v?picc_data=AABB&cmac=${CMAC}`)).toThrow('32 hex');
    });

    it('throws on bad cmac length', () => {
      expect(() => parseSdmUrl(`https://x.com/v?picc_data=${PICC}&cmac=AABB`)).toThrow('16 hex');
    });
  });
});
