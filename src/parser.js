'use strict';

const { URL } = require('url');

const URL_FORMATS = {
  standard: { piccDataParam: 'picc_data', cmacParam: 'cmac' },
  compact: { piccDataParam: 'e', cmacParam: 'm' },
};

function detectFormat(url, options) {
  if (options.piccDataParam && options.cmacParam) {
    return { piccDataParam: options.piccDataParam, cmacParam: options.cmacParam };
  }
  const lower = url.toLowerCase();
  if (lower.includes('picc_data=') || lower.includes('piccdata=')) {
    return URL_FORMATS.standard;
  }
  if (/[?&]e=[0-9a-f]{32}/i.test(url) && /[?&]m=[0-9a-f]{16}/i.test(url)) {
    return URL_FORMATS.compact;
  }
  return URL_FORMATS.standard;
}

function computeCmacInput(url, cmacParam, cmacHex) {
  const cmacValueIndex = url.lastIndexOf(cmacHex);
  if (cmacValueIndex !== -1) return url.substring(0, cmacValueIndex);

  const upperUrl = url.toUpperCase();
  const upperCmac = cmacHex.toUpperCase();
  const idx = upperUrl.lastIndexOf(upperCmac);
  if (idx !== -1) return url.substring(0, idx);

  throw new Error('Could not locate CMAC value in URL for CMAC input computation');
}

/**
 * Parse an SDM URL from an NTAG 424 DNA tag tap.
 * Auto-detects standard (?picc_data=...&cmac=...) and compact (?e=...&m=...) formats.
 */
function parseSdmUrl(url, options = {}) {
  const format = detectFormat(url, options);
  const piccDataParam = options.piccDataParam || format.piccDataParam;
  const cmacParam = options.cmacParam || format.cmacParam;

  const parsed = new URL(url);
  const piccDataHex = parsed.searchParams.get(piccDataParam);
  const cmacHex = parsed.searchParams.get(cmacParam);

  if (!piccDataHex) {
    throw new Error(
      `PICCData parameter '${piccDataParam}' not found in URL. ` +
      `Available params: ${[...parsed.searchParams.keys()].join(', ')}`
    );
  }
  if (!cmacHex) {
    throw new Error(
      `CMAC parameter '${cmacParam}' not found in URL. ` +
      `Available params: ${[...parsed.searchParams.keys()].join(', ')}`
    );
  }

  if (!/^[0-9A-Fa-f]{32}$/.test(piccDataHex)) {
    throw new Error(`Invalid PICCData: expected 32 hex chars, got '${piccDataHex}' (${piccDataHex.length} chars)`);
  }
  if (!/^[0-9A-Fa-f]{16}$/.test(cmacHex)) {
    throw new Error(`Invalid CMAC: expected 16 hex chars, got '${cmacHex}' (${cmacHex.length} chars)`);
  }

  const cmacInput = computeCmacInput(url, cmacParam, cmacHex);

  return {
    piccData: Buffer.from(piccDataHex, 'hex'),
    cmac: Buffer.from(cmacHex, 'hex'),
    cmacInput: Buffer.from(cmacInput, 'utf8'),
    piccDataHex: piccDataHex.toUpperCase(),
    cmacHex: cmacHex.toUpperCase(),
    baseUrl: `${parsed.protocol}//${parsed.host}${parsed.pathname}`,
    fullUrl: url,
  };
}

module.exports = { parseSdmUrl, detectFormat, URL_FORMATS };
