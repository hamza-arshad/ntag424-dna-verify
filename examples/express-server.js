'use strict';

/**
 * Minimal Express server for verifying NTAG 424 DNA tag taps.
 *
 *   npm install express
 *   node examples/express-server.js
 *
 * Configure your tags to point to:
 *   http://localhost:3000/verify?picc_data=...&cmac=...
 */

const express = require('express');
const { verifyTag } = require('../src');

const app = express();
const PORT = process.env.PORT || 3000;

// In production this is a database. Map of UID -> tag config.
const TAGS = new Map();
TAGS.set('04A23BC1D52A80', {
  sdmMetaReadKey: Buffer.from('00000000000000000000000000000000', 'hex'),
  sdmFileReadKey: Buffer.from('00112233445566778899AABBCCDDEEFF', 'hex'),
  productId: 'artwork-001',
  productName: 'Sunset Over Mountains — Limited Edition Print',
  lastCounter: 0,
});

app.get('/verify', (req, res) => {
  const fullUrl = `${req.protocol}://${req.get('host')}${req.originalUrl}`;
  console.log(`[${new Date().toISOString()}] Tap: ${fullUrl}`);

  try {
    for (const [uid, tag] of TAGS) {
      const result = verifyTag(fullUrl, {
        sdmMetaReadKey: tag.sdmMetaReadKey,
        sdmFileReadKey: tag.sdmFileReadKey,
        lastKnownCounter: tag.lastCounter,
      });

      if (result.authentic) {
        tag.lastCounter = result.readCounter;
        console.log(`  OK — UID: ${result.uid}, counter: ${result.readCounter}`);
        return res.json({
          authentic: true,
          product: { id: tag.productId, name: tag.productName },
          tag: { uid: result.uid, scanNumber: result.readCounter },
        });
      }

      if (result.reason === 'counter_replay') {
        console.log(`  REPLAY — UID: ${result.uid}`);
        return res.json({
          authentic: false,
          reason: 'counter_replay',
          message: 'This tag may have been cloned.',
        });
      }
    }

    console.log('  UNKNOWN TAG');
    return res.json({ authentic: false, reason: 'unknown_tag' });
  } catch (err) {
    console.error('  ERROR:', err.message);
    return res.status(500).json({ authentic: false, reason: 'verification_error' });
  }
});

app.get('/health', (req, res) => {
  res.json({ status: 'ok', registeredTags: TAGS.size });
});

app.listen(PORT, () => {
  console.log(`Verification server on port ${PORT}`);
  console.log(`${TAGS.size} tags registered`);
});
