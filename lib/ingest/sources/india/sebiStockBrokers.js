'use strict';
// intmId 30 = Stock Brokers (equity segment). ~5000 rows / 200 pages: run at most weekly.
module.exports = require('./_sebiRegistered').makeSource({
  id: 'sebi-stock-brokers', name: 'SEBI registered Stock Brokers - equity (allow-list)', intmId: 30,
  regRe: /^IN[A-Z][A-Z0-9]{8,12}$/, typeName: 'Stock Broker', schedule: 'every 7d', staleAfterHours: 24 * 14, timeoutMs: 20 * 60 * 1000,
});
