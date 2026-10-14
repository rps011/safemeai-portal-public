'use strict';
module.exports = require('./_sebiRegistered').makeSource({
  id: 'sebi-research-analysts', name: 'SEBI registered Research Analysts (allow-list)', intmId: 14,
  regRe: /^INH[A-Z0-9]{8,12}$/, typeName: 'Research Analyst', schedule: 'every 7d', staleAfterHours: 24 * 14,
});
