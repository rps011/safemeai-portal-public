'use strict';
module.exports = require('./_sebiRegistered').makeSource({
  id: 'sebi-investment-advisers', name: 'SEBI registered Investment Advisers (allow-list)', intmId: 13,
  regRe: /^INA[A-Z0-9]{8,12}$/, typeName: 'Investment Adviser', schedule: 'every 7d', staleAfterHours: 24 * 14,
});
