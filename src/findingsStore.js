const { v4: uuidv4 } = require('uuid');
const logger = require('./logger');
const FINDINGS = [];
function addFinding(f) {
  const id = uuidv4();
  const base = { id, status: 'open', timestamp: new Date().toISOString() };
  const record = Object.assign({}, base, f);
  FINDINGS.push(record);
  logger.info(`Finding added: ${id} ${f.type} ${f.severity}`);
  return record;
}
function getFindings(filter = {}) {
  if (!filter || Object.keys(filter).length === 0) return FINDINGS;
  return FINDINGS.filter(f => {
    for (const k of Object.keys(filter)) { if (f[k] !== filter[k]) return false; }
    return true;
  });
}
function updateFindingStatus(id, status) {
  const f = FINDINGS.find(x => x.id === id);
  if (!f) return null;
  f.status = status;
  return f;
}
module.exports = { addFinding, getFindings, updateFindingStatus, FINDINGS };
