function shannonEntropy(s) {
  if (!s || s.length === 0) return 0;
  const map = {};
  for (const c of s) map[c] = (map[c] || 0) + 1;
  const len = s.length;
  let ent = 0;
  for (const k in map) {
    const p = map[k] / len;
    ent -= p * Math.log2(p);
  }
  return ent;
}
function nowIso() { return new Date().toISOString(); }
module.exports = { shannonEntropy, nowIso };
