// CVSS v3.1 base-score helpers — shared by the site (vector chips) and scripts/validate.mjs.
// Spec: https://www.first.org/cvss/v3.1/specification-document

export const METRICS = {
  AV: { label: "Attack vector", values: { N: "Network", A: "Adjacent", L: "Local", P: "Physical" } },
  AC: { label: "Attack complexity", values: { L: "Low", H: "High" } },
  PR: { label: "Privileges required", values: { N: "None", L: "Low", H: "High" } },
  UI: { label: "User interaction", values: { N: "None", R: "Required" } },
  S:  { label: "Scope", values: { U: "Unchanged", C: "Changed" } },
  C:  { label: "Confidentiality", values: { H: "High", L: "Low", N: "None" } },
  I:  { label: "Integrity", values: { H: "High", L: "Low", N: "None" } },
  A:  { label: "Availability", values: { H: "High", L: "Low", N: "None" } },
};
const ORDER = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"];

/** Parse "CVSS:3.1/AV:N/..." → { AV:"N", ... } or null if malformed/incomplete. */
export function parseVector(vector) {
  if (typeof vector !== "string" || !/^CVSS:3\.[01]\//.test(vector)) return null;
  const out = {};
  for (const part of vector.split("/").slice(1)) {
    const [k, v] = part.split(":");
    if (!METRICS[k] || !(v in METRICS[k].values) || k in out) return null;
    out[k] = v;
  }
  return ORDER.every((k) => k in out) ? out : null;
}

/** Human-readable metric list for display. */
export function describeVector(vector) {
  const m = parseVector(vector);
  if (!m) return [];
  return ORDER.map((k) => ({ key: k, code: m[k], label: METRICS[k].label, value: METRICS[k].values[m[k]] }));
}

function roundUp(x) {
  const i = Math.round(x * 100000);
  return i % 10000 === 0 ? i / 100000 : (Math.floor(i / 10000) + 1) / 10;
}

/** CVSS v3.1 base score from a vector string, or null. */
export function baseScore(vector) {
  const m = parseVector(vector);
  if (!m) return null;
  const changed = m.S === "C";
  const W = {
    AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
    AC: { L: 0.77, H: 0.44 },
    PR: { N: 0.85, L: changed ? 0.68 : 0.62, H: changed ? 0.5 : 0.27 },
    UI: { N: 0.85, R: 0.62 },
    CIA: { H: 0.56, L: 0.22, N: 0 },
  };
  const iss = 1 - (1 - W.CIA[m.C]) * (1 - W.CIA[m.I]) * (1 - W.CIA[m.A]);
  const impact = changed ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15) : 6.42 * iss;
  const exploitability = 8.22 * W.AV[m.AV] * W.AC[m.AC] * W.PR[m.PR] * W.UI[m.UI];
  if (impact <= 0) return 0;
  return changed ? roundUp(Math.min(1.08 * (impact + exploitability), 10)) : roundUp(Math.min(impact + exploitability, 10));
}

/** Qualitative severity rating for a base score. */
export function severityOf(score) {
  if (score >= 9) return "Critical";
  if (score >= 7) return "High";
  if (score >= 4) return "Medium";
  if (score > 0) return "Low";
  return "None";
}
