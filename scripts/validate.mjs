#!/usr/bin/env node
// Validates the generated data/ folder. Runs in CI (.github/workflows/validate.yml) and locally:
// `npm run validate`. Add --check-repos to confirm every linked writeup is publicly reachable.
import { readFileSync, existsSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { baseScore, severityOf, parseVector } from "../assets/js/cvss.js";

const DATA = fileURLToPath(new URL("../data/", import.meta.url));
const CHECK_REPOS = process.argv.includes("--check-repos");
const SEVERITIES = ["Critical", "High", "Medium", "Low"];
const RE = {
  id: /^(CVE-\d{4}-\d{4,}|BH-\d{4}-\d{3,})$/,
  tid: /^BH-\d{4}-\d{3,}$/,
  cwe: /^CWE-\d+$/,
  date: /^\d{4}-\d{2}-\d{2}$/,
  repo: /^[A-Za-z0-9-]+\/[A-Za-z0-9._-]+$/,
  ref: /^[A-Za-z0-9._/-]+$/,
  path: /^(?!.*\.\.)[A-Za-z0-9._/-]+$/,
};
// The exact shape of the public embargo data. Anything else could leak withheld details.
const EMBARGO_KEYS = ["windowDays", "fields", "types", "cwes", "extensions", "rows"];
const EMBARGO_FIELDS = ["trackingId", "type", "cwe", "cvss", "reported", "releaseAt", "windowDays", "ext", "ackDay", "fixedDay", "flags"];
const INDEX_FIELDS = ["id", "trackingId", "title", "vendor", "product", "type", "cwe", "date", "cvss", "fixedDay", "releaseDay", "repo", "poc"];

const problems = [];
const warnings = [];
const bad = (where, msg) => problems.push(`${where}: ${msg}`);
const read = (rel) => {
  const file = join(DATA, rel);
  if (!existsSync(file)) return undefined;
  try { return JSON.parse(readFileSync(file, "utf8")); } catch (err) { bad(rel, `not valid JSON (${err.message})`); return null; }
};
const isInt = (v) => Number.isInteger(v);
const sameList = (a, b) => Array.isArray(a) && a.length === b.length && a.every((x, i) => x === b[i]);

if (existsSync(join(DATA, "cves.json"))) warnings.push("data/cves.json is from the old layout and is ignored by the site. Import it into the vault (bh import) and publish.");

// A freshly uploaded site has no data until the vault's first publish.
if (!existsSync(join(DATA, "stats.json")) && !existsSync(join(DATA, "embargo.json"))) {
  console.log("No data yet: the vault's first publish creates data/. Nothing to check.");
  process.exit(0);
}

/* ---------- stats.json ---------- */
const stats = read("stats.json");
if (stats === undefined) bad("stats.json", "missing (run the vault's publish step)");
else if (stats) {
  if (stats.version !== 3) bad("stats.json", "version must be 3");
  if (!isInt(stats.released?.total)) bad("stats.json", "released.total must be a whole number");
  if (!Array.isArray(stats.index)) bad("stats.json", "index must list the years that have an index file");
}

/* ---------- embargo.json ---------- */
const embargoIds = new Set();
const emb = read("embargo.json");
if (emb) {
  for (const k of Object.keys(emb)) if (!EMBARGO_KEYS.includes(k)) bad("embargo.json", `key "${k}" is not allowed; withheld details belong in the private vault`);
  if (!sameList(emb.fields, EMBARGO_FIELDS)) bad("embargo.json", `fields must be exactly ${EMBARGO_FIELDS.join(", ")}`);
  if (!Array.isArray(emb.types) || emb.types.some((t) => typeof t !== "string")) bad("embargo.json", "types must be a list of class names");
  if (!Array.isArray(emb.cwes) || emb.cwes.some((c) => !RE.cwe.test(c))) bad("embargo.json", "cwes must be a list like CWE-89");
  const extSum = {};
  for (const [tid, list] of Object.entries(emb.extensions ?? {})) {
    if (!RE.tid.test(tid)) bad("embargo.json", `extensions key "${tid}" is not a tracking ID`);
    if (!Array.isArray(list)) { bad("embargo.json", `extensions of ${tid} must be a list`); continue; }
    for (const e of list) {
      for (const k of Object.keys(e)) if (!["days", "reason"].includes(k)) bad("embargo.json", `extension field "${k}" of ${tid} is not allowed`);
      if (!(isInt(e.days) && e.days > 0) || typeof e.reason !== "string" || !e.reason.trim()) bad("embargo.json", `extension of ${tid} needs whole days and a reason`);
    }
    extSum[tid] = list.reduce((s, e) => s + (e.days || 0), 0);
  }
  (emb.rows ?? []).forEach((r, i) => {
    const where = `embargo.json row ${i + 1}`;
    if (!Array.isArray(r) || r.length !== EMBARGO_FIELDS.length) { bad(where, `must have ${EMBARGO_FIELDS.length} values`); return; }
    const [tid, type, cwe, cvss, reported, releaseAt, windowDays, ext, ackDay, fixedDay, flags] = r;
    if (!RE.tid.test(tid ?? "")) bad(where, "trackingId must look like BH-2026-0021");
    else if (embargoIds.has(tid)) bad(where, `duplicate tracking ID ${tid}`);
    embargoIds.add(tid);
    if (!isInt(type) || !emb.types?.[type]) bad(where, "type must point into types");
    if (!(cwe === -1 || (isInt(cwe) && emb.cwes?.[cwe]))) bad(where, "cwe must be -1 or point into cwes");
    if (typeof cvss !== "number" || cvss < 0 || cvss > 10) bad(where, "cvss must be 0–10");
    if (!isInt(reported) || !isInt(releaseAt) || releaseAt < reported) bad(where, "reported and releaseAt must be unix seconds, release after report");
    if (!(isInt(windowDays) && windowDays > 0)) bad(where, "windowDays must be whole days");
    if (!(isInt(ext) && ext >= 0)) bad(where, "ext must be whole days");
    else if ((extSum[tid] ?? 0) !== ext) bad(where, `ext ${ext} does not match the listed extensions (${extSum[tid] ?? 0})`);
    for (const [k, v] of [["ackDay", ackDay], ["fixedDay", fixedDay]]) if (!(v === null || (isInt(v) && v >= 0))) bad(where, `${k} must be null or whole days`);
    if (!(isInt(flags) && flags >= 0 && flags <= 3)) bad(where, "flags must be 0–3");
  });
  for (const tid of Object.keys(emb.extensions ?? {})) if (!embargoIds.has(tid)) bad("embargo.json", `extensions listed for ${tid}, which is not under embargo`);
}

/* ---------- index/<year>.json and details/<year>/<date>.json ---------- */
const released = new Map(); // id -> { date, trackingId }
const trackingIds = new Set();
let indexRows = 0;
const indexDir = join(DATA, "index");
const years = existsSync(indexDir) ? readdirSync(indexDir).filter((f) => /^\d{4}\.json$/.test(f)).map((f) => f.slice(0, 4)).sort().reverse() : [];
if (stats && !sameList(stats.index, years)) bad("stats.json", `index lists ${JSON.stringify(stats.index)} but data/index has ${JSON.stringify(years)}`);
for (const y of years) {
  const rel = `index/${y}.json`;
  const idx = read(rel);
  if (!idx) continue;
  if (!sameList(idx.fields, INDEX_FIELDS)) { bad(rel, `fields must be exactly ${INDEX_FIELDS.join(", ")}`); continue; }
  let prev = "9999-99-99";
  (idx.rows ?? []).forEach((r, i) => {
    const where = `${rel} row ${i + 1}`;
    if (!Array.isArray(r) || r.length !== INDEX_FIELDS.length) { bad(where, `must have ${INDEX_FIELDS.length} values`); return; }
    const [id, tid, title, vendor, product, type, cwe, date, cvss, fixedDay, releaseDay, repo, poc] = r;
    indexRows++;
    if (!RE.id.test(id ?? "")) bad(where, "id must be a CVE ID or tracking ID");
    else if (released.has(id)) bad(where, `duplicate id ${id}`);
    if (tid != null) {
      if (!RE.tid.test(tid)) bad(where, "trackingId must look like BH-2026-0021");
      if (trackingIds.has(tid)) bad(where, `duplicate tracking ID ${tid}`);
      if (embargoIds.has(tid)) bad(where, `${tid} is both released and under embargo`);
      trackingIds.add(tid);
    }
    for (const [k, v] of [["title", title], ["vendor", vendor], ["product", product]]) if (typeof v !== "string" || !v.trim()) bad(where, `missing ${k}`);
    if (!isInt(type) || !idx.types?.[type]) bad(where, "type must point into types");
    if (cwe != null && !RE.cwe.test(cwe)) bad(where, "cwe must look like CWE-79");
    if (!RE.date.test(date ?? "") || date.slice(0, 4) !== y) bad(where, `date must be YYYY-MM-DD in ${y}`);
    else if (date > prev) bad(where, "rows must be sorted newest first");
    else prev = date;
    if (typeof cvss !== "number" || cvss < 0 || cvss > 10) bad(where, "cvss must be 0–10");
    for (const [k, v] of [["fixedDay", fixedDay], ["releaseDay", releaseDay]]) if (!(v === null || (isInt(v) && v >= 0))) bad(where, `${k} must be null or whole days`);
    if (repo != null && !RE.repo.test(repo)) bad(where, "repo must be owner/name");
    if (poc !== 0 && poc !== 1) bad(where, "poc must be 0 or 1");
    released.set(id, { date, tid });
  });
}
if (stats?.released && stats.released.total !== indexRows) bad("stats.json", `released.total is ${stats.released.total} but the index files hold ${indexRows} rows`);
// "reported" counts every finding, disclosed or not, from fields that are public anyway
if (stats?.reported) {
  const R = stats.reported, embRows = (emb?.rows ?? []).length;
  const sumOf = (o) => Object.values(o ?? {}).reduce((a, b) => a + b, 0);
  if (R.total !== embRows + indexRows) bad("stats.json", `reported.total is ${R.total} but embargo.json + index hold ${embRows + indexRows}`);
  if (sumOf(R.months) !== R.total) bad("stats.json", `reported.months adds up to ${sumOf(R.months)}, not ${R.total}`);
  if (sumOf(R.severity) !== R.total) bad("stats.json", `reported.severity adds up to ${sumOf(R.severity)}, not ${R.total}`);
  for (const c of R.classes ?? []) if (!Array.isArray(c) || c.length !== 3 || typeof c[0] !== "string" || !isInt(c[1]) || !isInt(c[2]) || c[2] > c[1]) bad("stats.json", `reported.classes entry ${JSON.stringify(c)} must be [class, reported, disclosed]`);
}

const withRepo = [];
const detailsDir = join(DATA, "details");
const detailFiles = existsSync(detailsDir) ? readdirSync(detailsDir).flatMap((y) => readdirSync(join(detailsDir, y)).map((f) => `details/${y}/${f}`)) : [];
const detailed = new Set();
for (const rel of detailFiles) {
  const day = read(rel);
  if (!day) continue;
  const date = rel.slice(-15, -5);
  for (const [id, c] of Object.entries(day)) {
    const where = `${rel} ${id}`;
    detailed.add(id);
    const row = released.get(id);
    if (!row) { bad(where, "not listed in any index file"); continue; }
    if (row.date !== date || c.date !== date) bad(where, `belongs in details/${row.date.slice(0, 4)}/${row.date}.json`);
    if (c.id !== id) bad(where, "record id does not match its key");
    if (!SEVERITIES.includes(c.severity) || severityOf(c.cvss) !== c.severity) bad(where, `severity ${c.severity} does not match score ${c.cvss}`);
    if (c.cvssVector) {
      if (!parseVector(c.cvssVector)) bad(where, "cvssVector is not a complete CVSS:3.x vector");
      else if (Math.abs(baseScore(c.cvssVector) - c.cvss) > 0.05) bad(where, `cvss ${c.cvss} does not match its vector (${baseScore(c.cvssVector)})`);
    }
    if (c.repo != null && !RE.repo.test(c.repo)) bad(where, "repo must be owner/name");
    if (c.branch != null && !RE.ref.test(c.branch)) bad(where, "branch contains unsupported characters");
    for (const k of ["writeup", "pocPath"]) if (c[k] != null && !RE.path.test(c[k])) bad(where, `${k} must be a relative path inside the repository`);
    if (c.pocUrl != null && !/^https:\/\//.test(c.pocUrl)) bad(where, "pocUrl must be an https URL");
    if (c.repo) withRepo.push(c);
  }
}
for (const id of released.keys()) if (!detailed.has(id)) bad("details", `${id} has no details record`);

if (CHECK_REPOS) {
  for (const c of withRepo) {
    const url = `https://raw.githubusercontent.com/${c.repo}/${c.branch || "main"}/${c.writeup || "README.md"}`;
    try {
      const res = await fetch(url, { method: "HEAD" });
      if (!res.ok) problems.push(`${c.id}: writeup not reachable at ${url} (HTTP ${res.status}). Is the repository public?`);
    } catch (err) {
      problems.push(`${c.id}: could not reach ${url} (${err.message})`);
    }
  }
}

warnings.slice(0, 20).forEach((w) => console.warn(`⚠ ${w}`));
if (warnings.length > 20) console.warn(`⚠ … and ${warnings.length - 20} more warnings`);
if (problems.length) {
  problems.slice(0, 60).forEach((p) => console.error(`✖ ${p}`));
  console.error(`\n${problems.length} problem(s)${problems.length > 60 ? " (first 60 shown)" : ""}`);
  process.exit(1);
}
console.log(`✔ ${indexRows.toLocaleString("en-GB")} released and ${embargoIds.size.toLocaleString("en-GB")} embargoed findings valid${CHECK_REPOS ? ", all writeups reachable" : ""}`);
