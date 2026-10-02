#!/usr/bin/env node
// Lit package.json (npm) ou requirements.txt (PyPI), vérifie chaque dépendance
// contre l'API Presend, résume les résultats, et sort avec un code d'erreur
// si quelque chose de suspect est trouvé (sauf si fail-on-issue=false).
//
// maintainer-change-check est npm uniquement pour l'instant -- ignoré
// silencieusement en mode pypi plutôt que de générer des erreurs inutiles.
//
// Passe la version épinglée à vulnerability-check quand elle est connue,
// pour qu'OSV.dev filtre lui-même aux CVE réellement actives sur cette
// version précise, plutôt que de renvoyer tout l'historique du paquet.

import { readFileSync, existsSync } from 'fs';
import { dirname, join } from 'path';

const API_BASE = process.env.PRESEND_API_BASE || 'https://presend.pages.dev/api';
// Identification des requetes : famille de client reconnaissable dans la mesure d'usage de Presend
// (premier mot du User-Agent, jamais d'IP). PRESEND_TEST=1, pose seulement par nos propres workflows
// de test, exclut ces appels de la mesure.
const HEADERS = { 'User-Agent': 'presend-check-action/1 (+https://github.com/presendapp/presend-check-action)' };
if (process.env.PRESEND_TEST === '1') HEADERS['X-Presend-Test'] = '1';
const ECOSYSTEM = (process.env.ECOSYSTEM || 'npm').toLowerCase();
const MANIFEST_PATH = process.env.MANIFEST_PATH || (ECOSYSTEM === 'pypi' ? 'requirements.txt' : 'package.json');
const FAIL_ON_ISSUE = (process.env.FAIL_ON_ISSUE || 'true') !== 'false';
const REQUESTED_CHECKS = (process.env.CHECKS || 'typosquat,maintainer,vulnerability').split(',').map(s => s.trim()).filter(Boolean);
const FAIL_ON_INCOMPLETE = (process.env.FAIL_ON_INCOMPLETE || 'false') === 'true';
const TYPOSQUAT_BATCH = 100;   // max names per POST /api/typosquat-check (one rate-limit unit)
const MAINTAINER_BATCH = 20;   // max names per POST /api/maintainer-change-check
const OSV_BATCH = 1000;        // max queries per OSV.dev querybatch
const OSV_ECOSYSTEM = { npm: 'npm', pypi: 'PyPI' };

function extractVersionNumber(spec) {
  const match = (spec || '').match(/(\d+\.\d+(?:\.\d+)?(?:[.\-][A-Za-z0-9]+)*)/);
  return match ? match[1] : null;
}

function readNpmDependencies(path) {
  const pkg = JSON.parse(readFileSync(path, 'utf-8'));
  const deps = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) };
  // Installed version from package-lock.json when it sits next to the manifest; otherwise the version
  // written in package.json, labelled when it comes from a range (its lower bound, not what is installed).
  let lock = null;
  try { const lp = join(dirname(path), 'package-lock.json'); if (existsSync(lp)) lock = JSON.parse(readFileSync(lp, 'utf-8')); } catch (e) { lock = null; }
  return Object.entries(deps).map(([name, spec]) => {
    const entry = lock && lock.packages && lock.packages['node_modules/' + name];
    if (entry && entry.version) return { name, version: entry.version, versionSource: 'from package-lock.json' };
    const version = extractVersionNumber(spec);
    const exact = /^\d/.test(String(spec).trim());
    return { name, version, versionSource: version && !exact ? `lower bound of "${spec}"` : null };
  });
}

function readPypiDependencies(path) {
  const lines = readFileSync(path, 'utf-8').split('\n');
  const seen = new Set();
  const result = [];
  for (let line of lines) {
    line = line.trim();
    if (!line || line.startsWith('#') || line.startsWith('-')) continue;
    const nameMatch = line.match(/^([A-Za-z0-9][A-Za-z0-9._-]*)/);
    if (!nameMatch) continue;
    const name = nameMatch[1];
    if (seen.has(name)) continue;
    seen.add(name);
    const rest = line.slice(name.length);
    const version = extractVersionNumber(rest);
    const exact = rest.trim().startsWith('==');
    result.push({ name, version, versionSource: version && !exact ? `lower bound of "${rest.trim()}"` : null });
  }
  return result;
}

function readDependencies(ecosystem, path) {
  if (!existsSync(path)) {
    throw new Error(`Manifest file not found: ${path}`);
  }
  return ecosystem === 'pypi' ? readPypiDependencies(path) : readNpmDependencies(path);
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
function chunks(arr, n) { const out = []; for (let i = 0; i < arr.length; i += n) out.push(arr.slice(i, i + n)); return out; }

// POST with JSON; on HTTP 429 (per-minute limit) wait 30 s and retry, at most twice.
async function postJson(url, body, headers) {
  for (let attempt = 0; attempt < 3; attempt++) {
    let res;
    try {
      res = await fetch(url, { method: 'POST', headers: { ...headers, 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    } catch (e) {
      if (attempt === 2) return { error: 'network error' };
      await sleep(3000); continue;
    }
    if (res.status === 429 && attempt < 2) { await sleep(30000); continue; }
    if (!res.ok) return { error: res.status === 429 ? 'rate limit reached (HTTP 429)' : `HTTP ${res.status}` };
    try { return { data: await res.json() }; } catch (e) { return { error: 'invalid response' }; }
  }
}

// Batch call to a Presend endpoint; results are matched by position (names may be normalised).
async function presendBatch(check, endpoint, batchSize, ecosystem, deps, toResult) {
  const out = [];
  for (const group of chunks(deps, batchSize)) {
    const r = await postJson(`${API_BASE}/${endpoint}`, { ecosystem, packages: group.map((d) => d.name) }, HEADERS);
    const list = r.data && Array.isArray(r.data.results) ? r.data.results : null;
    if (r.error || !list || list.length !== group.length) {
      const why = r.error || 'unexpected response';
      for (const d of group) out.push({ pkgName: d.name, check, error: why });
      continue;
    }
    group.forEach((d, i) => out.push(list[i].error ? { pkgName: d.name, check, error: String(list[i].error) } : { pkgName: d.name, check, ...toResult(list[i]) }));
  }
  return out;
}

const checkTyposquats = (ecosystem, deps) => presendBatch('typosquat', 'typosquat-check', TYPOSQUAT_BATCH, ecosystem, deps,
  (x) => ({ suspicious: !!x.suspicious, details: (x.similar_to || []).map((s) => `close to ${s.name} (distance ${s.distance})`) }));
const checkMaintainers = (ecosystem, deps) => presendBatch('maintainer', 'maintainer-change-check', MAINTAINER_BATCH, ecosystem, deps,
  (x) => ({ suspicious: !!x.suspicious, details: x.flagged_events }));

// Known vulnerabilities of the version in the manifest, straight from OSV.dev (no key, batch API).
async function checkVulnerabilities(ecosystem, deps) {
  const out = [];
  for (const d of deps.filter((d) => !d.version)) out.push({ pkgName: d.name, check: 'vulnerability', error: 'no version in the manifest' });
  for (const group of chunks(deps.filter((d) => d.version), OSV_BATCH)) {
    const r = await postJson('https://api.osv.dev/v1/querybatch',
      { queries: group.map((d) => ({ package: { name: d.name, ecosystem: OSV_ECOSYSTEM[ecosystem] }, version: d.version })) },
      { 'User-Agent': HEADERS['User-Agent'] });
    const list = r.data && Array.isArray(r.data.results) ? r.data.results : null;
    if (r.error || !list || list.length !== group.length) {
      for (const d of group) out.push({ pkgName: d.name, check: 'vulnerability', error: 'OSV.dev ' + (r.error || 'unexpected response') });
      continue;
    }
    group.forEach((d, i) => {
      const ids = (list[i].vulns || []).map((v) => v.id);
      const more = list[i].next_page_token ? ['(more on osv.dev)'] : [];
      out.push({ pkgName: d.name, check: 'vulnerability', version_checked: d.version, version_note: d.versionSource, suspicious: ids.length > 0,
        details: ids.map((id) => `https://osv.dev/vulnerability/${id}`).concat(more) });
    });
  }
  return out;
}

export async function run(manifestPath = MANIFEST_PATH, ecosystem = ECOSYSTEM) {
  const deps = readDependencies(ecosystem, manifestPath);
  const skippedMaintainer = REQUESTED_CHECKS.includes('maintainer') && ecosystem !== 'npm';
  const results = [];
  if (deps.length > 0) {
    if (REQUESTED_CHECKS.includes('typosquat')) results.push(...await checkTyposquats(ecosystem, deps));
    if (REQUESTED_CHECKS.includes('maintainer') && ecosystem === 'npm') results.push(...await checkMaintainers(ecosystem, deps));
    if (REQUESTED_CHECKS.includes('vulnerability')) results.push(...await checkVulnerabilities(ecosystem, deps));
  }
  const issues = results.filter((r) => r.suspicious);
  const errors = results.filter((r) => r.error);
  const done = results.length - errors.length;

  console.log(`Presend dependency check (${ecosystem}): ${deps.length} package(s), ${done} of ${results.length} check(s) completed.`);
  if (skippedMaintainer) console.log('(maintainer-change check skipped: npm only)');
  if (errors.length > 0) {
    const reasons = {};
    for (const e of errors) { const k = `${e.check}: ${e.error}`; reasons[k] = (reasons[k] || 0) + 1; }
    const why = Object.entries(reasons).map(([k, n]) => `${n} x ${k}`).join('; ');
    console.log(`::warning title=Presend check incomplete::${errors.length} of ${results.length} checks could not run (${why}). The result covers only the completed checks.`);
    console.log(`RESULT INCOMPLETE: ${errors.length} check(s) could not run (${why}).`);
  }
  if (issues.length > 0) {
    console.log(`⚠️  ${issues.length} issue(s) found:`);
    for (const issue of issues) {
      const v = issue.version_checked ? ` (version ${issue.version_checked}${issue.version_note ? ', ' + issue.version_note : ''})` : '';
      console.log(`  - ${issue.pkgName} [${issue.check}]${v}: ${JSON.stringify(issue.details)}`);
    }
  } else if (errors.length === 0) {
    console.log(`✅ No issues found in ${results.length} check(s).`);
  } else {
    console.log(`No issues found in the ${done} completed check(s); ${errors.length} could not run (see above).`);
  }
  return { deps, results, issues, errors };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  run().then(({ issues, errors }) => {
    if (issues.length > 0 && FAIL_ON_ISSUE) process.exit(1);
    if (errors.length > 0 && FAIL_ON_INCOMPLETE) process.exit(1);
    process.exit(0);
  }).catch((e) => {
    console.error('Fatal error:', e.message);
    process.exit(1);
  });
}
