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

const API_BASE = process.env.PRESEND_API_BASE || 'https://presend.pages.dev/api';
// Identification des requetes : famille de client reconnaissable dans la mesure d'usage de Presend
// (premier mot du User-Agent, jamais d'IP). PRESEND_TEST=1, pose seulement par nos propres workflows
// de test, exclut ces appels de la mesure.
const HEADERS = { 'User-Agent': 'presend-check-action/1 (+https://github.com/presendapp/presend-check-action)' };
if (process.env.PRESEND_TEST === '1') HEADERS['X-Presend-Test'] = '1';
const ECOSYSTEM = (process.env.ECOSYSTEM || 'npm').toLowerCase();
const MANIFEST_PATH = process.env.MANIFEST_PATH || (ECOSYSTEM === 'pypi' ? 'requirements.txt' : 'package.json');
const FAIL_ON_ISSUE = (process.env.FAIL_ON_ISSUE || 'true') !== 'false';
const REQUESTED_CHECKS = (process.env.CHECKS || 'maintainer,vulnerability').split(',').map(s => s.trim());

function extractVersionNumber(spec) {
  const match = (spec || '').match(/(\d+\.\d+(?:\.\d+)?(?:[.\-][A-Za-z0-9]+)*)/);
  return match ? match[1] : null;
}

function readNpmDependencies(path) {
  const pkg = JSON.parse(readFileSync(path, 'utf-8'));
  const deps = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) };
  return Object.entries(deps).map(([name, spec]) => ({
    name,
    version: extractVersionNumber(spec),
  }));
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
    result.push({ name, version: extractVersionNumber(rest) });
  }
  return result;
}

function readDependencies(ecosystem, path) {
  if (!existsSync(path)) {
    throw new Error(`Manifest file not found: ${path}`);
  }
  return ecosystem === 'pypi' ? readPypiDependencies(path) : readNpmDependencies(path);
}

async function checkMaintainer(ecosystem, pkgName) {
  const url = `${API_BASE}/maintainer-change-check?ecosystem=${ecosystem}&package=${encodeURIComponent(pkgName)}`;
  const res = await fetch(url, { headers: HEADERS });
  if (!res.ok) return { pkgName, check: 'maintainer', error: `HTTP ${res.status}` };
  const data = await res.json();
  return { pkgName, check: 'maintainer', suspicious: !!data.suspicious, details: data.flagged_events };
}

async function checkVulnerability(ecosystem, pkgName, version) {
  let url = `${API_BASE}/vulnerability-check?ecosystem=${ecosystem}&package=${encodeURIComponent(pkgName)}`;
  if (version) url += `&version=${encodeURIComponent(version)}`;
  const res = await fetch(url, { headers: HEADERS });
  if (!res.ok) return { pkgName, check: 'vulnerability', error: `HTTP ${res.status}` };
  const data = await res.json();
  const count = (data.vulnerabilities || []).length;
  return { pkgName, check: 'vulnerability', suspicious: count > 0, count, details: data.vulnerabilities, version_checked: version || 'all versions' };
}

export async function run(manifestPath = MANIFEST_PATH, ecosystem = ECOSYSTEM) {
  const deps = readDependencies(ecosystem, manifestPath);
  const results = [];

  const effectiveChecks = REQUESTED_CHECKS.filter(c => c !== 'maintainer' || ecosystem === 'npm');
  const skippedMaintainer = REQUESTED_CHECKS.includes('maintainer') && ecosystem !== 'npm';

  for (const dep of deps) {
    if (effectiveChecks.includes('maintainer')) results.push(await checkMaintainer(ecosystem, dep.name));
    if (effectiveChecks.includes('vulnerability')) results.push(await checkVulnerability(ecosystem, dep.name, dep.version));
  }

  const issues = results.filter(r => r.suspicious);
  const errors = results.filter(r => r.error);
  const noVersionCount = results.filter(r => r.check === 'vulnerability' && r.version_checked === 'all versions').length;

  console.log(`Presend dependency check (${ecosystem}) -- ${deps.length} package(s), ${results.length} check(s) run.`);
  if (skippedMaintainer) {
    console.log('(maintainer-change check skipped: npm only for now)');
  }
  if (noVersionCount > 0) {
    console.log(`(${noVersionCount} package(s) had no parseable version -- checked against full vulnerability history instead of a specific version)`);
  }
  if (issues.length === 0) {
    console.log('✅ No issues found.');
  } else {
    console.log(`⚠️  ${issues.length} issue(s) found:`);
    for (const issue of issues) {
      const versionNote = issue.version_checked ? ` (version checked: ${issue.version_checked})` : '';
      console.log(`  - ${issue.pkgName} [${issue.check}]${versionNote}`, JSON.stringify(issue.details));
    }
  }
  if (errors.length > 0) {
    console.log(`(${errors.length} check(s) could not complete: network/API errors, not counted as issues)`);
  }

  return { deps, results, issues, errors };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  run().then(({ issues }) => {
    if (issues.length > 0 && FAIL_ON_ISSUE) {
      process.exit(1);
    }
    process.exit(0);
  }).catch((e) => {
    console.error('Fatal error:', e.message);
    process.exit(1);
  });
}
