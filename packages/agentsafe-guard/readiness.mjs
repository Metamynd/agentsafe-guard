// readiness.mjs — Agent Readiness Reports from the command line and CI.
//
//   npx @metamynd/agentsafe-guard readiness status <reportId> [--hash sha256:…]
//   npx @metamynd/agentsafe-guard readiness gate --programme <id> [--issue] [--min conditional] …
//
// `status` is public: anyone holding a report id can check it is authentic and still valid. `gate` reads (and with
// --issue, issues) the owner's report, so it needs an owner API token with readiness:read (and readiness:issue). The
// token is read ONLY from the METAMYND_TOKEN environment variable, never a flag, so it stays out of shell history and
// process listings. Zero dependencies, like the rest of the guard.

export const DEFAULT_API = 'https://metamynd.ai/api/v1';

/** Deployment statuses, best first. `--min` passes this one and every better one. */
export const STATUS_ORDER = ['ready', 'conditional', 'insufficient-evidence', 'not-ready', 'indicative'];
const RANK = Object.fromEntries(STATUS_ORDER.map((s, i) => [s, i]));

/** Exit codes: 0 passed, 1 the report says no, 2 the check could not run (never read as a pass). */
export const EXIT = { PASS: 0, FAIL: 1, ERROR: 2 };

export class ReadinessError extends Error {}

function apiBase(flags, env) {
  const base = (flags.api || env.AGENTSAFE_API || DEFAULT_API).replace(/\/+$/, '');
  if (!/^https:\/\//.test(base) && !/^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?(\/|$)/.test(base)) {
    // A token sent over plain HTTP to a remote host would be readable on the way.
    throw new ReadinessError(`--api must be https:// (or http://localhost): ${base}`);
  }
  return base;
}

async function call(fetchImpl, url, { token, method = 'GET', body, accept = 'application/json' } = {}) {
  const res = await fetchImpl(url, {
    method,
    headers: {
      accept,
      ...(token ? { authorization: `Bearer ${token}` } : {}),
      ...(body ? { 'content-type': 'application/json' } : {}),
    },
    ...(body ? { body: JSON.stringify(body) } : {}),
  });
  if (accept !== 'application/json') {
    if (!res.ok) throw new ReadinessError(`${method} ${url} answered ${res.status}`);
    return res.text();
  }
  const json = await res.json().catch(() => null);
  if (!res.ok) {
    const code = json?.data?.code ? ` (${json.data.code})` : '';
    const hint =
      res.status === 401 ? ' — check METAMYND_TOKEN is set, unexpired, not revoked and has the needed scope' : res.status === 404 ? ' — not found, or not yours' : '';
    throw new ReadinessError(`${method} ${new URL(url).pathname} answered ${res.status}${code}: ${json?.message ?? 'no message'}${hint}`);
  }
  return json?.data;
}

/** `readiness status <reportId>`: authentic and current, or not. Public: no token. */
export async function readinessStatus({ reportId, hash, flags = {}, env = process.env, fetchImpl = fetch }) {
  if (!reportId) throw new ReadinessError('give the report id: readiness status <reportId>');
  const base = apiBase(flags, env);
  const q = hash ? `?hash=${encodeURIComponent(hash)}` : '';
  const s = await call(fetchImpl, `${base}/sandbox/readiness-reports/${encodeURIComponent(reportId)}/status${q}`);
  const reasons = (s.reasons ?? []).map((r) => r.description || r.code);
  const ok = s.authentic === true && s.status === 'current' && s.hashMatches !== false;
  return {
    ok,
    reportId: s.reportId,
    authentic: s.authentic,
    validity: s.status,
    hashMatches: s.hashMatches ?? null,
    reasons,
    reassessBy: s.reassessBy,
    supersededBy: s.supersededBy ?? null,
    lines: [
      `${ok ? 'PASS' : 'FAIL'}  report ${s.reportId}`,
      `  authentic: ${s.authentic ? 'yes' : 'NO'}${s.hashMatches === false ? ' (your copy does not match the issued report)' : ''}`,
      `  validity:  ${s.status}${reasons.length ? ` — ${reasons.join(' ')}` : ''}`,
      ...(s.supersededBy ? [`  superseded by ${s.supersededBy}`] : []),
      `  reassess by ${s.reassessBy}`,
    ],
  };
}

/**
 * `readiness gate --programme <id>`: the latest issued report (or a fresh one with --issue) must be at least `--min`
 * and still current. A build that cannot tell exits 2, never 0.
 */
export async function readinessGate({ flags = {}, env = process.env, fetchImpl = fetch, writeFile }) {
  const token = env.METAMYND_TOKEN;
  if (!token) throw new ReadinessError('set METAMYND_TOKEN to an owner API token (Settings → API tokens) with readiness:read');
  const programme = flags.programme;
  if (!programme) throw new ReadinessError('give the programme: --programme <id>');
  const min = flags.min || 'ready';
  if (!(min in RANK) || min === 'indicative') throw new ReadinessError(`--min must be one of ready, conditional, insufficient-evidence, not-ready`);
  const edition = flags.edition === 'full' ? 'full' : 'lite';
  const base = apiBase(flags, env);
  const prog = encodeURIComponent(programme);

  let reportId;
  if (flags.issue) {
    const issued = await call(fetchImpl, `${base}/sandbox/programmes/${prog}/readiness-reports`, {
      token,
      method: 'POST',
      body: flags.target ? { target: flags.target } : {},
    });
    reportId = issued.reportId;
  } else {
    const list = await call(fetchImpl, `${base}/sandbox/programmes/${prog}/readiness-reports`, { token });
    const pick = (list ?? []).find((r) => !flags.target || r.target === flags.target);
    if (!pick) throw new ReadinessError(`no issued report for this programme${flags.target ? ` and target ${flags.target}` : ''}; run with --issue to issue one`);
    reportId = pick.reportId;
  }

  const report = await call(fetchImpl, `${base}/sandbox/readiness-reports/${encodeURIComponent(reportId)}?edition=${edition}`, { token });
  const status = report.status?.status;
  const validity = report.validity?.status;
  const statusOk = status in RANK && RANK[status] <= RANK[min];
  const validOk = flags['allow-stale'] ? validity !== 'revoked' : validity === 'current';
  const ok = statusOk && validOk;

  if (flags.out) {
    if (!writeFile) throw new ReadinessError('--out is not available here');
    const html = await call(fetchImpl, `${base}/sandbox/readiness-reports/${encodeURIComponent(reportId)}?edition=${edition}&format=html`, { token, accept: 'text/html' });
    await writeFile(flags.out, html);
  }

  const failedGates = (report.gates ?? []).filter((g) => g.result !== 'pass').map((g) => `${g.id} ${g.result}`);
  const triggers = (report.validity?.triggers ?? []).join(', ');
  return {
    ok,
    reportId,
    status,
    grade: report.risk?.grade,
    validity,
    hash: report.evidence?.reportHash ?? report.verification?.reportHash ?? null,
    lines: [
      `${ok ? 'PASS' : 'FAIL'}  ${report.targetLabel ?? 'readiness'}: ${status} (needs ${min} or better), grade ${report.risk?.grade} (index ${report.risk?.index}, band ${report.risk?.band?.low}–${report.risk?.band?.high})`,
      `  report ${reportId}${flags.issue ? ' (issued now)' : ''}, validity ${validity}${triggers ? ` — ${triggers}` : ''}`,
      ...(failedGates.length ? [`  gates not passing: ${failedGates.join(', ')}`] : []),
      ...(!statusOk ? [`  ${(report.status?.reasons ?? []).join(' ')}`] : []),
      ...(flags.out ? [`  report written to ${flags.out}`] : []),
      `  grade and status are separate: the status is decided by gates and evidence first; the grade is an ordinal, uncalibrated index.`,
    ],
  };
}
