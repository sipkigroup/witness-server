// 0.2.47: Settings -> Export tokens (settings.html). Pure texts and checks; settings.js wires them. Server: app/export_tokens.py,
// POST /api/export-tokens (owner + fresh passkey), GET (list), DELETE /api/export-tokens/{id} (revoke).
export const TTL_MIN = 1, TTL_MAX = 168, TTL_DEFAULT = 24;

// "24" -> 24; anything that is not a whole number from 1 to 168 -> null (the server says BAD_TTL too)
export function ttlHours(s) {
  const t = String(s == null ? '' : s).trim();
  if (!/^\d{1,3}$/.test(t)) return null;
  const n = Number(t);
  return n >= TTL_MIN && n <= TTL_MAX ? n : null;
}

export function issueBody(agentId, ttlText, label) {
  const ttl = ttlHours(ttlText);
  if (typeof agentId !== 'string' || !agentId || ttl === null) return null;
  const b = { agent_id: agentId, ttl_hours: ttl };
  const l = String(label || '').trim().slice(0, 80);
  if (l) b.label = l;
  return b;
}

// the tokens a person still has to care about: live ones, newest first (the server sends revoked and expired ones too)
export const liveTokens = (rows) => (Array.isArray(rows) ? rows : []).filter((t) => t && t.live).sort((a, b) => (b.created_at || 0) - (a.created_at || 0));

export function leftText(exp, now = Math.floor(Date.now() / 1000)) {
  const s = exp - now;
  if (!(s > 0)) return 'expired';
  const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60);
  return (h ? h + ' h ' : '') + m + ' min left';
}

export function usesText(t) {
  return t.uses ? t.uses + (t.uses === 1 ? ' export' : ' exports') : 'not used yet';
}

// shown once, under the token: how the CI job uses it (the same headers as server/app/api_agent.py GET /v1/export)
export function useExample(token, origin) {
  return 'curl -fsS ' + (origin || 'https://<witness>') + '/v1/export \\\n  -H "Authorization: Bearer $DEUS_WITNESS_KEY" \\\n  -H "X-DW-Export-Token: ' + token + '" -o evidence-pack.zip';
}

export const ONCE_TEXT = 'Shown once: copy it now into your CI secrets (for example DEUS_WITNESS_EXPORT_TOKEN). We keep only its hash, so it cannot be shown again; if it is lost, revoke it and issue a new one.';
export const SCOPE_TEXT = [
  'It opens one thing: GET /v1/export, the evidence pack of this account (the whole hash-chained journal, every agent). No actions, no approvals, no settings.',
  'It works only together with the chosen agent\'s API key: a token found in a log is useless alone. Freezing or removing the agent ends it.',
  'Valid 1 to 168 hours, at most 10 live per account, 6 exports an hour each. Revoke ends it at once.',
];

export const XT_ERRORS = {
  QUOTA: '10 export tokens are live already. Revoke one below, then issue a new one.',
  BAD_TTL: 'Valid for: a whole number of hours from 1 to 168.',
  NOT_FOUND: 'That agent or token is gone (removed elsewhere). Reload the page.',
  FORBIDDEN: 'Only an owner of this account issues and revokes export tokens.',
  NOT_MEMBER: 'Only an owner of this account issues and revokes export tokens.',
};
export function xtError(e) { return e && e.code && XT_ERRORS[e.code] ? XT_ERRORS[e.code] : null; }
