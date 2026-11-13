// 0.2.27: what the node 2 page shows, from GET /v1/node2, /v1/node2/keys, /v1/node2/alarms.
// pure functions (node tests: test/v0227.test.mjs); the page is js/node2.js
const fmtTime = (t) => (t ? new Date(t * 1000).toISOString().replace('T', ' ').slice(0, 19) + ' UTC' : '-');

export const OFF_TEXT = 'Node 2 is not running on this server yet. Nothing on this page is a claim until it does.';

// rows of the "Last co-signature" list
export function latestRows(st) {
  if (!st || !st.latest) return [['status', 'no co-signature yet']];
  const l = st.latest;
  return [['co-signature', 'n = ' + l.n + (l.linked ? ' (first after a restart: linked to the previous key)' : '')],
    ['batch', l.bid], ['batch time', fmtTime(l.batch_t)], ['checkpoints inspected', String(l.cps)], ['journals known to node 2', String(l.ledgers)],
    ['alarms counted so far', String(l.alarms)], ['signed by K2', l.pub_hex], ['genesis (SHA-256 of co-signature 1)', st.genesis_hex || '-']];
}

// one key: facts of its report and the problems the offline check found
export function keyView(k) {
  const f = k.facts || {};
  return {
    title: 'K2 ' + String(k.kid_hex || '').slice(0, 16) + '... started ' + fmtTime(k.t),
    rows: [['public key', k.pub_hex], ['platform', k.platform], ['report version', String(f.version)], ['debug', f.debug ? 'ON (proves nothing)' : 'off'],
      ['VMPL', String(f.vmpl)], ['measurement', f.measurement], ['host_data (policy hash)', f.host_data], ['policy SHA-256 (text below)', f.policy_sha256],
      ['reported TCB', f.reported_tcb], ['chip id', f.chip_id], ['AMD signature', f.amd ? 'valid, root ' + f.amd : 'not verified']],
    verdict: (k.problems || []).length ? 'NOT independent: ' + k.problems.join('; ') : 'bound to an AMD-signed report; compare the policy hash with your build',
    bad: (k.problems || []).length > 0,
    policy: k.policy_text || '',
  };
}

export function alarmRows(list) {
  return (list || []).map((a) => [a.alarm, 'batch ' + a.bid + ', journal ' + String(a.ledger_hex || '').slice(0, 16) + '..., received ' + fmtTime(a.t)]);
}

// the "test stage" banner stays until there is a key whose offline check found no problem at all
export const stageHidden = (keys) => (keys || []).length > 0 && keys.every((k) => !(k.problems || []).length);
