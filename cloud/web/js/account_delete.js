// 0.2.23: "Delete account" (devices.html). Pure texts + the name check; devices.js wires them. Server: POST /api/account/delete (app/account_delete.py).
export const KEPT_TEXT = [
  'Erased: your agents and their API keys, mandates, requests and approvals, the closed-data words, push subscriptions, recovery codes, your name and every session. Your passkeys stop working for good.',
  'Kept, on purpose: the witness journal of your account (what the witness decided, with times, amounts and hashes, signed by the witness), the key registry entries and the public keys, and an account number with no name. They are append-only chains that other accounts share and whose heads are stamped in public time-stamps: removing a line would break the proof for everybody and for every evidence pack already issued. They hold no message text and no name.',
  'There is no undo and no way back in: a deleted account cannot be restored, not even by us.',
];

export const nameMatches = (typed, name) => typeof typed === 'string' && typeof name === 'string' && name.trim() !== '' && typed.trim() === name.trim();

export const DELETE_ERRORS = {
  NAME_MISMATCH: 'The name does not match. Type the account name exactly as shown above.',
  TEAM_HAS_MEMBERS: 'Other people are in this account (Team page). Remove them, or ask them to leave, and then delete it.',
  IN_TEAM: 'You sign for another team. Ask that team to replace your key (Team page there) first.',
  NOT_OWN_ACCOUNT: 'Switch to your own account (the menu at the top), then delete it from there.',
  PHONE_PENDING: 'This passkey is still waiting to count as your phone (after a recovery code). Try again when the wait is over.',
};
export function deleteError(e) { return e && e.code && DELETE_ERRORS[e.code] ? DELETE_ERRORS[e.code] : null; }
