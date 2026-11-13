// Thin wrappers over navigator.credentials. Binary <-> base64url (no padding).
export function b64uEnc(bytes) {
  let s = '';
  for (const x of bytes) s += String.fromCharCode(x);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
export function b64uDec(str) {
  const s = str.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((str.length + 3) % 4);
  const bin = atob(s);
  const o = new Uint8Array(bin.length);
  for (let i = 0; i < o.length; i++) o[i] = bin.charCodeAt(i);
  return o;
}

export function supported() {
  return !!(window.PublicKeyCredential && navigator.credentials);
}

// options: PublicKeyCredentialCreationOptionsJSON from the server -> RegistrationResponseJSON
export async function createCredential(o) {
  const pk = {
    ...o,
    challenge: b64uDec(o.challenge),
    user: { ...o.user, id: b64uDec(o.user.id) },
    excludeCredentials: (o.excludeCredentials || []).map((c) => ({ ...c, id: b64uDec(c.id) })),
  };
  const c = await navigator.credentials.create({ publicKey: pk });
  if (!c) throw new Error('No credential returned');
  const r = c.response;
  return {
    id: c.id, rawId: b64uEnc(new Uint8Array(c.rawId)), type: c.type,
    response: {
      clientDataJSON: b64uEnc(new Uint8Array(r.clientDataJSON)),
      attestationObject: b64uEnc(new Uint8Array(r.attestationObject)),
      transports: r.getTransports ? r.getTransports() : [],
    },
    clientExtensionResults: c.getClientExtensionResults ? c.getClientExtensionResults() : {},
  };
}

// options: RequestOptionsJSON -> AuthenticationResponseJSON (for login)
export async function getCredential(o) {
  const pk = { ...o, challenge: b64uDec(o.challenge), allowCredentials: (o.allowCredentials || []).map((c) => ({ ...c, id: b64uDec(c.id) })) };
  const c = await navigator.credentials.get({ publicKey: pk });
  if (!c) throw new Error('No credential returned');
  const r = c.response;
  return {
    id: c.id, rawId: b64uEnc(new Uint8Array(c.rawId)), type: c.type,
    response: {
      clientDataJSON: b64uEnc(new Uint8Array(r.clientDataJSON)),
      authenticatorData: b64uEnc(new Uint8Array(r.authenticatorData)),
      signature: b64uEnc(new Uint8Array(r.signature)),
      userHandle: r.userHandle ? b64uEnc(new Uint8Array(r.userHandle)) : null,
    },
    clientExtensionResults: c.getClientExtensionResults ? c.getClientExtensionResults() : {},
  };
}

// Raw assertion over an arbitrary 32-byte challenge, for signing (profile 3.3). credentialIds: one base64url id or a list
// (0.2.2: any of the person's active passkeys may sign; rawId says which one did).
export async function assertOver(challengeBytes, rpId, credentialIds) {
  const ids = Array.isArray(credentialIds) ? credentialIds : [credentialIds];
  const c = await navigator.credentials.get({ publicKey: {
    challenge: challengeBytes, rpId, userVerification: 'required', timeout: 300000,
    allowCredentials: ids.map((id) => ({ type: 'public-key', id: b64uDec(id) })),
  } });
  if (!c) throw new Error('No credential returned');
  return {
    authData: new Uint8Array(c.response.authenticatorData),
    clientDataJSON: new Uint8Array(c.response.clientDataJSON),
    signature: new Uint8Array(c.response.signature),
    rawId: b64uEnc(new Uint8Array(c.rawId)),
  };
}

// 0.2.22 (N3): the server refused a signature because the passkey's counter did not grow (409 SIGN_COUNT_REGRESSION): it may be a COPY of the key.
export const CLONE_TEXT = 'The server refused this signature: the signature counter of your passkey did not grow. That can mean an old signature was replayed, or that a copy of your passkey exists. Nothing was approved. Check your passkeys on the Devices page; if you do not recognise this, remove the passkey there.';
export function cloneNote(el, e) {   // adds the link to devices.html after the text (plain DOM, no HTML from the server)
  if (!(e && e.code === 'SIGN_COUNT_REGRESSION') || !el) return false;
  const a = document.createElement('a'); a.href = 'devices.html'; a.textContent = 'Open Devices';
  el.append(' ', a); return true;
}
export const isClone = (e) => !!(e && e.code === 'SIGN_COUNT_REGRESSION');

export const NO_PASSKEY_TEXT = 'This browser does not support passkeys. Open this page on your phone or a browser with passkeys (Safari, Chrome, Edge).';

// 0.2.75 (N21): a passkey step that took longer than the server keeps it (5 minutes) comes back as FLOW_UNKNOWN; said in words, with what to do
export const FLOW_EXPIRED_TEXT = 'The passkey step took too long and expired, so this attempt does not count. Press the button again: it starts over.';
export function explainError(e) {
  if (isClone(e)) return CLONE_TEXT;
  if (e && e.code === 'FLOW_UNKNOWN') return FLOW_EXPIRED_TEXT;
  // 0.2.48: a server answer has a STRING code; a DOMException has a legacy NUMBER code (NotSupportedError = 9, InvalidStateError = 11 ...) that must never be shown
  if (e && typeof e.code === 'string' && e.code) return (e.code + (e.detail ? ': ' + e.detail : ''));   // 0.2.22: a server answer is not a device error (its text may contain "passkey")
  if (e && e.name === 'NotAllowedError') return 'The passkey prompt was cancelled or timed out. Try again. If the system window said it could not create or use a passkey, check that a screen lock (PIN, pattern, fingerprint or face) is set on this device and that you are signed in to the account that stores passkeys (Google account on Android, Apple ID on iPhone).';
  if (e && e.name === 'InvalidStateError') return 'This device already has a passkey for this site. Use "Sign in" instead.';
  if (e && e.name === 'SecurityError') return 'The browser refused: the page origin does not match the server relying-party ID.';
  // 0.2.19: the system refused to create / use the passkey (Android Credential Manager: "unknown error ... credential manager" =
  // no screen lock, or no signed-in Google / platform account, or the system dialog was dismissed) -- say what to do
  const m = String((e && (e.message || e.detail)) || '');
  if (e && (e.name === 'UnknownError' || e.name === 'NotSupportedError' || e.name === 'ConstraintError' || e.name === 'AbortError' || e.name === 'DataError'
    || /credential manager|passkey|screen lock|unknown error/i.test(m)))
    return 'Your device could not create or use the passkey. Check that: (1) a screen lock (PIN, pattern, fingerprint or face) is set on this device; (2) you are signed in to the device account that stores passkeys (Google account on Android, Apple ID on iPhone); (3) you did not dismiss the system dialog. Then try again, or use another device or a security key. (' + (e.name || 'Error') + ')';
  return (e && (e.detail || e.message)) || String(e);
}
