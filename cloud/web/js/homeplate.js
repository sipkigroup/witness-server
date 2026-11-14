// r0283 (third blind evaluation #26, decision 4): on iPhone / iPad in a browser tab (not the app added to the Home Screen) iOS never delivers a
// web push: the person would get NO question from the agent at all, and the page used to say it in the middle of the dashboard. This plate is
// the first thing on the dashboard and on the first screen of the quick start, only there (an iOS tab), nowhere else.
import { envOf, iosInfo } from './push.js';

export const HOME_PLATE = 'On this iPhone your agent\'s questions reach you only in the Witness app on the Home Screen, never in a Safari tab. '
  + 'Tap Share → Add to Home Screen, then open Witness from its icon.';

// -> true when the plate is needed: iOS, not the Home Screen app
export function needsHomePlate(env) {
  return !!env && iosInfo(env.ua || '', env.platform || '', env.maxTouchPoints || 0).ios && !env.standalone;
}

export function mountHomePlate(win, el) {
  if (!el || !win) return false;
  const on = needsHomePlate(envOf(win));
  el.textContent = on ? HOME_PLATE : '';
  el.hidden = !on;
  return on;
}

if (typeof document !== 'undefined' && document.getElementById('homeplate')) mountHomePlate(window, document.getElementById('homeplate'));
