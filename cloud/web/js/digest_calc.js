// A100 = 100 H / W, F100 = 100 F / W (ARHITEKTURA-0.2 3.6); the server figures win when present, one decimal.
export function digestFigures(d) {
  const W = d.W || 0, H = d.H || 0, F = d.F || 0;
  const pct = (x) => (W ? Math.round((1000 * x) / W) / 10 : 0);
  return { W, H, F, A100: typeof d.A100 === 'number' ? d.A100 : pct(H), F100: typeof d.F100 === 'number' ? d.F100 : pct(F) };
}
