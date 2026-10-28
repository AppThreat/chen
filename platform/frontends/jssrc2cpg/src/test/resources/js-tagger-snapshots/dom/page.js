const SAFE = { a: 1, b: 2 };
function isKnown(k) { return Object.hasOwn(SAFE, k); }
class Widget {
  constructor() { this.label = location.hash; }
  paint(el) { el.innerHTML = this.label; }
}
export function boot() {
  const w = new Widget();
  const key = location.search.slice(1);
  if (isKnown(key)) document.write(key);
  document.body.innerHTML = w.label;
  window.open(new URLSearchParams(location.search).get('next'));
  fetch('/api?q=' + key).then((r) => r.json()).then((d) => { document.title = d.title; });
}
