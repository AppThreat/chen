const ALLOWED = ['/home', '/cart'];
export function isSafePath(p) { return ALLOWED.includes(p); }
export function go(url) { location.assign(url); }
