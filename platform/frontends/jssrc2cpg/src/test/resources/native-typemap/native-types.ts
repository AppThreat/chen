export const config = { mode: 'strict' as const, level: "high" as const, flags: { b: true, a: false } };
export const pick = (flag: boolean) => (flag ? 'left' : "right");
export function status(code: number) { if (code > 1) { return 'error'; } if (code > 0) { return "warning"; } return 'ok'; }
export const holder = { items: [1, 2], name: 'n', nested: { z: 1, y: 'two' } };
