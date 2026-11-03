export interface User { id: number; name: string }
export function makeUser(): User { return { id: 1, name: "a" }; }
export const defaultUser: User = { id: 0, name: "d" };
