import { makeUser, defaultUser, User, Box } from "./kinds-lib";

declare function fetchUser(): Promise<User>;
declare function fetchAll(): Promise<User[]>;

class Svc {
  items: User[] = [];
  load(u: User) { return u; }
}

export async function run(svc: Svc, { id, name }: User, ...rest: User[]) {
  const user = await fetchUser();
  const loaded = svc.load(user);
  const [first] = await fetchAll();
  const { name: renamed } = user;
  const cfg = { owner: user, list: [user] };
  const viaMember = svc.items;
  const made = makeUser();
  return loaded.name + renamed + first.name + cfg.owner.name + viaMember.length + made.id + defaultUser.id + id + name + rest.length;
}

const instance = new Svc();
export default instance;

declare const anyVal: any;
export const forced = anyVal as User;
const base = makeUser();
export const trimmed = base.name.trim();

export class Holder {
  private box = new Box<User>(defaultUser);
  get() { return this.box.value(); }
}
