import { makeUser, defaultUser, User } from "./kinds-lib";

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
