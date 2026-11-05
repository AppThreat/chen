import { v4 as uuidv4 } from "uuid";

function logged(target: any, key: string): any {
  return target[key];
}

export class Session {
  @logged accessor id: string = uuidv4();
  @logged static accessor limit: number = 42;
  accessor plain: number = 7;

  describe(): string {
    return this.id;
  }
}
