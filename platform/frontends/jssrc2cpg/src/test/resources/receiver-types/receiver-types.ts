import { signal } from "@angular/core";
import { Observable, Subscription } from "rxjs";

export class Feed {
  items$!: Observable<string[]>;
  get(id: string): Observable<string> {
    return this.items$ as unknown as Observable<string>;
  }
}

export class Comp {
  isSubmitting = signal(false);
  private sub: Subscription | null = null;

  constructor(private readonly feed: Feed) {}

  run(): void {
    this.isSubmitting.set(true);
    this.feed.get("a").pipe();
    this.feed.items$!.subscribe();
    this.sub?.unsubscribe();
  }

  reset(): void {
    const isSubmitting = 0;
    this.isSubmitting.set(isSubmitting > 0);
  }

  use(f: Feed): void {
    f.get("b");
  }
}
