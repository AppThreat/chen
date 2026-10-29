import { goto } from '$app/navigation';
import { page } from '$app/stores';

export function go(u) {
  goto(u);
}
export const section = $page.url.searchParams.get('section');
export function viaStore() {
  return page.url.hash;
}
