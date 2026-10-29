import { json, redirect } from '@sveltejs/kit';
import { page } from '$app/state';
import { page as legacy } from '$app/stores';

export async function GET({ url, request }) {
  const q = url.searchParams.get('q');
  const next = page.url.searchParams.get('next');
  const old = legacy.url.searchParams.get('old');
  if (q) return json({ q });
  redirect(302, next + old);
}
