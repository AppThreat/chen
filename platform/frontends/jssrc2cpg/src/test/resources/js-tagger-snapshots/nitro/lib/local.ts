function getQuery(url) {
  return new URL(url).searchParams
}

export function page(url) {
  return getQuery(url).get('page')
}
