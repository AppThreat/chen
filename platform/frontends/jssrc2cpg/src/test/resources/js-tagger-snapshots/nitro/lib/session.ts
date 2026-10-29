import { getCookie, readBody } from 'h3'
import { readFileSync } from 'fs'

export async function profile(event) {
  const id = getCookie(event, 'session')
  const form = await readBody(event)
  return readFileSync(`/data/${id}/${form.file}`, 'utf8')
}
