import { execSync } from 'child_process'

export default defineEventHandler(async (event) => {
  const { name } = getQuery(event)
  const body = await readBody(event)
  return execSync(`id ${name} ${body.flag}`).toString()
})
