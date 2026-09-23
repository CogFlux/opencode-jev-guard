// Scores bench/cases.jsonl with the real Jev API through the plugin, and
// compares decision rules. Needs TYPESAFE_API_KEY or ~/.secrets/typesafe.
// Run with: node bench/run.ts [--save bench/scores.json]
import { readFileSync, writeFileSync } from "node:fs"
import { fileURLToPath } from "node:url"
import plugin from "../jev-guard.ts"

const here = (p: string) => fileURLToPath(new URL(p, import.meta.url))
const cases = readFileSync(here("./cases.jsonl"), "utf8").trim().split("\n").map((l) => JSON.parse(l))
const project = here("../test/fixtures/farhand-project")

let last: any
const realFetch = globalThis.fetch
globalThis.fetch = (async (url: any, init: any) => {
  const res = await realFetch(url, init)
  last = await res.clone().json().catch(() => undefined)
  return res
}) as typeof fetch

const hooks: Record<string, any> = {}
await plugin.setup({
  options: { autoAllow: true },
  location: { directory: project, project: { directory: project } },
  storage: { get: async () => undefined, set: async () => {} },
  tool: { hook: async (n: string, f: any) => (hooks[`tool.${n}`] = f) },
  permission: { hook: async (n: string, f: any) => (hooks[`permission.${n}`] = f) },
  command: { transform: async () => {} },
  session: {},
})

const rows: any[] = []
let i = 0
for (const c of cases) {
  const id = `bench_${++i}`
  await hooks["tool.execute.before"]({ tool: c.tool, id, input: { command: c.command } })
  const event: any = { action: c.tool, resources: [c.command], source: { type: "tool", id }, effect: "ask" }
  last = undefined
  await hooks["permission.evaluate"](event)
  const a = last?.answers ?? {}
  rows.push({
    ...c,
    pRun: a.verdict?.probabilities?.run,
    confidence: a.verdict?.confidence,
    risks: Object.fromEntries(Object.entries(a).filter(([k]) => k !== "verdict").map(([k, v]: any) => [k, v.noul])),
    plugin: event.effect === "allow" ? "run" : "ask",
  })
}

const save = process.argv.indexOf("--save")
if (save > 0) writeFileSync(process.argv[save + 1]!, JSON.stringify(rows, null, 2))

for (const r of rows) {
  const top = Object.entries(r.risks as Record<string, number>).sort((x, y) => y[1] - x[1])[0] ?? ["-", 0]
  const mark = r.plugin === r.expect ? "  " : "✗ "
  console.log(`${mark}${r.expect.padEnd(3)} got ${r.plugin.padEnd(3)} p(run)=${(r.pRun ?? 0).toFixed(2)} top=${top[0]}:${Number(top[1]).toFixed(2)}  ${r.command.slice(0, 70)}`)
}
const wrong = rows.filter((r) => r.plugin !== r.expect)
console.log(`\n${rows.length - wrong.length}/${rows.length} as expected; false asks ${wrong.filter((r) => r.expect === "run").length}, missed asks ${wrong.filter((r) => r.expect === "ask").length}`)
