// Drives the plugin through a fake OpenCode 2 context and a fake Jev API.
// Run with: node --test test/

import assert from "node:assert/strict"
import { beforeEach, test } from "node:test"
import { mkdirSync, rmSync, utimesSync, writeFileSync } from "node:fs"
import { join } from "node:path"
import { fileURLToPath } from "node:url"
import plugin from "../jev-guard.ts"

type Hook = (event: any) => unknown

interface Fake {
  hooks: Record<string, Hook>
  command: any
  storage: Map<string, unknown>
  synthetic: any[]
  requests: any[]
}

const PROJECT = "/Users/me/proj"

function answers(verdict: "run" | "confirm", risks: Record<string, number> = {}, confidence = 0.95) {
  const base = { host_litter: 0.02, global_install: 0.02, global_config: 0.02, harmful: 0.02, privacy: 0.02 }
  const noul = Object.fromEntries(Object.entries({ ...base, ...risks }).map(([k, v]) => [k, { type: "noul", noul: v }]))
  const pRun = verdict === "run" ? confidence : 1 - confidence
  return {
    model: "jev-latest",
    answers: {
      verdict: { type: "choice", choice: verdict, probabilities: { run: pRun, confirm: 1 - pRun }, confidence },
      ...noul,
    },
  }
}

let reply: (body: any) => { status: number; json?: unknown; html?: string; headers?: Record<string, string> } = () => ({
  status: 200,
  json: answers("run"),
})

async function load(options: Record<string, unknown> = {}, storage = new Map<string, unknown>(), project = PROJECT): Promise<Fake> {
  const fake: Fake = { hooks: {}, command: undefined, storage, synthetic: [], requests: [] }
  globalThis.fetch = (async (_url: string, init: any) => {
    const body = JSON.parse(init.body)
    fake.requests.push(body)
    const r = reply(body)
    if (typeof r.html === "string") return new Response(r.html, { status: r.status, headers: r.headers })
    return new Response(JSON.stringify(r.json ?? {}), { status: r.status, headers: r.headers })
  }) as typeof fetch
  await plugin.setup({
    options: { apiKey: "test-key", ...options },
    location: { directory: project, project: { directory: project } },
    storage: {
      get: async (k: string) => fake.storage.get(k),
      set: async (k: string, v: unknown) => void fake.storage.set(k, v),
      remove: async (k: string) => void fake.storage.delete(k),
    },
    tool: { hook: async (name: string, fn: Hook) => void (fake.hooks[`tool.${name}`] = fn) },
    permission: { hook: async (name: string, fn: Hook) => void (fake.hooks[`permission.${name}`] = fn) },
    command: {
      transform: async (fn: (e: any) => void) => fn({ add: (c: any) => (fake.command = c) }),
    },
    session: { synthetic: async (m: any) => void fake.synthetic.push(m) },
  })
  return fake
}

let callSeq = 0
async function runShell(fake: Fake, command: string, effect = "ask", cwd?: string, sessionID = "s1") {
  const id = `call_${++callSeq}`
  await fake.hooks["tool.execute.before"]!({ tool: "shell", id, sessionID, input: { command, cwd } })
  const event: any = {
    sessionID,
    action: "shell",
    resources: command.split(/\s*&&\s*/),
    source: { type: "tool", messageID: "m1", id },
    effect,
  }
  await fake.hooks["permission.evaluate"]!(event)
  return event
}

async function runRemote(fake: Fake, command: string, effect = "allow", cwd?: string) {
  const id = `call_${++callSeq}`
  await fake.hooks["tool.execute.before"]!({ tool: "farhand_remote_shell", id, sessionID: "s1", input: { command, cwd } })
  const event: any = { sessionID: "s1", action: "farhand_remote_shell", resources: ["*"], source: { type: "tool", messageID: "m1", id }, effect }
  await fake.hooks["permission.evaluate"]!(event)
  return event
}

const FARHAND_PROJECT = fileURLToPath(new URL("./fixtures/farhand-project", import.meta.url))

beforeEach(() => {
  delete process.env.JEV_GUARD
  delete process.env.FARHAND_CONFIG
  // Keep the real ~/.config/farhand out of the tests.
  process.env.XDG_CONFIG_HOME = "/nonexistent-jev-guard-test"
  reply = () => ({ status: 200, json: answers("run") })
})

test("with autoAllow, a safe command runs without a prompt even when config says ask", async () => {
  const fake = await load({ autoAllow: true })
  const e = await runShell(fake, "npm test")
  assert.equal(e.effect, "allow")
  assert.equal(fake.requests.length, 1)
  const req = fake.requests[0]
  assert.equal(req.model, "jev-latest")
  assert.equal(req.state.command, "npm test")
  assert.equal(req.state.project_directory, PROJECT)
  assert.equal(req.state.working_directory, PROJECT)
  assert.deepEqual(Object.keys(req.questions).sort(), ["global_config", "global_install", "harmful", "host_litter", "privacy", "verdict"])
})

test("a flagged risk asks, and the prompt says why", async () => {
  reply = () => ({ status: 200, json: answers("run", { global_install: 0.93 }) })
  const fake = await load()
  const e = await runShell(fake, "npm install -g typescript", "allow")
  assert.equal(e.effect, "ask")
  assert.match(e.message, /installs software globally \(0\.93\)/)
})

test("a confirm verdict asks", async () => {
  reply = () => ({ status: 200, json: answers("confirm") })
  const fake = await load()
  assert.equal((await runShell(fake, "rm -rf ~/Downloads")).effect, "ask")
})

test("a low-confidence run verdict asks", async () => {
  reply = () => ({ status: 200, json: answers("run", {}, 0.4) })
  const fake = await load()
  const e = await runShell(fake, "make")
  assert.equal(e.effect, "ask")
  assert.equal(e.message, "Jev: leans towards run, but is unsure (confidence 0.40 < 0.60, p(run)=0.40)")
})

test("missing risk answers fail closed", async () => {
  reply = () => {
    const r: any = answers("run")
    delete r.answers.privacy
    return { status: 200, json: r }
  }
  const fake = await load()
  assert.equal((await runShell(fake, "ls")).effect, "ask")
})

test("Jev errors ask instead of running, and are not cached", async () => {
  reply = () => ({ status: 500, json: { error: "boom" } })
  const fake = await load()
  const e = await runShell(fake, "ls")
  assert.equal(e.effect, "ask")
  assert.match(e.message, /Jev unavailable \(HTTP 500/)
  assert.equal(fake.requests.length, 2)
  reply = () => ({ status: 200, json: answers("run") })
  assert.equal((await runShell(fake, "ls", "allow")).effect, "allow")
  assert.equal(fake.requests.length, 3)
})

test("a firewall block is summarised, not pasted, and not retried", async () => {
  reply = () => ({
    status: 403,
    html: '<!DOCTYPE html> <!--[if lt IE 7]> <html class="no-js ie6 oldie" lang="en-US"> <![endif]--> Sorry, you have been blocked',
    headers: { "content-type": "text/html; charset=UTF-8", server: "cloudflare", "cf-ray": "abc123-IAD" },
  })
  const fake = await load()
  const e = await runShell(fake, "pwd")
  assert.equal(e.effect, "ask")
  assert.equal(e.message, "Jev unavailable (HTTP 403, blocked by the Jev API's Cloudflare firewall, ray abc123-IAD); confirm manually")
  assert.equal(fake.requests.length, 1)
})

test("a rate limit is retried once", async () => {
  let calls = 0
  reply = () => (++calls === 1 ? { status: 429, json: { error: "slow down" } } : { status: 200, json: answers("run") })
  const fake = await load({ autoAllow: true })
  assert.equal((await runShell(fake, "ls")).effect, "allow")
  assert.equal(fake.requests.length, 2)
})

test("an API error is not retried", async () => {
  reply = () => ({ status: 422, json: { error: "bad question" } })
  const fake = await load()
  const e = await runShell(fake, "ls")
  assert.equal(fake.requests.length, 1)
  assert.match(e.message, /Jev unavailable \(HTTP 422: \{"error":"bad question"\}\)/)
})

test("no API key asks for everything and never calls out", async () => {
  const saved = process.env.TYPESAFE_API_KEY
  delete process.env.TYPESAFE_API_KEY
  try {
    const fake = await load({ apiKey: undefined, apiKeyFile: "/nonexistent/key" })
    const e = await runShell(fake, "ls")
    assert.equal(e.effect, "ask")
    assert.match(e.message, /not configured/)
    assert.equal(fake.requests.length, 0)
  } finally {
    if (saved !== undefined) process.env.TYPESAFE_API_KEY = saved
  }
})

test("identical commands in the same directory are judged once", async () => {
  const fake = await load()
  await runShell(fake, "git status")
  await runShell(fake, "git status")
  await runShell(fake, "git status", "ask", "/tmp")
  assert.equal(fake.requests.length, 2)
})

test("relative cwd is resolved against the project", async () => {
  const fake = await load()
  await runShell(fake, "ls", "ask", "sub/dir")
  assert.equal(fake.requests[0].state.working_directory, `${PROJECT}/sub/dir`)
})

test("secrets are redacted before leaving the machine", async () => {
  const fake = await load()
  await runShell(
    fake,
    'curl -H "Authorization: Bearer abc.def" https://user:hunter2@x.io && OPENAI_API_KEY=sk-1234567890abcdefghij node a.js --password=pw1',
  )
  const sent = fake.requests[0].state.command
  for (const secret of ["abc.def", "hunter2", "sk-1234567890abcdefghij", "pw1"]) assert.ok(!sent.includes(secret), sent)
})

test("other permission actions are left alone", async () => {
  const fake = await load()
  const e: any = { action: "edit", resources: ["a.ts"], effect: "ask" }
  await fake.hooks["permission.evaluate"]!(e)
  assert.equal(e.effect, "ask")
  assert.equal(fake.requests.length, 0)
})

test("/jev off leaves OpenCode's own decision alone in that session only, and /jev on restores", async () => {
  reply = () => ({ status: 200, json: answers("confirm", { harmful: 0.99 }) })
  const fake = await load()
  const jev = (text: string, sessionID = "s1") => fake.command.execute({ sessionID, prompt: { text } })
  await jev("off")
  assert.equal(fake.storage.get("session/s1"), false)
  assert.match(fake.synthetic.at(-1).description, /^Jev guard OFF \(set for this session\)/)
  assert.equal(fake.synthetic.at(-1).resume, false)
  // Neutral: a config `ask` stays ask, a config `allow` stays allow, and Jev is not called.
  assert.equal((await runShell(fake, "sudo rm -rf /", "ask")).effect, "ask")
  assert.equal((await runShell(fake, "sudo rm -rf /", "allow")).effect, "allow")
  assert.equal(fake.requests.length, 0)

  // Another session is still guarded.
  assert.equal((await runShell(fake, "sudo rm -rf /", "allow", undefined, "s2")).effect, "ask")
  assert.equal(fake.requests.length, 1)

  await jev("on")
  assert.equal((await runShell(fake, "sudo rm -rf /")).effect, "ask")
  await jev("")
  assert.match(fake.synthetic.at(-1).description, /^Jev guard ON \(set for this session\) · this session: 0 passed, 1 asked · default on \(built-in\)/)
  await jev("foo")
  assert.match(fake.synthetic.at(-1).description, /Unknown "\/jev foo"/)
})

test("/jev default switches every session without its own setting; /jev reset follows it again", async () => {
  reply = () => ({ status: 200, json: answers("confirm") })
  const fake = await load()
  const jev = (text: string, sessionID: string) => fake.command.execute({ sessionID, prompt: { text } })
  await jev("on", "mine")
  await jev("default off", "other")
  assert.equal(fake.storage.get("enabled"), false)
  assert.match(fake.synthetic.at(-1).description, /^Jev guard OFF \(default, from \/jev default\)/)
  assert.equal((await runShell(fake, "x", "allow", undefined, "fresh")).effect, "allow")
  assert.equal((await runShell(fake, "x", "allow", undefined, "mine")).effect, "ask")
  await jev("reset", "mine")
  assert.equal(fake.storage.has("session/mine"), false)
  assert.equal((await runShell(fake, "x", "allow", undefined, "mine")).effect, "allow")
})

test("settings survive a restart; JEV_GUARD overrides the default but not a session's own setting", async () => {
  reply = () => ({ status: 200, json: answers("confirm") })
  const fake = await load()
  await fake.command.execute({ sessionID: "a", prompt: { text: "off" } })

  const restarted = await load({}, fake.storage)
  assert.equal((await runShell(restarted, "ls", "allow", undefined, "a")).effect, "allow")
  assert.equal((await runShell(restarted, "ls", "allow", undefined, "b")).effect, "ask")

  process.env.JEV_GUARD = "off"
  const envOff = await load({}, fake.storage)
  assert.equal((await runShell(envOff, "ls", "allow", undefined, "b")).effect, "allow")
  await envOff.command.execute({ sessionID: "b", prompt: { text: "status" } })
  assert.match(envOff.synthetic.at(-1).description, /^Jev guard OFF \(default, from JEV_GUARD\)/)
  await envOff.command.execute({ sessionID: "c", prompt: { text: "on" } })
  assert.equal((await runShell(envOff, "ls", "allow", undefined, "c")).effect, "ask")
})

test("without autoAllow the guard never allows anything", async () => {
  const scenarios: Array<() => { status: number; json?: unknown }> = [
    () => ({ status: 200, json: answers("run") }),
    () => ({ status: 200, json: answers("run", {}, 0.3) }),
    () => ({ status: 200, json: answers("confirm") }),
    () => ({ status: 200, json: answers("run", { privacy: 0.9 }) }),
    () => ({ status: 500, json: {} }),
    () => ({ status: 200, json: {} }),
  ]
  for (const [i, sc] of scenarios.entries()) {
    reply = sc
    for (const options of [{}, { verdict: false }, { enabled: false }]) {
      const fake = await load(options)
      assert.equal((await runShell(fake, `cmd ${i}`, "ask")).effect, "ask", `scenario ${i} ${JSON.stringify(options)}`)
      assert.notEqual((await runRemote(fake, `cmd ${i}`, "ask")).effect, "allow")
    }
  }
})

test("enabled: false in options makes the default off", async () => {
  const fake = await load({ enabled: false })
  assert.equal((await runShell(fake, "brew install jq", "allow")).effect, "allow")
  assert.equal(fake.requests.length, 0)
  await fake.command.execute({ sessionID: "s1", prompt: { text: "status" } })
  assert.match(fake.synthetic.at(-1).description, /^Jev guard OFF \(default, from plugin options\)/)
})

test("by default a safe command keeps OpenCode's own decision", async () => {
  const fake = await load()
  assert.equal((await runShell(fake, "ls", "ask")).effect, "ask")
  assert.equal((await runShell(fake, "pwd", "allow")).effect, "allow")
})

test("FarHand remote commands are judged as running on the remote host", async () => {
  reply = () => ({ status: 200, json: answers("confirm", { global_install: 0.98, harmful: 0.8 }) })
  const fake = await load({}, new Map(), FARHAND_PROJECT)
  const e = await runRemote(fake, "sudo apt-get update && sudo apt-get install -y tmux")
  assert.equal(e.effect, "ask")
  assert.match(e.message, /installs software globally \(0\.98\)/)
  const st = fake.requests[0].state
  assert.equal(st.command, "sudo apt-get update && sudo apt-get install -y tmux")
  assert.match(st.machine, /remote host devbox/)
  assert.equal(st.platform, "linux")
  assert.equal(st.project_directory, "~/myapp")
  assert.equal(st.working_directory, "~/myapp")
})

test("FarHand cwd resolves against the remote workdir", async () => {
  const fake = await load({}, new Map(), FARHAND_PROJECT)
  await runRemote(fake, "ls", "allow", "src")
  await runRemote(fake, "ls", "allow", "/var/log")
  assert.equal(fake.requests[0].state.working_directory, "~/myapp/src")
  assert.equal(fake.requests[1].state.working_directory, "/var/log")
})

test("a safe FarHand command keeps FarHand's own decision", async () => {
  const fake = await load({}, new Map(), FARHAND_PROJECT)
  assert.equal((await runRemote(fake, "uname -a", "allow")).effect, "allow")
  assert.equal((await runRemote(fake, "whoami", "ask")).effect, "ask")
})

test("with the guard off, FarHand commands are left to OpenCode and FarHand too", async () => {
  const fake = await load({ enabled: false }, new Map(), FARHAND_PROJECT)
  assert.equal((await runRemote(fake, "sudo rm -rf /", "ask")).effect, "ask")
  assert.equal(fake.requests.length, 0)
})

test("a FarHand permission request without a recorded command asks", async () => {
  const fake = await load({}, new Map(), FARHAND_PROJECT)
  const e: any = { action: "farhand_remote_shell", resources: ["*"], source: { type: "tool", id: "unknown" }, effect: "allow" }
  await fake.hooks["permission.evaluate"]!(e)
  assert.equal(e.effect, "ask")
  assert.match(e.message, /could not see/)
  assert.equal(fake.requests.length, 0)
})

test("the same command is cached separately for local and remote", async () => {
  const fake = await load({}, new Map(), FARHAND_PROJECT)
  await runShell(fake, "ls")
  await runRemote(fake, "ls")
  assert.equal(fake.requests.length, 2)
  assert.equal(fake.requests[0].state.machine, "the user's own local computer")
})

test("a flagged command also leaves a visible note in the transcript", async () => {
  reply = () => ({ status: 200, json: answers("confirm", { global_install: 0.97 }) })
  const fake = await load({}, new Map(), FARHAND_PROJECT)
  await runRemote(fake, "sudo apt-get purge -y tmux")
  await new Promise((r) => setTimeout(r, 0))
  const note = fake.synthetic.at(-1)
  assert.equal(note.sessionID, "s1")
  assert.equal(note.resume, false)
  assert.equal(note.description, "⚠ Jev on devbox: installs software globally (0.97) · sudo apt-get purge -y tmux")
  assert.match(note.text, /If the command ran, the user approved it/)
  assert.match(note.text, /do not retry it another way/)
})

test("a safe command leaves no note", async () => {
  const fake = await load()
  await runShell(fake, "ls")
  await new Promise((r) => setTimeout(r, 0))
  assert.equal(fake.synthetic.length, 0)
})

// ---- Configurable risk categories ------------------------------------------------

const TMP = fileURLToPath(new URL("./fixtures/tmp-policy", import.meta.url))

function policyDirs() {
  rmSync(TMP, { recursive: true, force: true })
  const global = join(TMP, "config")
  const project = join(TMP, "project")
  mkdirSync(join(global, "opencode"), { recursive: true })
  mkdirSync(join(project, ".opencode"), { recursive: true })
  process.env.XDG_CONFIG_HOME = global
  return {
    project,
    globalFile: join(global, "opencode", "jev-guard.jsonc"),
    projectFile: join(project, ".opencode", "jev-guard.jsonc"),
  }
}

/** Writes a config and moves its mtime forward, so the change is seen within the same millisecond too. */
let bump = 0
function writeConfig(file: string, text: string) {
  writeFileSync(file, text)
  const t = Date.now() / 1000 + ++bump
  utimesSync(file, t, t)
}

test("a built-in category can be switched off and another retuned", async () => {
  reply = () => ({ status: 200, json: answers("run", { privacy: 0.99, host_litter: 0.85 }) })
  const fake = await load({ risks: { privacy: false, host_litter: { threshold: 0.9 } } })
  assert.equal((await runShell(fake, "ls", "allow")).effect, "allow")
  assert.ok(!("privacy" in fake.requests[0].questions))
  assert.ok("host_litter" in fake.requests[0].questions)
})

test("a custom category is asked and its own threshold applies", async () => {
  reply = () => ({ status: 200, json: answers("run", { docker: 0.65 }) })
  const fake = await load({
    risks: { docker: { label: "touches Docker", question: "Does this start, stop or remove Docker containers or images?", threshold: 0.6 } },
  })
  const e = await runShell(fake, "docker rm -f db", "allow")
  assert.equal(e.effect, "ask")
  assert.match(e.message, /touches Docker \(0\.65\)/)
  assert.deepEqual(fake.requests[0].questions.docker, {
    type: "noul",
    instructions: "Does this start, stop or remove Docker containers or images?",
  })
})

test("riskThreshold is the default for every category without its own", async () => {
  reply = () => ({ status: 200, json: answers("run", { harmful: 0.55 }) })
  assert.equal((await runShell(await load(), "x", "allow")).effect, "allow")
  assert.equal((await runShell(await load({ riskThreshold: 0.5 }), "x", "allow")).effect, "ask")
})

test("verdict: false leaves the decision to the categories alone", async () => {
  reply = () => ({ status: 200, json: answers("confirm", {}, 0.99) })
  const fake = await load({ verdict: false, autoAllow: true })
  assert.equal((await runShell(fake, "make deploy")).effect, "allow")
  assert.ok(!("verdict" in fake.requests[0].questions))
})

test("project file overrides global file, which overrides options; edits apply without a restart", async () => {
  const { project, globalFile, projectFile } = policyDirs()
  try {
    writeConfig(
      globalFile,
      `{
        // global: a custom category and a looser host_litter
        "risks": {
          "docker": { "question": "Does this start, stop or remove Docker containers?", "threshold": 0.6, },
          "host_litter": { "threshold": 0.95 },
        },
      }`,
    )
    reply = () => ({ status: 200, json: answers("run", { docker: 0.7, host_litter: 0.9 }) })
    // Options say host_litter 0.5; the global file loosens it to 0.95; docker comes from the global file.
    const fake = await load({ risks: { host_litter: { threshold: 0.5 } } }, new Map(), project)
    const first = await runShell(fake, "docker ps", "allow")
    assert.equal(first.effect, "ask")
    assert.match(first.message, /docker \(0\.70\)/)
    assert.doesNotMatch(first.message, /leaves files/)

    // The global file is edited while running: raising docker's threshold there takes effect at once.
    writeConfig(globalFile, `{ "risks": { "docker": { "question": "Does this start, stop or remove Docker containers?", "threshold": 0.8 }, "host_litter": { "threshold": 0.95 } } }`)
    assert.equal((await runShell(fake, "docker ps", "allow")).effect, "allow")
    // Same questions, so the cached answer was reused rather than asking Jev again.
    assert.equal(fake.requests.length, 1)

    // The project file may tighten it again.
    writeConfig(projectFile, `{ "risks": { "docker": { "threshold": 0.65 } } }`)
    assert.equal((await runShell(fake, "docker ps", "allow")).effect, "ask")

    await fake.command.execute({ sessionID: "s1", prompt: { text: "risks" } })
    assert.match(fake.synthetic.at(-1).description, /docker\* 0\.65/)
    assert.match(fake.synthetic.at(-1).text, /Read from: built-in defaults, then plugin options, then .*config\/opencode\/jev-guard\.jsonc, then .*\.opencode\/jev-guard\.jsonc\./)
    assert.match(fake.synthetic.at(-1).description, /host_litter 0\.95/)
  } finally {
    rmSync(TMP, { recursive: true, force: true })
  }
})

test("bad config entries are skipped and reported, good ones still apply", async () => {
  const { project, globalFile, projectFile } = policyDirs()
  try {
    writeConfig(
      globalFile,
      `{ "riskThreshold": 2, "risks": { "Bad-Id": {}, "gpu": { "threshold": 0.5 }, "privacy": { "threshold": 0.99 } } }`,
    )
    reply = () => ({ status: 200, json: answers("run", { privacy: 0.9 }) })
    const fake = await load({}, new Map(), project)
    assert.equal((await runShell(fake, "cat .env", "allow")).effect, "allow")
    await fake.command.execute({ sessionID: "s1", prompt: { text: "status" } })
    assert.match(fake.synthetic.at(-1).description, /3 config problems, see \/jev risks/)
    await fake.command.execute({ sessionID: "s1", prompt: { text: "risks" } })
    assert.match(fake.synthetic.at(-1).text, /riskThreshold must be a number/)
    assert.match(fake.synthetic.at(-1).text, /risks\.Bad-Id: ids are lowercase/)
    assert.match(fake.synthetic.at(-1).text, /risks\.gpu: a new category needs a question/)

    writeConfig(projectFile, `{ not json`)
    await fake.command.execute({ sessionID: "s1", prompt: { text: "risks" } })
    assert.match(fake.synthetic.at(-1).description, /PROBLEM: .*jev-guard\.jsonc/)
  } finally {
    rmSync(TMP, { recursive: true, force: true })
  }
})

test("a project file cannot loosen the guard", async () => {
  const { project, projectFile } = policyDirs()
  try {
    writeConfig(
      projectFile,
      `{
        "verdict": false, "autoAllow": true, "riskThreshold": 0.99, "minConfidence": 0,
        "risks": {
          "harmful": false,
          "privacy": { "threshold": 0.99 },
          "host_litter": { "question": "Is the sky green today, in your honest opinion?" },
          "global_install": { "threshold": 0.4 },
          "gpu": { "question": "Does this change GPU driver or CUDA settings?" }
        }
      }`,
    )
    reply = () => ({ status: 200, json: answers("run", { harmful: 0.8, privacy: 0.8, gpu: 0.1 }) })
    const fake = await load({}, new Map(), project)
    const e = await runShell(fake, "x", "allow")
    assert.equal(e.effect, "ask")
    assert.match(e.message, /may be harmful \(0\.80\)/)
    assert.match(e.message, /may expose private data \(0\.80\)/)
    const q = fake.requests[0].questions
    assert.ok("verdict" in q && "gpu" in q && "harmful" in q)
    assert.match(q.host_litter.instructions, /outside the project directory/)

    await fake.command.execute({ sessionID: "s1", prompt: { text: "risks" } })
    const text = fake.synthetic.at(-1).text
    for (const what of ["verdict: false", "autoAllow: true", "raising riskThreshold", "lowering minConfidence", "switching off risks.harmful", "raising risks.privacy.threshold", "changing the question or label of risks.host_litter"]) {
      assert.ok(text.includes(what), `${what} should be reported:\n${text}`)
    }
    assert.match(fake.synthetic.at(-1).description, /global_install 0\.40/)
  } finally {
    rmSync(TMP, { recursive: true, force: true })
  }
})
