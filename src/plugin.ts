// The plugin: OpenCode hooks and the /jev command.

import { posix, resolve } from "node:path"
import { type Options, settingsFrom } from "./config.ts"
import { REMOTE_SHELL_TOOL, SHELL_TOOLS, farhandRemote } from "./farhand.ts"
import { askJev, judge, redact, type JevResponse, type Target, type Verdict } from "./jev.ts"
import { debug } from "./log.ts"
import { policyFiles, policyLoader } from "./policy.ts"

/** Keeps the newest `max` entries. */
class Recent<V> extends Map<string, V> {
  readonly max: number
  constructor(max: number) {
    super()
    this.max = max
  }
  set(key: string, value: V): this {
    this.delete(key)
    super.set(key, value)
    if (this.size > this.max) this.delete(this.keys().next().value as string)
    return this
  }
}

/** Storage keys. The default keeps its old name, so a switch saved by an earlier version becomes the default. */
const DEFAULT_KEY = "enabled"
const sessionKey = (sessionID: string) => `session/${sessionID}`

function envSwitch(): boolean | undefined {
  const v = process.env.JEV_GUARD?.trim().toLowerCase()
  if (!v) return undefined
  if (["0", "off", "false", "no"].includes(v)) return false
  if (["1", "on", "true", "yes"].includes(v)) return true
  return undefined
}

/**
 * What the guard does with one permission request. `keep` leaves OpenCode's
 * own decision (`passed` when Jev judged the command safe); `ask` turns it
 * into a prompt. There is deliberately no `allow`: the guard can only add
 * prompts.
 */
type Decision = { effect: "keep"; passed?: boolean } | { effect: "ask"; reason: string; target?: Target }

type Switch = { on: boolean; source: string }

export async function setup(ctx: any) {
  const options: Options = ctx.options ?? {}
  const s = settingsFrom(options)
  const project: string = ctx.location?.project?.directory ?? ctx.location?.directory ?? process.cwd()
  const directory: string = ctx.location?.directory ?? project

  const load = async (key: string): Promise<boolean | undefined> => {
    try {
      const v = await ctx.storage?.get(key)
      return typeof v === "boolean" ? v : undefined
    } catch {
      return undefined
    }
  }
  const save = async (key: string, value: boolean | undefined) => {
    try {
      if (value === undefined) await ctx.storage?.remove(key)
      else await ctx.storage?.set(key, value)
    } catch {
      /* still switched for this run */
    }
  }

  /**
   * The guard is switched per session. A session without its own setting
   * follows the default: JEV_GUARD, else what `/jev default` saved, else the
   * `enabled` option, else on. Each is kept with where it came from, for
   * /jev status.
   */
  let savedDefault = await load(DEFAULT_KEY)
  const defaultSwitch = (): Switch => {
    const env = envSwitch()
    if (env !== undefined) return { on: env, source: "JEV_GUARD" }
    if (savedDefault !== undefined) return { on: savedDefault, source: "/jev default" }
    if (typeof options.enabled === "boolean") return { on: options.enabled, source: "plugin options" }
    return { on: true, source: "built-in" }
  }
  /** Per-session settings read so far; `null` = the session has none. */
  const sessions = new Recent<boolean | null>(1000)
  const sessionSwitch = async (sessionID: string | undefined): Promise<Switch> => {
    if (!sessionID) return defaultSwitch()
    let own = sessions.get(sessionID)
    if (own === undefined) {
      own = (await load(sessionKey(sessionID))) ?? null
      sessions.set(sessionID, own)
    }
    return own === null ? defaultSwitch() : { on: own, source: "this session" }
  }
  const setSession = async (sessionID: string, on: boolean | undefined) => {
    sessions.set(sessionID, on ?? null)
    await save(sessionKey(sessionID), on)
  }

  const remote = farhandRemote([...new Set([project, directory])])
  const policy = policyLoader(options, policyFiles(project))
  debug({ hook: "setup", directory, project, default: defaultSwitch(), remote, hasKey: !!s.apiKey })

  /** The command per tool call: permission requests carry only its parsed parts (shell) or nothing (FarHand). */
  const calls = new Recent<Target>(200)
  /** Jev's answers per question set, command and directory, so a retried command is not sent twice. */
  const answers = new Recent<JevResponse>(500)
  /** Per session, since this OpenCode process started. */
  const stats = new Recent<{ run: number; asked: number }>(1000)
  const count = (sessionID: string | undefined, key: "run" | "asked") => {
    const id = sessionID ?? "-"
    const st = stats.get(id) ?? { run: 0, asked: 0 }
    st[key]++
    stats.set(id, st)
  }

  await ctx.tool.hook("execute.before", (event: any) => {
    const command = event.input?.command
    if (SHELL_TOOLS.has(event.tool) || event.tool === REMOTE_SHELL_TOOL || String(event.tool).startsWith("farhand")) {
      debug({ hook: "execute.before", directory, tool: event.tool, id: event.id, command: typeof command === "string" ? redact(command) : command })
    }
    if (typeof command !== "string") return
    const cwd = typeof event.input.cwd === "string" && event.input.cwd ? event.input.cwd : undefined
    if (SHELL_TOOLS.has(event.tool)) {
      calls.set(event.id, { command, cwd: cwd ? resolve(directory, cwd) : directory, project })
    } else if (event.tool === REMOTE_SHELL_TOOL) {
      const workdir = remote?.workdir ?? "the remote workdir"
      const abs = cwd && (cwd.startsWith("/") || cwd.startsWith("~") || /^[A-Za-z]:[\\/]/.test(cwd))
      calls.set(event.id, {
        command,
        cwd: !cwd ? workdir : abs ? cwd : posix.join(workdir, cwd),
        project: workdir,
        remote: { host: remote?.host ?? "unknown", os: remote?.os },
      })
    }
  })

  await ctx.permission.hook("evaluate", async (event: any) => {
    const before = event.effect
    let decision: Decision = { effect: "keep" }
    try {
      decision = await decide(event)
    } catch (err) {
      // A bug in the guard must not let a command through unjudged.
      decision = { effect: "ask", reason: `Jev guard failed (${err instanceof Error ? err.message : String(err)}); confirm manually` }
    }
    try {
      apply(event, decision)
    } finally {
      debug({
        hook: "evaluate",
        directory,
        session: event.sessionID,
        action: event.action,
        resources: event.resources,
        source: event.source,
        decision: decision.effect,
        effect: `${before} -> ${event.effect}`,
        message: event.message,
      })
    }
  })

  /** Works out the decision; changes nothing. */
  async function decide(event: any): Promise<Decision> {
    const local = SHELL_TOOLS.has(event.action)
    if (!local && event.action !== REMOTE_SHELL_TOOL) return { effect: "keep" }
    // Off means neutral: OpenCode's own rules decide, including a `shell: ask`.
    if (!(await sessionSwitch(event.sessionID)).on) return { effect: "keep" }
    const call = event.source?.type === "tool" ? calls.get(event.source.id) : undefined
    const target: Target | undefined =
      call ?? (local && event.resources?.length ? { command: event.resources.join(" && "), cwd: directory, project } : undefined)
    if (!target) return { effect: "ask", reason: "Jev guard could not see this command; confirm manually" }

    const p = policy()
    const key = `${p.signature}\0${target.remote?.host ?? ""}\0${target.cwd}\0${target.command}`
    let response = answers.get(key)
    let verdict: Verdict
    if (response) verdict = judge(p, response)
    else {
      const asked = await askJev(s, p, target)
      // Only answers Jev actually gave are remembered; an outage is retried next time.
      if (asked.ok) answers.set(key, (response = asked.response))
      verdict = asked.ok ? judge(p, asked.response) : { run: false, reason: asked.reason }
    }
    if (!verdict.run) return { effect: "ask", reason: verdict.reason, target }
    return { effect: "keep", passed: true }
  }

  /** The only place that changes the permission request. */
  function apply(event: any, d: Decision): void {
    if (d.effect === "keep") {
      if (d.passed) count(event.sessionID, "run")
      return
    }
    count(event.sessionID, "asked")
    event.effect = "ask"
    event.message = d.reason
    warn(event.sessionID, d.reason, d.target)
  }

  /**
   * OpenCode 2.0.14's permission prompt never shows `message`: its body is
   * fixed ("$ <command>" for shell, "Tool: <name>" for MCP tools). So the
   * reason also goes into the transcript as a one-line synthetic note, which
   * the TUI renders right above the prompt as soon as it is queued. The model
   * only sees it once the tool step is over. Not awaited: the permission
   * request must not wait on it.
   */
  function warn(sessionID: string | undefined, reason: string, target: Target | undefined): void {
    if (!sessionID || !ctx.session?.synthetic) return
    const why = reason.replace(/^Jev:\s*/, "").replace(/\s*\[p\(run\)[^\]]*\]$/, "")
    const where = target?.remote ? ` on ${target.remote.host}` : ""
    const command = target ? target.command.replace(/\s+/g, " ").trim() : ""
    const shown = command.length > 80 ? `${command.slice(0, 79)}…` : command
    const description = `⚠ Jev${where}: ${why}${shown ? ` · ${shown}` : ""}`
    // The model receives this only after the tool step ends, i.e. after the
    // user has already answered the prompt. Word it as a record, so the model
    // does not conclude the command slipped past the guard.
    const text =
      `Jev guard flagged the command${where}${command ? ` \`${redact(command)}\`` : ""} (${reason}), so OpenCode ` +
      "asked the user to confirm it before it ran. If the command ran, the user approved it; if it was rejected, " +
      "the user declined it, so do not retry it another way."
    Promise.resolve()
      .then(() => ctx.session.synthetic({ sessionID, text, description, resume: false }))
      .catch((e: unknown) => debug({ hook: "warn", error: e instanceof Error ? e.message : String(e) }))
  }


  /**
   * The TUI shows only a synthetic message's `description`, as one line cut
   * to the window width, so the state goes there and stays short. `text` is
   * what the model sees as context.
   */
  const configNote = () => {
    const n = policy().problems.length
    return n ? ` · ${n} config problem${n === 1 ? "" : "s"}, see /jev risks` : ""
  }
  const status = async (sessionID: string) => {
    const sw = await sessionSwitch(sessionID)
    const def = defaultSwitch()
    const st = stats.get(sessionID) ?? { run: 0, asked: 0 }
    const head = sw.on ? "Jev guard ON" : "Jev guard OFF"
    const why = sw.source === "this session" ? "set for this session" : `default, from ${sw.source}`
    const counts = sw.on ? ` · this session: ${st.run} passed, ${st.asked} asked` : " · your OpenCode permission rules decide"
    const other = sw.source === "this session" ? ` · default ${def.on ? "on" : "off"} (${def.source})` : ""
    return `${head} (${why})${counts}${other}` + (sw.on && !s.apiKey ? " · NO API KEY: every command asks" : "") + configNote()
  }
  /** One line per the TUI's limits: the categories and thresholds in effect, then the first problem. */
  const risksLine = () => {
    const p = policy()
    const list = Object.entries(p.risks).map(([id, r]) => `${id}${r.builtin ? "" : "*"} ${r.threshold.toFixed(2)}`)
    const head = `Jev risks · ${list.join(" · ") || "none"}` + (p.verdict ? ` · verdict on (confidence ≥ ${p.minConfidence})` : " · verdict off")
    return p.problems.length ? `${head} · PROBLEM: ${p.problems[0]}` : head
  }
  const risksText = () => {
    const p = policy()
    const lines = Object.entries(p.risks).map(([id, r]) => `- ${id} (${r.builtin ? "built-in" : "custom"}, asks at ≥ ${r.threshold}): ${r.label}`)
    return (
      `Jev guard risk categories in effect:\n${lines.join("\n") || "- none"}\n` +
      `Overall verdict question: ${p.verdict ? `on, minimum confidence ${p.minConfidence}` : "off"}.\n` +
      `Read from: ${["built-in defaults", ...p.sources].join(", then ")}.` +
      (p.problems.length ? `\nIgnored config entries:\n${p.problems.map((x) => `- ${x}`).join("\n")}` : "")
    )
  }
  const context = (on: boolean) =>
    on
      ? `The Jev command guard is on for this session: shell commands are checked by Jev (${s.model}) and risky ones need the user's confirmation.`
      : "The Jev command guard is off for this session: shell commands are not checked by Jev; OpenCode's own permission rules still apply."

  const USAGE = "on | off | toggle (this session) · default on | off · reset · status · risks"

  await ctx.command.transform((editor: any) => {
    editor.add({
      name: "jev",
      description: `Jev command guard: /jev ${USAGE}`,
      execute: async ({ sessionID, prompt }: { sessionID: string; prompt?: { text?: string } }) => {
        const words = (prompt?.text ?? "").trim().toLowerCase().split(/\s+/).filter(Boolean)
        const [cmd = "status", arg] = words
        const note = (description: string, text: string) => ctx.session.synthetic({ sessionID, text, description, resume: false })

        if (cmd === "risks") return note(risksLine(), risksText())
        if (cmd === "on" || cmd === "off" || cmd === "toggle") {
          const on = cmd === "toggle" ? !(await sessionSwitch(sessionID)).on : cmd === "on"
          await setSession(sessionID, on)
        } else if (cmd === "reset") {
          await setSession(sessionID, undefined)
        } else if (cmd === "default" && (arg === "on" || arg === "off")) {
          savedDefault = arg === "on"
          await save(DEFAULT_KEY, savedDefault)
        } else if (cmd !== "status") {
          return note(`Unknown "/jev ${words.join(" ")}" (use ${USAGE}) · ${await status(sessionID)}`, context((await sessionSwitch(sessionID)).on))
        }
        const line = await status(sessionID)
        const envNote = cmd === "default" && envSwitch() !== undefined ? " · JEV_GUARD overrides the saved default until restart" : ""
        return note(line + envNote, context((await sessionSwitch(sessionID)).on))
      },
    })
  })
}
