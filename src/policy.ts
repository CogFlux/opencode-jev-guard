// Which risk categories are asked and at which thresholds: built-in defaults,
// then plugin options, then the global and project jev-guard.jsonc files.

import { readFileSync, statSync } from "node:fs"
import { homedir } from "node:os"
import { join } from "node:path"
import type { Options } from "./config.ts"
import { debug } from "./log.ts"
import { BUILTIN_RISKS } from "./questions.ts"

export interface Risk {
  label: string
  question: string
  threshold: number
  builtin: boolean
}

/** What decides a verdict. Rebuilt whenever a jev-guard.jsonc changes. */
export interface Policy {
  verdict: boolean
  minConfidence: number
  autoAllow: boolean
  risks: Record<string, Risk>
  /** Config entries that were ignored, and why. */
  problems: string[]
  /** Changes whenever the questions change; part of the answer cache key. */
  signature: string
  /** The layers that were read, in order (for /jev risks). */
  sources: string[]
}

const RISK_ID = /^[a-z][a-z0-9_]{0,39}$/

/** JSON with comments and trailing commas, as OpenCode's own .jsonc files allow. */
export function parseJsonc(text: string): unknown {
  let out = ""
  for (let i = 0; i < text.length; i++) {
    const c = text[i]!
    if (c === '"') {
      const start = i
      for (i++; i < text.length && text[i] !== '"'; i++) if (text[i] === "\\") i++
      out += text.slice(start, i + 1)
    } else if (c === "/" && text[i + 1] === "/") {
      while (i < text.length && text[i] !== "\n") i++
      out += "\n"
    } else if (c === "/" && text[i + 1] === "*") {
      i = text.indexOf("*/", i + 2)
      if (i < 0) break
      i++
    } else out += c
  }
  return JSON.parse(out.replace(/,(\s*[}\]])/g, "$1"))
}

/**
 * `stricter` layers may only tighten the policy. A project's
 * .opencode/jev-guard.jsonc is one: it sits inside the project, where writing
 * a file looks harmless to Jev, so an agent (or a cloned repo) could otherwise
 * switch its own guard off with one unflagged command.
 */
export type Layer = { source: string; config: Options; stricter?: boolean }

function num01(v: unknown): v is number {
  return typeof v === "number" && v > 0 && v <= 1
}

/**
 * Builds the policy from the defaults and then each layer in order: plugin
 * options, the global file, the project file. A later layer overrides single
 * fields of an earlier one; a bad entry, or one a `stricter` layer may not
 * make, is skipped and reported, never fatal.
 */
export function buildPolicy(layers: Layer[]): Policy {
  const problems: string[] = []
  let riskThreshold = 0.7
  let minConfidence = 0.6
  let autoAllow = false
  let verdict = true
  const defs: Record<string, { label?: string; question?: string; threshold?: number; builtin: boolean } | false> = {}
  for (const [id, r] of Object.entries(BUILTIN_RISKS)) defs[id] = { ...r, builtin: true }

  for (const { source, config, stricter } of layers) {
    const c = config as Record<string, unknown>
    const looser = (what: string) => problems.push(`${source}: ${what} ignored; a project file can only make the guard stricter`)
    if (c.riskThreshold !== undefined) {
      if (!num01(c.riskThreshold)) problems.push(`${source}: riskThreshold must be a number in (0, 1]`)
      else if (stricter && c.riskThreshold > riskThreshold) looser("raising riskThreshold")
      else riskThreshold = c.riskThreshold
    }
    if (c.minConfidence !== undefined) {
      if (!(typeof c.minConfidence === "number" && c.minConfidence >= 0 && c.minConfidence <= 1)) problems.push(`${source}: minConfidence must be a number in [0, 1]`)
      else if (stricter && c.minConfidence < minConfidence) looser("lowering minConfidence")
      else minConfidence = c.minConfidence
    }
    if (c.autoAllow !== undefined) {
      if (typeof c.autoAllow !== "boolean") problems.push(`${source}: autoAllow must be true or false`)
      else if (stricter && c.autoAllow && !autoAllow) looser("autoAllow: true")
      else autoAllow = c.autoAllow
    }
    if (c.verdict !== undefined) {
      if (typeof c.verdict !== "boolean") problems.push(`${source}: verdict must be true or false`)
      else if (stricter && !c.verdict && verdict) looser("verdict: false")
      else verdict = c.verdict
    }
    if (c.risks === undefined) continue
    if (typeof c.risks !== "object" || c.risks === null || Array.isArray(c.risks)) {
      problems.push(`${source}: risks must be an object`)
      continue
    }
    for (const [id, raw] of Object.entries(c.risks as Record<string, unknown>)) {
      const where = `${source}: risks.${id}`
      if (!RISK_ID.test(id) || id === "verdict") {
        problems.push(`${where}: ids are lowercase letters, digits and _, up to 40 characters, and not "verdict"`)
        continue
      }
      if (raw === false) {
        if (stricter && defs[id]) looser(`switching off risks.${id}`)
        else defs[id] = false
        continue
      }
      if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
        problems.push(`${where}: expected false or { label, question, threshold }`)
        continue
      }
      const r = raw as Record<string, unknown>
      const prev = defs[id] || undefined
      const next = { ...(prev ?? { builtin: false }) }
      let ok = true
      if (stricter && prev) {
        // An existing category's question and label are what make it bite; only its threshold may go down.
        if (r.question !== undefined || r.label !== undefined) {
          looser(`changing the question or label of risks.${id}`)
          continue
        }
        const current = prev.threshold ?? riskThreshold
        if (num01(r.threshold) && r.threshold > current) {
          looser(`raising risks.${id}.threshold`)
          continue
        }
      }
      if (r.label !== undefined) {
        if (typeof r.label === "string" && r.label.trim() && r.label.length <= 80) next.label = r.label.trim()
        else (problems.push(`${where}.label: a non-empty string up to 80 characters`), (ok = false))
      }
      if (r.question !== undefined) {
        if (typeof r.question === "string" && r.question.trim().length >= 10 && r.question.length <= 2000) next.question = r.question.trim()
        else (problems.push(`${where}.question: a yes/no question of 10 to 2000 characters`), (ok = false))
      }
      if (r.threshold !== undefined) {
        if (num01(r.threshold)) next.threshold = r.threshold
        else (problems.push(`${where}.threshold: a number in (0, 1]`), (ok = false))
      }
      if (!next.question) {
        problems.push(`${where}: a new category needs a question`)
        ok = false
      }
      if (ok) defs[id] = next
    }
  }

  const risks: Record<string, Risk> = {}
  for (const [id, d] of Object.entries(defs)) {
    if (!d || !d.question) continue
    risks[id] = { label: d.label ?? id.replaceAll("_", " "), question: d.question, threshold: d.threshold ?? riskThreshold, builtin: d.builtin }
  }
  const signature = JSON.stringify([verdict, Object.entries(risks).map(([id, r]) => [id, r.question])])
  return { verdict, minConfidence, autoAllow, risks, problems, signature, sources: layers.map((l) => l.source) }
}

/** The jev-guard.jsonc files that apply here, global first. */
export function policyFiles(project: string): string[] {
  const global = join(process.env.XDG_CONFIG_HOME || join(homedir(), ".config"), "opencode", "jev-guard.jsonc")
  return [global, join(project, ".opencode", "jev-guard.jsonc")]
}

/** Re-reads the files only when one of them changed, so edits apply without a restart. */
export function policyLoader(options: Options, files: string[]): () => Policy {
  let stamp = ""
  let policy: Policy | undefined
  return () => {
    const mtimes = files.map((f) => {
      try {
        return String(statSync(f).mtimeMs)
      } catch {
        return "-"
      }
    })
    const now = mtimes.join("|")
    if (policy && now === stamp) return policy
    stamp = now
    const layers: Layer[] = [{ source: "plugin options", config: options }]
    // An empty options object is not a source worth listing.
    if (!Object.keys(options).some((k) => ["riskThreshold", "minConfidence", "verdict", "autoAllow", "risks"].includes(k))) layers.pop()
    const problems: string[] = []
    files.forEach((file, i) => {
      if (mtimes[i] === "-") return
      try {
        const config = parseJsonc(readFileSync(file, "utf8"))
        if (typeof config !== "object" || config === null || Array.isArray(config)) problems.push(`${file}: not a JSON object`)
        else layers.push({ source: file.replace(homedir(), "~"), config: config as Options, stricter: i > 0 })
      } catch (e) {
        problems.push(`${file.replace(homedir(), "~")}: ${e instanceof Error ? e.message : String(e)}`)
      }
    })
    policy = buildPolicy(layers)
    policy.problems.unshift(...problems)
    debug({ hook: "policy", files, risks: Object.keys(policy.risks), problems: policy.problems })
    return policy
  }
}

