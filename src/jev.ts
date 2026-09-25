// Talking to Jev: the request, the reply, and how a reply becomes a verdict.

import { homedir } from "node:os"
import type { Settings } from "./config.ts"
import { debug } from "./log.ts"
import type { Policy } from "./policy.ts"
import { VERDICT } from "./questions.ts"

export interface JevAnswer {
  type?: string
  choice?: string
  noul?: number
  probabilities?: Record<string, number>
  confidence?: number
}
export interface JevResponse {
  answers?: Record<string, JevAnswer | undefined>
}

export interface Verdict {
  run: boolean
  /** Shown in the permission prompt when `run` is false. */
  reason: string
}

/** Obvious secrets are masked before the command leaves the machine. */
export function redact(text: string): string {
  return text
    .replace(/(authorization:\s*(?:bearer|basic|token)\s+)[^\s'"]+/gi, "$1[REDACTED]")
    .replace(/\b((?:[A-Z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|PWD))\s*=\s*)(['"]?)[^\s'"]+\2/g, "$1$2[REDACTED]$2")
    .replace(/(?<![\w-])(--?(?:password|passwd|token|api-key|secret)[= ])(['"]?)[^\s'"]+\2/gi, "$1$2[REDACTED]$2")
    .replace(/\b(sk-[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9]{20,}|xox[abpr]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16})\b/g, "[REDACTED]")
    .replace(/(:\/\/[^\s:/@]+:)[^\s@/]+@/g, "$1[REDACTED]@")
}

/** Where a command runs. A FarHand command runs on its remote host, in the remote workdir. */
export interface Target {
  command: string
  cwd: string
  project: string
  remote?: { host: string; os?: string }
}

export function buildRequest(s: Settings, policy: Policy, t: Target): Record<string, unknown> {
  const questions: Record<string, unknown> = policy.verdict ? { verdict: VERDICT } : {}
  for (const [id, r] of Object.entries(policy.risks)) questions[id] = { type: "noul", instructions: r.question }
  const machine = t.remote
    ? {
        machine: `remote host ${t.remote.host}, reached over SSH (not the user's local computer)`,
        home_directory: "~ (the remote user's home directory)",
        platform: t.remote.os ?? "unknown",
      }
    : { machine: "the user's own local computer", home_directory: homedir(), platform: process.platform }
  return {
    model: s.model,
    state: { command: redact(t.command), working_directory: t.cwd, project_directory: t.project, ...machine },
    questions,
  }
}

export function judge(policy: Policy, res: JevResponse): Verdict {
  const a = res.answers ?? {}
  const v = a.verdict
  if (policy.verdict && (!v || (v.choice !== "run" && v.choice !== "confirm"))) return { run: false, reason: "Jev gave no verdict" }

  const flagged: string[] = []
  const ids = Object.keys(policy.risks)
  let answered = 0
  for (const id of ids) {
    const r = policy.risks[id]!
    const p = a[id]?.noul
    if (typeof p !== "number") continue
    answered++
    if (p >= r.threshold) flagged.push(`${r.label} (${p.toFixed(2)})`)
  }
  const confidence = v?.confidence ?? 0
  const pRun = v?.probabilities?.run ?? (v?.choice === "run" ? 1 : 0)
  const tag = policy.verdict ? ` [p(run)=${pRun.toFixed(2)}, confidence ${confidence.toFixed(2)}]` : ""

  if (answered < ids.length) return { run: false, reason: `Jev answered only ${answered} of ${ids.length} risk questions` }
  if (flagged.length) return { run: false, reason: `Jev: ${flagged.join("; ")}${tag}` }
  if (policy.verdict && v!.choice === "confirm") return { run: false, reason: `Jev: wants confirmation${tag}` }
  if (policy.verdict && confidence < policy.minConfidence) {
    const why = `confidence ${confidence.toFixed(2)} < ${policy.minConfidence.toFixed(2)}, p(run)=${pRun.toFixed(2)}`
    return { run: false, reason: `Jev: leans towards run, but is unsure (${why})` }
  }
  return { run: true, reason: `Jev: safe${tag}` }
}

/** Jev's answers, or why there are none. Kept apart from `judge` so a threshold change needs no new request. */
export type Asked = { ok: true; response: JevResponse } | { ok: false; reason: string }

/**
 * Statuses worth one more try: timeouts, rate limits, overload, server errors.
 * Not 403: the API's Cloudflare firewall refuses some commands by their
 * content (verified: the same request is refused every time), so a retry only
 * delays the prompt.
 */
const RETRYABLE = new Set([408, 425, 429, 500, 502, 503, 504, 520, 521, 522, 524, 529])
const USER_AGENT = "jev-guard (+https://github.com/CogFlux/opencode-jev-guard)"

/**
 * A one-line reason for a failed response. An HTML body is an edge page
 * (Cloudflare in front of the API), not an API error, so it is summarised
 * with its ray id rather than pasted into the prompt note.
 */
export function failure(status: number, headers: Headers, body: string): string {
  const html = /text\/html/i.test(headers.get("content-type") ?? "") || /^\s*</.test(body)
  if (html) {
    const edge = /cloudflare/i.test(headers.get("server") ?? "") ? "the Jev API's Cloudflare firewall" : "the network in front of the Jev API"
    const ray = headers.get("cf-ray")
    return `HTTP ${status}, blocked by ${edge}${ray ? `, ray ${ray}` : ""}`
  }
  const text = body.replace(/\s+/g, " ").trim().slice(0, 160)
  return `HTTP ${status}${text ? `: ${text}` : ""}`
}

export async function askJev(s: Settings, policy: Policy, t: Target): Promise<Asked> {
  if (!s.apiKey) {
    return { ok: false, reason: "Jev is not configured (no TYPESAFE_API_KEY or ~/.secrets/typesafe); confirm manually" }
  }
  // One deadline for both attempts, so a retry never makes the prompt wait longer than timeoutMs.
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), s.timeoutMs)
  const body = JSON.stringify(buildRequest(s, policy, t))
  let reason = ""
  try {
    for (let attempt = 1; attempt <= 2; attempt++) {
      let retryAfterMs = 400
      try {
        const res = await fetch(`${s.baseUrl}/v1/systemone`, {
          method: "POST",
          headers: { "Content-Type": "application/json", Authorization: `Bearer ${s.apiKey}`, "User-Agent": USER_AGENT },
          body,
          signal: controller.signal,
        })
        if (res.ok) return { ok: true, response: (await res.json()) as JevResponse }
        reason = failure(res.status, res.headers, await res.text().catch(() => ""))
        if (!RETRYABLE.has(res.status)) break
        const after = Number(res.headers.get("retry-after"))
        if (after > 0) retryAfterMs = after * 1000
      } catch (e) {
        if (controller.signal.aborted) {
          reason = `timed out after ${s.timeoutMs}ms`
          break
        }
        reason = e instanceof Error ? e.message : String(e)
      }
      debug({ hook: "jev", attempt, reason })
      if (attempt === 2 || retryAfterMs > 2000) break
      await new Promise((r) => setTimeout(r, retryAfterMs))
      if (controller.signal.aborted) {
        reason = `timed out after ${s.timeoutMs}ms`
        break
      }
    }
    return { ok: false, reason: `Jev unavailable (${reason}); confirm manually` }
  } finally {
    clearTimeout(timer)
  }
}

