// Plugin options and connection settings.

import { readFileSync } from "node:fs"
import { homedir } from "node:os"

export interface Options {
  /** Initial state when nothing was saved by `/jev` yet. Default true. */
  enabled?: boolean
  /** TypeSafe API key. Prefer `apiKeyFile` or the TYPESAFE_API_KEY env var. */
  apiKey?: string
  /** File holding the API key. Default ~/.secrets/typesafe. */
  apiKeyFile?: string
  baseUrl?: string
  model?: string
  /**
   * A risk question at or above this probability asks the user. Default 0.7:
   * on bench/cases.jsonl, commands that should run peak at 0.62 and commands
   * that should ask start at 0.75.
   */
  riskThreshold?: number
  /** Below this confidence, Jev's "run" verdict still asks the user. Default 0.6. */
  minConfidence?: number
  timeoutMs?: number
  /**
   * When Jev finds a command safe, run it without a prompt even if your
   * OpenCode config says `ask` for shell. Default false: safe commands keep
   * OpenCode's own decision and Jev can only add prompts.
   */
  autoAllow?: boolean
  /**
   * Also ask Jev's overall run/confirm question. Default true. With false,
   * only the risk categories decide, so switching one off really stops it
   * from causing prompts.
   */
  verdict?: boolean
  /** Risk categories: see `RiskConfig` and README.md. */
  risks?: Record<string, RiskConfig | false>
}

/**
 * One risk category in a config: a built-in id to retune (any field may be
 * left out), `false` to switch a built-in off, or a new id, which needs a
 * `question`.
 */
export interface RiskConfig {
  /** Shown in the prompt note, e.g. "touches Docker". Default: the id. */
  label?: string
  /** A yes/no question about the command; yes means it should ask. */
  question?: string
  /** Asks when Jev's yes-probability is at or above this. Default: `riskThreshold`. */
  threshold?: number
}

/** Connection settings. They come from plugin options and env only, never from a jev-guard.jsonc file. */
export interface Settings {
  apiKey?: string
  baseUrl: string
  model: string
  timeoutMs: number
}

export function expandHome(p: string): string {
  return p === "~" || p.startsWith("~/") ? homedir() + p.slice(1) : p
}

export function readKeyFile(path: string): string | undefined {
  try {
    return readFileSync(expandHome(path), "utf8").trim() || undefined
  } catch {
    return undefined
  }
}

export function settingsFrom(options: Options): Settings {
  return {
    apiKey:
      options.apiKey ??
      process.env.TYPESAFE_API_KEY ??
      readKeyFile(options.apiKeyFile ?? "~/.secrets/typesafe"),
    baseUrl: (options.baseUrl ?? process.env.TYPESAFE_BASE_URL ?? "https://api.typesafe.ai").replace(/\/+$/, ""),
    model: options.model ?? process.env.JEV_GUARD_MODEL ?? "jev-latest",
    timeoutMs: options.timeoutMs ?? 8000,
  }
}

