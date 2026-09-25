// Opt-in diagnostics.

import { appendFileSync, existsSync, realpathSync } from "node:fs"
import { dirname, join } from "node:path"
import { fileURLToPath } from "node:url"

/**
 * Diagnostics: when a `jev-guard.log` file exists next to the real plugin file
 * (`touch jev-guard.log` in this repo), every hook call is appended to it as
 * one JSON line. Delete the file to stop. Commands are logged after redaction.
 */
export const LOG_FILE = (() => {
  try {
    // This file lives in src/; the log sits at the repository root, next to jev-guard.ts.
    return join(dirname(dirname(realpathSync(fileURLToPath(import.meta.url)))), "jev-guard.log")
  } catch {
    return undefined
  }
})()

export function debug(entry: Record<string, unknown>): void {
  if (!LOG_FILE || !existsSync(LOG_FILE)) return
  try {
    appendFileSync(LOG_FILE, JSON.stringify({ time: new Date().toISOString(), pid: process.pid, ...entry }) + "\n")
  } catch {
    /* diagnostics never break a command */
  }
}

