// Opt-in diagnostics.

import { appendFileSync, existsSync, realpathSync } from "node:fs"
import { basename, dirname, join } from "node:path"
import { fileURLToPath } from "node:url"

/**
 * Diagnostics: when a `jev-guard.log` file exists next to the plugin file
 * (`touch jev-guard.log` in this repo, or next to the installed bundle),
 * every hook call is appended to it as one JSON line. Delete the file to
 * stop. Commands are logged after redaction.
 */
export const LOG_FILE = (() => {
  try {
    // From the repository this file is src/log.ts and the log sits at the root,
    // next to jev-guard.ts; in the bundle it sits next to the bundle.
    const dir = dirname(realpathSync(fileURLToPath(import.meta.url)))
    return join(basename(dir) === "src" ? dirname(dir) : dir, "jev-guard.log")
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

