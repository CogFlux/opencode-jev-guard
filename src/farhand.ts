// Which tools run shell commands, and where FarHand runs them.

import { readFileSync } from "node:fs"
import { homedir } from "node:os"
import { join } from "node:path"
import { expandHome } from "./config.ts"

export const SHELL_TOOLS = new Set(["shell", "bash"])
/** FarHand's MCP tool. Its permission request carries no command, only `["*"]`. */
export const REMOTE_SHELL_TOOL = "farhand_remote_shell"

export interface FarHandRemote {
  host: string
  workdir: string
  os?: string
}

/**
 * The `[remote]` table of the FarHand config this session uses: the project's
 * `.farhand.toml` first, then FARHAND_CONFIG, then the global config -- the
 * order FarHand itself uses. Only `host`, `workdir` and `os` are read, and
 * only to tell Jev where the command runs.
 */
export function farhandRemote(dirs: string[]): FarHandRemote | undefined {
  const candidates = [
    ...dirs.map((d) => join(d, ".farhand.toml")),
    ...(process.env.FARHAND_CONFIG ? [expandHome(process.env.FARHAND_CONFIG)] : []),
    join(process.env.XDG_CONFIG_HOME || join(homedir(), ".config"), "farhand", "config.toml"),
  ]
  for (const file of candidates) {
    let text: string
    try {
      text = readFileSync(file, "utf8")
    } catch {
      continue
    }
    const remote: Record<string, string> = {}
    let section = ""
    for (const raw of text.split(/\r?\n/)) {
      const line = raw.replace(/^\s+/, "")
      const header = /^\[([^\]]+)\]/.exec(line)
      if (header) {
        section = header[1]!.trim()
        continue
      }
      const kv = /^(host|workdir|os)\s*=\s*(?:"([^"]*)"|'([^']*)')/.exec(line)
      if (section === "remote" && kv) remote[kv[1]!] = kv[2] ?? kv[3] ?? ""
    }
    if (remote.host) {
      const os = remote.os && remote.os !== "auto" ? remote.os : undefined
      return { host: remote.host, workdir: remote.workdir || "~", os }
    }
  }
  return undefined
}
