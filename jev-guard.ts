/**
 * jev-guard — an OpenCode 2 plugin that sends every shell command the agent
 * wants to run through TypeSafe's Jev decision model before it runs: local
 * `shell` commands, and FarHand's `farhand_remote_shell` commands on a remote
 * host.
 *
 * Jev is asked whether the command
 *   - leaves files on the host outside the project (caches, dotfiles, /tmp, ...)
 *   - installs software globally (brew, npm -g, pip outside a venv, curl | sh, ...)
 *   - changes global settings (shell rc files, ~/.config, git --global, defaults, launchd, ...)
 *   - is harmful (data loss, weakening security, running downloaded code, attacking hosts)
 *   - exposes private data (keys, tokens, password stores, personal files, sending data out)
 * and whether it can run unattended. Anything flagged becomes a permission
 * prompt with Jev's reasons; everything else keeps OpenCode's own permission
 * decision (or runs without asking, with the `autoAllow` option).
 *
 * The risk categories and their thresholds are configurable: built-in ones
 * can be retuned or switched off and new ones added, in `jev-guard.jsonc`
 * (see README.md). `/jev risks` shows what is in effect.
 *
 * The switch is per session: `/jev off` turns it off in that session only
 * (commands then follow your own OpenCode and FarHand permission settings,
 * untouched), `/jev on` back on, `/jev default on|off` sets it for sessions
 * without their own setting, `/jev status` shows it. Settings survive
 * restarts. `JEV_GUARD=off opencode` makes the default off for one launch.
 *
 * Explicit `deny` rules in your OpenCode config are final: OpenCode never asks
 * this plugin about them, in either mode.
 *
 * Nothing is imported from OpenCode, so the plugin loads without a
 * node_modules. The code is in src/: config (options), questions (what Jev is
 * asked), policy (categories and thresholds), jev (the API client and the
 * verdict), farhand (remote commands), log (diagnostics), plugin (the hooks
 * and /jev). Installed through a symlink to this file, the relative imports
 * still resolve: OpenCode's Bun follows the link to the repository first.
 */

import { setup } from "./src/plugin.ts"

export default {
  id: "jev-guard",
  setup,
}
