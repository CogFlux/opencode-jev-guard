# jev-guard

An OpenCode 2 plugin that sends every shell command the agent wants to run to
[TypeSafe's Jev](https://docs.typesafe.ai/api) decision model first: local
`shell` commands, and [FarHand](#farhand)'s `farhand_remote_shell` commands on
a remote host. Jev answers six typed questions about the command:

| Question         | Asks the user when the command…                                                   |
| ---------------- | --------------------------------------------------------------------------------- |
| `verdict`        | is anything but ordinary work inside the project (`run` / `confirm`)               |
| `host_litter`    | leaves files outside the project (home dir, `/tmp`, caches, dotfiles, system paths) |
| `global_install` | installs software globally (brew, `npm -g`, pip outside a venv, `curl \| sh`, …)   |
| `global_config`  | changes global settings (`~/.zshrc`, `~/.config`, `git --global`, defaults, launchd) |
| `harmful`        | may do damage (data loss, force-push, sudo, weakening security, attacking hosts)    |
| `privacy`        | may expose private data (keys, tokens, `.env`, keychain, personal files, uploads)  |

A command counts as safe only if the verdict is `run` with confidence
≥ `minConfidence` **and** every risk is below `riskThreshold`. A safe command
keeps whatever your OpenCode `permission` config decides (set `autoAllow` to
let it run without a prompt). Anything else gets OpenCode's normal permission prompt, with Jev's reasons as the
message, e.g. `Jev: installs software globally (0.93) [p(run)=0.04, confidence 0.95]`.

If Jev cannot be reached, times out, or no API key is set, the command asks.
It never silently runs.

OpenCode 2.0.14's permission prompt does not show the reason: its body is
fixed (`$ <command>` for `shell`, `Tool: <name>` for MCP tools). So a flagged
command also puts a one-line note in the transcript, right above the prompt:

```
⚠ Jev on devbox: installs software globally (0.97) · sudo apt-get purge -y tmux
```

A prompt with no such note was asked by your OpenCode or FarHand permission
settings, not by Jev. The prompt preselects **Allow once**, so a stray Enter
approves it.

## Choosing the categories

The five categories above are built in. You can retune them, switch them off,
or add your own in a `jev-guard.jsonc`:

| File | Applies to | May |
| --- | --- | --- |
| `~/.config/opencode/jev-guard.jsonc` | every project | anything |
| `<project>/.opencode/jev-guard.jsonc` | that project | only make the guard stricter |

```jsonc
{
  "riskThreshold": 0.7,          // default for categories without their own
  "risks": {
    "host_litter": { "threshold": 0.8 },   // retune a built-in
    "global_config": false,                // switch a built-in off
    "docker": {                            // add your own
      "label": "touches Docker",
      "question": "Does this start, stop, remove or rebuild Docker containers, images, volumes or networks?",
      "threshold": 0.6
    }
  }
}
```

`jev-guard.example.jsonc` has every field with comments. A category asks when
Jev's yes-probability is at or above its `threshold`, so phrase `question`
so that "yes" means "ask me first". A new category needs a `question`; `label`
defaults to its id. Ids are lowercase letters, digits and `_`.

`verdict: false` drops Jev's overall run/confirm question, so only the
categories decide. Otherwise the overall verdict can still ask for a command
no category flags, and switching a category off does not guarantee it stops
causing prompts.

Edits apply on the next command, with no restart. `/jev risks` shows the
categories and thresholds in effect (custom ones marked `*`) and the first
problem, if any; `/jev status` says when a config has problems. A bad entry
is skipped, never fatal: the rest of the file still applies.

A project file can add categories and lower thresholds, but not switch
anything off, raise a threshold, change a category's question or label, turn
`verdict` off or `autoAllow` on. Those entries are ignored and reported. The
file lives inside the project, where writing a file looks harmless to Jev,
so without this rule an agent (or a cloned repository) could turn its own
guard off with one unflagged command. The global file is outside every
project, and changing it is itself flagged as a global setting.

`riskThreshold`, `minConfidence`, `verdict`, `autoAllow` and `risks` can also
be given as plugin options; the global file overrides them. Connection
settings (`apiKey`, `baseUrl`, `model`, `timeoutMs`) are plugin options or
environment variables only, never read from these files.

## Switching it off

In any session:

- `/jev off` — every shell command runs **without confirmation**.
- `/jev on` — back to Jev checking.
- `/jev status` (or `/jev`) — current state and pass/ask counts.
- `/jev risks` — the categories and thresholds in effect.

The switch is saved in the plugin's OpenCode storage, so it survives restarts.
`JEV_GUARD=off opencode` (or `on`) forces the starting state for one launch.

`deny` rules in your OpenCode `permission` config are final in both modes;
OpenCode never consults plugins about them. With the guard off, FarHand
commands are left to FarHand's own `[approval]` setting rather than forced
through.

## FarHand

When FarHand is active, the agent's commands run on a remote host through the
`farhand_remote_shell` MCP tool instead of `shell`. OpenCode's permission
request for an MCP tool carries no arguments, so the plugin takes the command
(and its `cwd`) from the `execute.before` hook, which OpenCode runs first.

Jev is told the command runs on the remote host, not your computer. The host,
`workdir` and `os` come from the `[remote]` table of the FarHand config, looked
up in FarHand's own order: `.farhand.toml` in the project, then
`$FARHAND_CONFIG`, then `~/.config/farhand/config.toml`. "Outside the project"
then means outside the remote workdir. A relative `cwd` resolves against it.

A command Jev finds safe keeps FarHand's decision (`auto` runs it, `ask`
prompts). Only `remote_shell` is judged; FarHand's file and transfer tools
(`remote_write`, `upload`, …) are governed by FarHand's `[approval]` setting.

## Setup

1. Put your TypeSafe key in `~/.secrets/typesafe` (or export `TYPESAFE_API_KEY`).
2. Load the plugin. Either link it into the global plugins directory:

   ```sh
   git clone https://github.com/CogFlux/opencode-jev-guard.git
   cd opencode-jev-guard
   ln -s "$PWD/jev-guard.ts" ~/.config/opencode/plugins/jev-guard.ts
   ```

   or copy it into a project's `.opencode/plugins/` to use it there only.

The file imports nothing from OpenCode, so it needs no `node_modules`.

## Options

Pass options with the object form of the `plugins` config entry:

```jsonc
{
  "plugins": [
    { "package": "/path/to/jev-guard.ts", "options": { "riskThreshold": 0.4 } }
  ]
}
```

| Option          | Default                  | Meaning                                                               |
| --------------- | ------------------------ | --------------------------------------------------------------------- |
| `enabled`       | `true`                   | Starting state when `/jev` has never been used                         |
| `apiKey`        | `$TYPESAFE_API_KEY`      | TypeSafe API key                                                       |
| `apiKeyFile`    | `~/.secrets/typesafe`    | File to read the key from when neither of the above is set             |
| `baseUrl`       | `https://api.typesafe.ai` | Also `$TYPESAFE_BASE_URL`                                             |
| `model`         | `jev-latest`             | Also `$JEV_GUARD_MODEL`; pin a version for stable behaviour            |
| `riskThreshold` | `0.7`                    | A risk at or above this asks (see [Tuning](#tuning))                   |
| `risks`         | built-in five            | Categories to retune, switch off or add (see [Choosing the categories](#choosing-the-categories)) |
| `verdict`       | `true`                   | Also ask Jev's overall run/confirm question                            |
| `minConfidence` | `0.6`                    | A `run` verdict below this confidence asks                             |
| `timeoutMs`     | `8000`                   | Jev request timeout                                                    |
| `autoAllow`     | `false`                  | `true` = safe commands skip OpenCode's `ask` rule; `false` = Jev only adds prompts |

## What leaves your machine

Each command is sent to TypeSafe with the working directory, the project
directory, your home directory path and the platform (for FarHand commands:
the remote host name, remote workdir and remote OS). Obvious secrets
(`Authorization` headers, `*_KEY=`/`*_TOKEN=` assignments, `--password=`
flags, `sk-…`/`ghp_…`/`AKIA…` tokens, URL credentials) are masked first. This
is best-effort; a secret in an unusual shape is sent as-is.

Verdicts are cached in memory per exact command and directory for the
session; errors are not cached.

## Scope

Only `shell` and `farhand_remote_shell` are gated. File edits go through OpenCode's own
`edit` / `external_directory` permissions, and Code Mode's `execute` tool and
MCP tools are not inspected.

## Tuning

`bench/cases.jsonl` holds commands labelled `run` or `ask`, local and FarHand.
`node bench/run.ts` scores them with the real Jev API (it needs the key) and
lists every disagreement. It uses your global `jev-guard.jsonc`, if any. On the current set, commands that should run peak at
a risk of 0.62 and commands that should ask start at 0.75, hence the 0.7
default; 0.5 asked for `npm install lodash`, `pytest` and read-only checks
like `tmux ls`. Add a case whenever Jev gets one wrong, then rerun.

## License

MIT

## Tests

```sh
npm test   # node --test, with a fake OpenCode context and a fake Jev API
```
