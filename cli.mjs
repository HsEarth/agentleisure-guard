#!/usr/bin/env node
// agentleisure-guard command line.
//   agentleisure-guard mcp [options] -- <command> [args...]   guard any stdio MCP server
//   agentleisure-guard mcp [options] --url <https url>         guard a remote (Streamable HTTP) MCP server
//   agentleisure-guard check <tool> <args-json>                 classify one tool call locally
//   agentleisure-guard scan <file|->                            scan untrusted text for prompt injection
//   agentleisure-guard test [--agent claude|codex|cursor]       replay real agent incidents against your setup
//   agentleisure-guard blast [--fix] [--json]                   what your agent can break on this machine right now
//   agentleisure-guard hook                                     Claude Code PreToolUse hook (local rules)
import { readFileSync } from "node:fs";
import { classifyCall, scanUntrusted } from "./agent-guard.mjs";
import { runMcpGuard, runMcpGuardRemote } from "./mcp-guard.mjs";
import { DEFAULT_SNAPSHOT_DIR, listSnapshots, restoreSnapshot } from "./snapshots.mjs";
import { runReplay } from "./replay.mjs";
import { runBlast } from "./blast.mjs";
import { runHook } from "./hook.mjs";
import { POLICY_FILE, describeRules, findPolicy, loadPolicy, validatePolicy, writePolicyTemplate } from "./policy.mjs";

const HELP = `agentleisure-guard: hard limits for AI agent tools

  agentleisure-guard mcp [options] -- <command> [args...]
  agentleisure-guard mcp [options] --url <https://remote-server/mcp>
      Run an MCP server behind the guard. Put this in your MCP client config instead of the server command.
      Options:
        --url <url>          guard a remote MCP server (Streamable HTTP) instead of starting a local one
        --header "N: v"      extra header for the remote server (repeatable)
        --bearer-env <VAR>   send "Authorization: Bearer <value of VAR>" to the remote server
        --remember-approval <minutes>  after a human approves a call, let the exact same call through for this long
        --journal <file>     append a hash-chained JSON line per call (verify at agentleisure.com/safety/journal)
        --ask block|allow    what to do with destructive calls when no approver is set (default: block)
        --loop-limit <n>     refuse a call repeated more than n times in 5 minutes (default 10, 0 = off)
        --no-scan            do not scan tool results and tool descriptions
        --no-taint           do not require approval for outbound calls after a result tried to instruct the agent
        --snapshots <dir>    where to keep copies of files before a call changes them (default ~/.agentleisure/snapshots)
        --no-snapshot        do not copy files before a call changes them
        --policy <file>      project rules (default: agentleisure.policy.json in the working directory)
        --observe            block nothing; log what would be stopped and print a summary on exit
        --no-agent-tools     do not add agentleisure_policy and agentleisure_ask_human to the server's tools
      Environment:
        AGENTLEISURE_KEY        agent key from agentleisure.com/console: destructive calls wait for one-click approval
        AGENTLEISURE_NOTIFY_URL Slack or Discord webhook that receives the approval link

  agentleisure-guard test [--agent claude|codex|cursor] [-- extra agent args]
      Crash-test YOUR agent and settings: 6 traps rebuilt from real incidents, in a throwaway repo.
      Run "agentleisure-guard test --help" for options.

  agentleisure-guard blast [--json] [--fix] [--publish "<setup name>"]
      What your agent can break on this machine right now, with fixes. Secrets never leave the machine.
      Run "agentleisure-guard blast --help" for options.

  agentleisure-guard hook
      Claude Code PreToolUse hook: destructive commands ask first, secret uploads are refused. Local rules.

  agentleisure-guard check <tool> '<json args>'
  agentleisure-guard scan <file>    (use - for stdin)
  agentleisure-guard undo [id] [--snapshots <dir>]   list snapshots, or restore one
  agentleisure-guard policy init|check [file]       create or validate agentleisure.policy.json
`;

const [command, ...rest] = process.argv.slice(2);

if (command === "mcp") {
  const split = rest.indexOf("--");
  // Without "--", a leading non-flag word starts the server command (older usage); otherwise everything is flags.
  const bareCommand = split < 0 && rest.length > 0 && !rest[0].startsWith("--");
  const flags = split >= 0 ? rest.slice(0, split) : bareCommand ? [] : rest;
  const target = split >= 0 ? rest.slice(split + 1) : bareCommand ? rest : [];
  const options = { askMode: "block", loopLimit: 10, scan: true, journal: null, rememberApprovalMs: 0, headers: {} };
  let url = null;
  for (let index = 0; index < flags.length; index++) {
    const flag = flags[index];
    if (flag === "--journal") options.journal = flags[++index];
    else if (flag === "--ask") options.askMode = flags[++index] === "allow" ? "allow" : "block";
    else if (flag === "--loop-limit") options.loopLimit = Math.max(0, Number(flags[++index]) || 0);
    else if (flag === "--no-scan") options.scan = false;
    else if (flag === "--no-taint") options.taint = false;
    else if (flag === "--no-snapshot") options.snapshots = false;
    else if (flag === "--policy") options.policyPath = flags[++index];
    else if (flag === "--observe") options.observeFlag = true;
    else if (flag === "--no-agent-tools") options.agentTools = false;
    else if (flag === "--snapshots") options.snapshotDir = flags[++index];
    else if (flag === "--remember-approval") options.rememberApprovalMs = Math.max(0, Number(flags[++index]) || 0) * 60_000;
    else if (flag === "--url") url = flags[++index];
    else if (flag === "--header") {
      const raw = flags[++index] ?? ""; const colon = raw.indexOf(":");
      if (colon <= 0) { process.stderr.write(`--header needs "Name: value"
`); process.exit(2); }
      options.headers[raw.slice(0, colon).trim()] = raw.slice(colon + 1).trim();
    } else if (flag === "--bearer-env") {
      const name = flags[++index]; const value = name ? process.env[name] : undefined;
      if (!value) { process.stderr.write(`--bearer-env: environment variable ${name} is not set
`); process.exit(2); }
      options.headers.Authorization = `Bearer ${value}`;
    } else { process.stderr.write(`unknown option ${flag}
${HELP}`); process.exit(2); }
  }
  // Project policy: --policy <file>, or agentleisure.policy.json in the working directory.
  const policyPath = options.policyPath ?? findPolicy();
  if (policyPath) {
    try { options.policy = loadPolicy(policyPath); }
    catch (error) { process.stderr.write(`[agentleisure-guard] policy error: ${error instanceof Error ? error.message : error}\n`); process.exit(2); }
    if (options.policy.loop_limit !== undefined && !flags.includes("--loop-limit")) options.loopLimit = options.policy.loop_limit;
    if (options.policy.remember_approval_minutes !== undefined && !flags.includes("--remember-approval")) options.rememberApprovalMs = options.policy.remember_approval_minutes * 60_000;
    process.stderr.write(`[agentleisure-guard] policy: ${policyPath}\n`);
  }
  options.observe = options.observeFlag === true || options.policy?.observe === true;
  if (options.observe) process.stderr.write("[agentleisure-guard] observe mode: nothing is blocked; calls that would be stopped are logged and summarised on exit\n");
  if (url) {
    try { runMcpGuardRemote(url, options); } catch (error) { process.stderr.write(`${error instanceof Error ? error.message : error}
`); process.exit(2); }
  } else if (target.length) runMcpGuard(target[0], target.slice(1), options);
  else { process.stderr.write(HELP); process.exit(2); }
} else if (command === "policy") {
  const [action = "check", file = POLICY_FILE] = rest;
  if (action === "init") {
    try { writePolicyTemplate(file); process.stdout.write(`Created ${file}. Edit it, commit it, and the gateway picks it up from the working directory.\n`); }
    catch (error) { process.stderr.write(`${error instanceof Error ? error.message : error}\n`); process.exitCode = 1; }
  } else if (action === "check") {
    try {
      const { errors } = validatePolicy(JSON.parse(readFileSync(file, "utf8")));
      if (errors.length) { process.stderr.write(`${file}:\n${errors.map(error => `  - ${error}`).join("\n")}\n`); process.exitCode = 1; }
      else process.stdout.write(`${file} is valid.\n\n${describeRules(loadPolicy(file), { approver: Boolean(process.env.AGENTLEISURE_KEY) })}\n`);
    } catch (error) { process.stderr.write(`${file}: ${error instanceof Error ? error.message : error}\n`); process.exitCode = 1; }
  } else { process.stderr.write("usage: agentleisure-guard policy init|check [file]\n"); process.exitCode = 2; }
} else if (command === "undo") {
  const dirFlag = rest.indexOf("--snapshots");
  const dir = dirFlag >= 0 ? rest[dirFlag + 1] : DEFAULT_SNAPSHOT_DIR;
  const id = rest.find((word, index) => !word.startsWith("--") && index !== dirFlag + 1);
  if (!id) {
    const list = listSnapshots(dir).slice(0, 20);
    if (!list.length) process.stdout.write(`No snapshots in ${dir}
`);
    for (const item of list) process.stdout.write(`${item.id}  ${item.ts}  ${item.tool}  ${item.items.map(entry => entry.original).join(", ")}
`);
  } else {
    try {
      const result = restoreSnapshot(id, dir);
      process.stdout.write(`Restored: ${result.restored.join(", ")}${result.previous ? `
The state before this restore is saved as ${result.previous}` : ""}
`);
    } catch (error) { process.stderr.write(`${error instanceof Error ? error.message : error}
`); process.exitCode = 1; }
  }
} else if (command === "blast") {
  process.exitCode = await runBlast(rest);
} else if (command === "hook") {
  process.exitCode = await runHook();
} else if (command === "test") {
  process.exitCode = await runReplay(rest);
} else if (command === "check") {
  const [tool, raw = "{}"] = rest;
  let args = raw;
  try { args = JSON.parse(raw); } catch { /* plain text arguments */ }
  process.stdout.write(`${JSON.stringify(classifyCall({ tool, args }), null, 2)}\n`);
} else if (command === "scan") {
  const source = rest[0] ?? "-";
  const text = readFileSync(source === "-" ? 0 : source, "utf8");
  const result = scanUntrusted(text);
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  process.exitCode = result.risk === "high" ? 2 : result.risk === "medium" ? 1 : 0;
} else {
  process.stdout.write(HELP);
  process.exitCode = command && command !== "help" && command !== "--help" ? 2 : 0;
}
