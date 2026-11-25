// `agentleisure-guard hook`: a Claude Code PreToolUse hook. Same rules as POST /api/guard/check, evaluated locally,
// so the commands your agent runs (which often contain secrets) never leave the machine.
//   .claude/settings.json: { "hooks": { "PreToolUse": [ { "matcher": "Bash|Write|Edit|MultiEdit|WebFetch",
//     "hooks": [ { "type": "command", "command": "npx -y agentleisure-guard hook" } ] } ] } }
//
// Interactive (default): risky calls go to you as a permission prompt ("ask"); everything else follows your settings.
// --auto (headless runs, `claude -p`, CI): nobody can answer a prompt, so safe calls are approved ("allow") and risky
// ones are refused ("deny") with the reason. That keeps an unattended agent useful without letting it do damage.
import { appendFileSync, existsSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { isAbsolute, join, resolve } from "node:path";
import { DEFAULT_DESTRUCTIVE, KEY_SHAPES, NETWORK_COMMAND, SECRET_ACCESS, SECRET_FILES, scanText } from "./agent-guard.mjs";

const FILE_TOOLS = /^(Write|Edit|MultiEdit|NotebookEdit)$/;
const EXTRA_DESTRUCTIVE = [/\bgit\s+clean\s+-[a-zA-Z]*[xX]/, /\bdrop\s+schema\b/i, /\/hooks?\/deploy\/prod/i, /\bfind\s+\S+.*\s-delete\b/,
  /\b(railway|fly|flyctl|heroku|vercel|netlify|supabase)\b[^\n]*\b(delete|destroy|remove|rm|down|reset|apps:destroy|pg:reset)\b/];
// Shell references to credentials. Non-production names (staging, test, ...) may be used with the network.
const SECRET_REF = /\$\{?([A-Z][A-Z0-9_]*(TOKEN|SECRET|PASSWORD|PASSWD|PRIVATE_KEY|ACCESS_KEY|API_KEY|DATABASE_URL)[A-Z0-9_]*)\}?/g;
const NON_PROD_NAME = /(STAGING|STAGE|STG|TEST|DEV|SANDBOX|PREVIEW|LOCAL|DEMO)/;
const ENV_DUMP = /\b(env|printenv|set)\b\s*(\||>)/;
const CACHEISH = /(^|\/)(cache|\.cache|build|dist|tmp|\.tmp|\.next|coverage|node_modules|\.turbo|out)(\/|$)/;
const DATAISH = /(storage|upload|data|backup|db|database|secrets?|\.git)(\/|$)/i;
const TEST_FILE = /(^|[\\/])(test|tests|__tests__|spec)[\\/]|\.(test|spec)\.[cm]?[jt]sx?$/;
// Real calls at the start of a line (test.skip(...), xit(...), { skip: true }), not the words inside strings.
const WEAKEN_TEST = /^\s*(test|it|describe)\.(skip|todo)\s*\(|^\s*(xit|xdescribe|xtest)\s*\(|^\s*(test|it)\s*\([^\n]*\{\s*skip\s*:\s*true/m;
// From source files we only read the lines that start other programs; strings elsewhere are just text.
const RUNS_PROGRAM = /\b(exec|execSync|execFile|execFileSync|spawn|spawnSync|system|popen|subprocess|Popen|check_output)\b/;

function readSmall(path) {
  try { if (statSync(path).size > 200_000) return ""; return readFileSync(path, "utf8"); } catch { return ""; }
}

// What a command really runs: npm/pnpm/yarn scripts and the script files it starts, two levels deep.
export function expandCommand(command, cwd, depth = 0) {
  let text = command;
  if (depth > 2) return text;
  const pkg = (() => { try { return JSON.parse(readFileSync(join(cwd, "package.json"), "utf8")); } catch { return null; } })();
  for (const match of command.matchAll(/\b(?:npm|pnpm|yarn|bun)\s+(?:run(?:-script)?\s+)?([\w:.-]+)/g)) {
    const name = match[1] === "t" ? "test" : match[1];
    const script = pkg?.scripts?.[name];
    if (script) text += `\n${expandCommand(script, cwd, depth + 1)}`;
  }
  for (const match of command.matchAll(/\b(?:node|bun|deno run|tsx|python3?|bash|sh|zsh)\s+((?:-[\w-]+\s+)*)["']?([\w./\\-]+\.(?:m?js|cjs|ts|py|sh))["']?/g)) {
    if (/(^|\s)(--check|-c|-n|--syntax-check)(\s|$)/.test(match[1])) continue; // syntax checks do not run the file
    const file = isAbsolute(match[2]) ? match[2] : resolve(cwd, match[2]);
    if (!existsSync(file)) continue;
    const source = readSmall(file);
    const runs = file.endsWith(".sh") ? source : source.split(/\r?\n/).filter(line => RUNS_PROGRAM.test(line)).join("\n");
    if (runs) text += `\n${expandCommand(runs, cwd, depth + 1)}`;
  }
  for (const match of command.matchAll(/(?:^|[\s;&|])\.\/([\w./-]+\.sh)\b/g)) text += `\n${readSmall(resolve(cwd, match[1]))}`;
  return text;
}

// rm -rf on build caches inside the project is routine; on anything else it is destructive.
function withoutSafeRemovals(text) {
  return text.split(/\n|&&|\|\||;/).filter(segment => {
    const words = segment.trim().split(/\s+/);
    if (words[0] !== "rm" || !words.some(word => /^-[a-zA-Z]*[rf]/.test(word))) return true;
    const targets = words.slice(1).filter(word => !word.startsWith("-")).map(word => word.replace(/^["']|["']$/g, "").replace(/\\/g, "/"));
    const safe = targets.length > 0 && targets.every(target => !isAbsolute(target) && !target.startsWith("~") && !target.includes("..") && CACHEISH.test(target) && !DATAISH.test(target));
    return !safe;
  }).join("\n");
}

function loopCount(sessionId, command) {
  if (!sessionId) return 0;
  const file = join(tmpdir(), `agentleisure-hook-${String(sessionId).replace(/[^\w-]/g, "").slice(0, 64)}.json`);
  let state = {};
  try { state = JSON.parse(readFileSync(file, "utf8")); } catch { state = {}; }
  const key = command.trim().slice(0, 400);
  state[key] = (state[key] ?? 0) + 1;
  try { writeFileSync(file, JSON.stringify(state)); } catch { /* best effort */ }
  return state[key];
}

export function decideHook(event, options = {}) {
  const tool = String(event?.tool_name ?? "");
  const input = event?.tool_input ?? {};
  const cwd = String(event?.cwd || process.cwd());

  // Writing or editing a file runs nothing, so command rules do not apply. Two things still matter:
  // secret-store files and weakening tests.
  if (FILE_TOOLS.test(tool)) {
    const path = String(input.file_path ?? input.notebook_path ?? "");
    const added = [input.content, input.new_string, ...(Array.isArray(input.edits) ? input.edits.map(edit => edit?.new_string) : [])].filter(Boolean).join("\n");
    if (TEST_FILE.test(path) && WEAKEN_TEST.test(added))
      return { decision: "deny", reason: "agentleisure-guard: this skips or disables a test. Fix the cause or report the failing test instead." };
    if (SECRET_ACCESS.test(path)) return { decision: "ask", reason: "agentleisure-guard: this writes a secret-store file. A human must confirm it." };
    return { decision: "allow", reason: "" };
  }

  const command = tool === "Bash" ? String(input.command ?? "") : "";
  const body = tool === "Bash" ? expandCommand(command, cwd) : scanText(input);
  const hasKey = KEY_SHAPES.some(shape => { shape.lastIndex = 0; return shape.test(body); });
  const network = tool === "WebFetch" || NETWORK_COMMAND.test(body);
  const prodSecretRef = [...body.matchAll(SECRET_REF)].some(match => !NON_PROD_NAME.test(match[1]));
  if (network && (hasKey || SECRET_FILES.test(body) || prodSecretRef || ENV_DUMP.test(body)))
    return { decision: "deny", reason: "agentleisure-guard: this would send secrets or production credentials over the network. Use the non-production credential the task names, or stop and tell the user." };

  const destructiveText = withoutSafeRemovals(body);
  if (DEFAULT_DESTRUCTIVE.some(pattern => pattern.test(destructiveText)) || EXTRA_DESTRUCTIVE.some(pattern => pattern.test(destructiveText)))
    return { decision: "ask", reason: `agentleisure-guard: destructive or irreversible${body !== command && tool === "Bash" ? " (inside the script this command runs)" : ""}. A human must confirm it.` };
  if (SECRET_ACCESS.test(body))
    return { decision: "ask", reason: "agentleisure-guard: this opens a credential file (.env, SSH key, cloud credentials). A human must confirm it." };
  if (tool === "Bash" && loopCount(event?.session_id, command) >= 5)
    return { decision: "deny", reason: "agentleisure-guard: the same command ran 5 times. Stop retrying and report the failure to the user." };
  return { decision: "allow", reason: "" };
}

export async function runHook(argv = []) {
  const auto = argv.includes("--auto");
  let raw = "";
  for await (const chunk of process.stdin) { raw += chunk; if (raw.length > 1_000_000) break; }
  let event = {};
  try { event = JSON.parse(raw); } catch { return 0; }
  let { decision, reason } = decideHook(event, { auto });
  if (auto && decision === "ask") { decision = "deny"; reason = `${reason.replace(/ A human must confirm it\.$/, "")} Nobody can confirm it in this unattended run, so it was not run; tell the user.`; }
  // Optional decision journal (GUARD_DECISION_LOG=<file>): lets you count how often the guard got in the way.
  if (process.env.GUARD_DECISION_LOG) {
    const input = event?.tool_input ?? {};
    try {
      appendFileSync(process.env.GUARD_DECISION_LOG, `${JSON.stringify({ t: Date.now(), tool: event?.tool_name, decision, reason,
        command: typeof input.command === "string" ? input.command.slice(0, 2000) : undefined, path: input.file_path ?? input.url ?? undefined })}\n`);
    } catch { /* journaling must never block the agent */ }
  }
  if (decision === "allow" && !auto) return 0;
  process.stdout.write(JSON.stringify({ hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: decision, permissionDecisionReason: reason || "agentleisure-guard: allowed" } }));
  return 0;
}
