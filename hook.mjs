// `agentleisure-guard hook`: a Claude Code PreToolUse hook. Same rules as POST /api/guard/check, evaluated locally,
// so the commands your agent runs (which often contain secrets) never leave the machine.
//   .claude/settings.json: { "hooks": { "PreToolUse": [ { "matcher": "Bash|Write|Edit|WebFetch",
//     "hooks": [ { "type": "command", "command": "npx -y agentleisure-guard hook" } ] } ] } }
import { DEFAULT_DESTRUCTIVE, KEY_SHAPES, NETWORK_COMMAND, SECRET_ACCESS, SECRET_FILES, scanText } from "./agent-guard.mjs";

export function decideHook(event) {
  const tool = String(event?.tool_name ?? "");
  const body = scanText(event?.tool_input ?? {});
  const hasKey = KEY_SHAPES.some(shape => { shape.lastIndex = 0; return shape.test(body); });
  const network = tool === "WebFetch" || NETWORK_COMMAND.test(body);
  if (network && (hasKey || SECRET_FILES.test(body)))
    return { decision: "deny", reason: "agentleisure-guard: this would send secrets (keys, .env, private keys) over the network. Summarize for the user instead." };
  if (DEFAULT_DESTRUCTIVE.some(pattern => pattern.test(body)))
    return { decision: "ask", reason: "agentleisure-guard: destructive or irreversible command. A human must confirm it." };
  if (SECRET_ACCESS.test(body))
    return { decision: "ask", reason: "agentleisure-guard: this opens a credential file (.env, SSH key, cloud credentials). A human must confirm it." };
  return { decision: "allow", reason: "" };
}

export async function runHook() {
  let raw = "";
  for await (const chunk of process.stdin) { raw += chunk; if (raw.length > 1_000_000) break; }
  let event = {};
  try { event = JSON.parse(raw); } catch { return 0; }
  const { decision, reason } = decideHook(event);
  if (decision !== "allow")
    process.stdout.write(JSON.stringify({ hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: decision, permissionDecisionReason: reason } }));
  return 0;
}
