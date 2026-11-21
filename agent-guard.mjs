// AgentLeisure agent-guard: hard limits and a tamper-evident journal around an agent's tools.
// Enforced in code instead of the prompt. Node 18+, no dependencies. MIT licensed. https://agentleisure.com/safety/fix
//
//   import { createGuard } from "./agent-guard.mjs";
//   const guard = createGuard({
//     approve: async call => askHumanInSlack(call),          // human sign-off for destructive calls
//     budgetUsd: 5, maxFailures: 2,                            // spend cap and loop breaker
//     secretValues: [process.env.OPENAI_API_KEY],              // never sent over the network, never logged
//     // opening .env, SSH keys or cloud credentials also needs approve(); allowSecretAccess: true turns that off
//     permissions: { run_sql: { deny: [/production/i] }, http_post: { allow: [/^https:\/\/api\.example\.com\//] } },
//     journal: line => fs.appendFileSync("agent-journal.jsonl", line + "\n"),
//   });
//   const runSql = guard.wrap("run_sql", realRunSql);
//   const httpPost = guard.wrap("http_post", realPost, { network: true, costUsd: 0.01 });
//
// Checks on every wrapped call, in order: permissions -> secrets -> loop breaker -> budget -> approval.
// A refusal throws GuardError with a code, so the agent gets a clear, final "no".
// Every call (ok, error or refused) is written to the journal as a hash-chained JSON line; verify it at
// https://agentleisure.com/safety/journal or with verifyJournal() below.

import { createHash } from "node:crypto";

export class GuardError extends Error {
  constructor(code, message) { super(message); this.name = "GuardError"; this.code = code; }
}

// Matched anywhere in the call, case-insensitively, so chained (&&, ;, |) and multi-line commands are covered too.
export const DEFAULT_DESTRUCTIVE = [
  /\bdrop\s+(database|schema|table)\b/i, /\btruncate\b/i, /\bdelete\s+from\s+\w+\s*(;|$|")/i,
  /\brm\s+(-[a-z]*\s+)*-[a-z]*r/i, /\brm\s+.*--recursive\b/i, /\bformat\s+[a-z]:/i, /\bmkfs(\.\w+)?\b/i, /\bdd\s+if=/i,
  /\bgit\s+push\b.*(--force|-f\b)/i, /\bgit\s+reset\s+--hard\b/i, /\bgit\s+clean\s+-[a-z]*f/i, /\bgit\s+branch\s+-D\b/,
  /\bfind\b.*\s-delete\b/i, /\bchmod\s+-R\s+777\b/i, /\bkubectl\s+delete\b/i, /\bdocker\s+(system|volume)\s+prune\b/i,
  /\baws\s+s3\s+(rm|rb)\b/i, /\bdelete\b.*\bbackups?\b/i, /\bdestroy\b/i, /\bterraform\s+destroy\b/i,
  // Running code fetched from the internet.
  /\b(curl|wget)\b[^\n|]*\|\s*(sudo\s+)?(ba|z|da)?sh\b/i, /\b(iwr|irm|invoke-webrequest|invoke-restmethod)\b[^\n|]*\|\s*(iex|invoke-expression)\b/i,
  // Windows and PowerShell deletes.
  /\bremove-item\b[^\n]*-recurse\b/i, /\b(rd|rmdir)\s+\/s\b/i, /\bdel\s+(\/[a-z]\s+)*\/s\b/i,
  // SQL that rewrites or removes a whole table, or drops part of a schema.
  /\b(update\s+\w+\s+set\b(?![\s\S]*\bwhere\b)|delete\s+from\s+\w+\s*$)/im, /\balter\s+table\b[^;]*\bdrop\b/i,
  // Resetting databases and deleting cloud resources.
  /\b(prisma\s+migrate|supabase\s+db|rails\s+db:|rake\s+db:)\s*(reset|drop)\b/i, /\b(gcloud|az)\b[^\n]*\s(delete|purge)\b/i,
  /\baws\s+\S+\s+(delete-\S+|terminate-instances)\b/i,
  // Deleting repositories, remote branches and published packages.
  /\bgh\s+repo\s+delete\b/i, /\bgit\s+push\b[^\n]*(\s--delete\b|\s:\S)/i, /\bnpm\s+unpublish\b/i,
  // Deleting through an API: HTTP DELETE requests and GraphQL mutations that delete, destroy, drop or purge.
  /(-X\s*DELETE\b|--request\s+DELETE\b|\bmethod:\s*["']?DELETE\b|^DELETE\s+https?:\/\/)/im,
  /\bmutation\b[\s\S]{0,300}?\b\w*(delete|destroy|drop|purge|wipe)\w*\s*\(/i,
];
// Opening credential files at all (not just sending them): agents have found infrastructure tokens in unrelated files
// and used them to delete production. Templates such as .env.example do not match.
export const SECRET_ACCESS = /(^|[\s"'`=:(/\\])(\.env(\.(local|production|prod|development|dev|staging|test))?|\.envrc|id_rsa|id_ed25519|id_ecdsa|[\w.-]*\.(pem|p12|pfx)|\.aws[/\\]credentials|\.npmrc|\.netrc|\.pgpass|\.git-credentials|\.docker[/\\]config\.json|application_default_credentials\.json|\.kube[/\\]config|kubeconfig|secrets?\.(json|ya?ml)|[\w.-]*service[-_]?account[\w.-]*\.json)(?![\w.-])/im;
export const NETWORK_COMMAND =/\b(curl|wget|nc|ncat|scp|rsync|sftp|ftp|telnet|invoke-webrequest|iwr)\b/i;
export const SECRET_FILES = /(\.env\b|id_rsa|id_ed25519|\.pem\b|credentials\b|\.npmrc|\.netrc|secrets?\.(json|ya?ml))/i;
export const KEY_SHAPES = [/\bsk-[A-Za-z0-9_-]{16,}/g, /\bAKIA[0-9A-Z]{16}\b/g, /\bghp_[A-Za-z0-9]{30,}/g, /\bxox[bap]-[A-Za-z0-9-]{10,}/g,
  /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g, /\b0x[a-fA-F0-9]{64}\b/g];

function text(value) { try { return typeof value === "string" ? value : JSON.stringify(value); } catch { return String(value); } }
// Raw text of every string inside the arguments, joined by newlines. Patterns run on this, not on JSON,
// because JSON escapes newlines (as backslash-n) and would let a multi-line command slip past word boundaries.
// Object fields come out as "key: value" so rules can see e.g. "method: DELETE".
export function scanText(value, depth = 0) {
  if (typeof value === "string") return value;
  if (depth > 6 || value === null || typeof value !== "object") return value === undefined ? "" : String(value);
  if (Array.isArray(value)) return value.map(item => scanText(item, depth + 1)).join("\n");
  return Object.entries(value).map(([key, item]) => `${key}: ${scanText(item, depth + 1)}`).join("\n");
}

// Heuristic check of untrusted text (web pages, issues, PR comments, tool descriptions, tool results) for
// instructions aimed at an AI agent. It flags; it cannot prove text is safe. Treat findings as data, never obey them.
const HIDDEN_CHARS = /[\u200B-\u200F\u202A-\u202E\u2060-\u2064\u2066-\u2069\uFEFF]|[\u{E0000}-\u{E007F}]/u;
const UNTRUSTED_RULES = [
  { rule: "hidden_characters", severity: "high", test: HIDDEN_CHARS, why: "Invisible or direction-changing characters can hide instructions from a human reader." },
  { rule: "instruction_override", severity: "high", why: "Tries to replace the agent's real instructions.",
    test: /\b(ignore|disregard|forget|override)\b[^.\n]{0,40}\b(previous|prior|above|earlier|all|system|original)\b[^.\n]{0,20}\b(instructions?|prompts?|rules|messages?|guidelines)\b|\bnew\s+(system\s+)?instructions\s*:|\byou\s+are\s+now\s+(a|an|in)\b/i },
  { rule: "secret_file_exfiltration", severity: "high", why: "Asks for credential files or keys to be sent to an outside address.",
    test: /\b(send|post|paste|upload|forward|email|exfiltrate|leak|copy)\b(?=[^\n]{0,200}(\.env\b|id_rsa|id_ed25519|ssh[_ -]?keys?|private[_ -]?keys?|cookies|\.aws\/credentials|\.npmrc|keychain))(?=[^\n]{0,240}(https?:\/\/|www\.|\b[\w.-]+@[\w-]+\.\w+|webhook|pastebin|gist|requestbin|ngrok|discord|telegram))/i },
  { rule: "secret_exfiltration", severity: "medium", why: "Asks for keys, tokens or passwords to be sent to an outside address.",
    test: /\b(send|post|paste|upload|forward|email|exfiltrate|leak)\b(?=[^\n]{0,160}\b(api[_ -]?keys?|tokens?|secrets?|passwords?|credentials)\b)(?=[^\n]{0,240}(pastebin|gist\.|requestbin|ngrok|webhook\.site|discord(app)?\.com\/api\/webhooks|t\.me\/|\b[\w.-]+@[\w-]+\.\w+))/i },
  { rule: "hidden_html_instruction", severity: "high", why: "An HTML comment or invisible element carries commands for an agent.",
    test: /<!--[\s\S]{0,2000}?\b(ignore|run|execute|curl|wget|send|assistant|agent|ai\b|instructions?)\b[\s\S]{0,2000}?-->|(display\s*:\s*none|font-size\s*:\s*0|opacity\s*:\s*0)[^>]*>[^<]{8,}/i },
  { rule: "addresses_the_agent", severity: "medium", why: "Speaks directly to an AI agent, which ordinary content rarely does.",
    test: /\b(ai|assistant|agent|llm|chatbot|claude|gpt|copilot|cursor|gemini)\b[,:]?\s+(please\s+)?(you\s+)?(must|should|need to|have to|run|execute|ignore|do not tell|don't tell|silently|immediately)\b/i },
  { rule: "remote_code", severity: "medium", why: "Contains a command that downloads and runs code.",
    test: /\b(curl|wget)\b[^\n|]*\|\s*(sudo\s+)?(ba|z)?sh\b|\b(iwr|irm|invoke-webrequest)\b[^\n|]*\|\s*(iex|invoke-expression)\b/i },
  { rule: "data_in_link", severity: "medium", why: "A markdown image or link would leak data through its URL when rendered or fetched.",
    test: /!\[[^\]]*\]\(\s*https?:\/\/[^)\s]*[?&][^)\s]*=[^)\s]*\)/i },
  { rule: "encoded_payload", severity: "low", why: "A long encoded blob can smuggle instructions past a quick read.",
    test: /[A-Za-z0-9+/]{240,}={0,2}/ },
];
// Tool names that usually send data off the machine.
export const NETWORK_TOOL = /(http|fetch|request|post|curl|wget|webhook|email|mail|send|upload|slack|discord|browse|web)/i;

// One decision for one proposed tool call, shared by the Guard API, the MCP gateway and the Claude Code hook.
// deny: secrets would leave over the network. ask: destructive, irreversible or opens credential files. allow: nothing matched.
/** @param {{ tool?: string, args?: unknown, network?: boolean }} [call] */
export function classifyCall({ tool = "", args, network } = {}) {
  const body = `${tool}\n${scanText(args)}`;
  const outbound = network === true || NETWORK_TOOL.test(tool) || NETWORK_COMMAND.test(body);
  const keyShaped = KEY_SHAPES.some(shape => { shape.lastIndex = 0; return shape.test(body); });
  if (outbound && (keyShaped || SECRET_FILES.test(body)))
    return { decision: "deny", rule: "secret_exfiltration",
      reason: "This call would send secrets (API keys, .env, private keys) over the network. Do not send them; tell the user instead." };
  if (DEFAULT_DESTRUCTIVE.some(pattern => pattern.test(body)))
    return { decision: "ask", rule: "destructive", reason: "Destructive or irreversible action. A human must approve it before it runs." };
  if (SECRET_ACCESS.test(body))
    return { decision: "ask", rule: "secret_access",
      reason: "This opens a credential file (.env, SSH key, cloud credentials). A human must approve it; agents should not read secrets they were not given." };
  return { decision: "allow", rule: null, reason: "No guard rule matched. Your own permissions still apply." };
}

const SEVERITY = { none: 0, low: 1, medium: 2, high: 3 };
export function scanUntrusted(input) {
  const body = typeof input === "string" ? input : scanText(input);
  const findings = [];
  for (const { rule, severity, test, why } of UNTRUSTED_RULES) {
    const match = test.exec(body);
    if (!match) continue;
    const start = Math.max(0, match.index - 40);
    const excerpt = body.slice(start, match.index + Math.min(match[0].length, 160) + 40).replace(new RegExp(HIDDEN_CHARS.source, "gu"), "\u2423").replace(/\s+/g, " ").trim();
    findings.push({ rule, severity, why, excerpt: excerpt.length > 240 ? `${excerpt.slice(0, 237)}…` : excerpt });
  }
  const risk = findings.reduce((top, finding) => SEVERITY[finding.severity] > SEVERITY[top] ? finding.severity : top, "none");
  return { risk, findings };
}
const sha256 = value => createHash("sha256").update(value, "utf8").digest("hex");

// Hash of one journal entry: sha256(prev + JSON of the fields in this exact order). The browser verifier uses the same rule.
export function entryHash(entry) {
  const body = JSON.stringify({ seq: entry.seq, ts: entry.ts, tool: entry.tool, args: entry.args, outcome: entry.outcome,
    code: entry.code, costUsd: entry.costUsd, prev: entry.prev });
  return sha256(`${entry.prev}${body}`);
}

export function verifyJournal(lines) {
  let prev = "genesis";
  const entries = (Array.isArray(lines) ? lines : String(lines).split("\n")).filter(line => line.trim());
  for (let index = 0; index < entries.length; index++) {
    let entry;
    try { entry = JSON.parse(entries[index]); } catch { return { ok: false, entries: index, brokenAt: index, reason: "not JSON" }; }
    if (entry.seq !== index || entry.prev !== prev || entryHash(entry) !== entry.hash)
      return { ok: false, entries: index, brokenAt: index, reason: entry.prev !== prev ? "chain broken" : "entry altered" };
    prev = entry.hash;
  }
  return { ok: true, entries: entries.length };
}

// Ready-made approve() that asks a human through AgentLeisure approvals: creates a request, hands the link to
// onRequest (or posts it to a Slack/Discord webhook), then waits for the decision. Anything but "approved" is a no.
//   const guard = createGuard({ approve: agentLeisureApprover({ apiKey: process.env.AGENTLEISURE_KEY,
//     notifyUrl: process.env.SLACK_WEBHOOK_URL, onRequest: url => console.log("Approve:", url) }) });
export function agentLeisureApprover({ apiKey, baseUrl = "https://agentleisure.com", notifyUrl, ttlMinutes = 30,
  timeoutSeconds = 600, pollSeconds = 3, onRequest = url => console.error(`[agent-guard] approval needed: ${url}`) } = {}) {
  if (!apiKey) throw new Error("agentLeisureApprover needs an AgentLeisure agent key (apiKey).");
  const headers = { authorization: `Bearer ${apiKey}`, "content-type": "application/json" };
  return async ({ tool, args }) => {
    let summary = `${tool}: ${text(args)}`;
    if (summary.length > 300) summary = `${summary.slice(0, 297)}…`;
    const created = await fetch(`${baseUrl}/api/approvals`, { method: "POST", headers,
      body: JSON.stringify({ tool, summary, args, ttl_minutes: ttlMinutes, ...(notifyUrl ? { notify_url: notifyUrl } : {}) }) });
    const request = await created.json();
    if (!created.ok) throw new GuardError("approval_unavailable", `Could not create an approval request: ${request.error ?? created.status}`);
    await onRequest(request.approve_url, request);
    const deadline = Date.now() + timeoutSeconds * 1000;
    while (Date.now() < deadline) {
      await new Promise(resolve => setTimeout(resolve, pollSeconds * 1000));
      const response = await fetch(`${baseUrl}${request.status_url}`, { headers });
      if (!response.ok) continue;
      const { status } = await response.json();
      if (status === "approved") return true;
      if (status === "denied" || status === "expired") return false;
    }
    return false;
  };
}

export function createGuard(options = {}) {
  const approve = options.approve ?? (async () => false);
  const destructive = options.destructivePatterns ?? DEFAULT_DESTRUCTIVE;
  const askBeforeSecretAccess = options.allowSecretAccess !== true;
  const secrets = (options.secretValues ?? []).filter(value => typeof value === "string" && value.length >= 8);
  const maxFailures = options.maxFailures ?? 3;
  const budget = typeof options.budgetUsd === "number" ? options.budgetUsd : Infinity;
  const permissions = options.permissions ?? null;
  const writeJournal = options.journal ?? null;
  let spent = 0; let seq = 0; let prev = "genesis";
  const failures = new Map();

  function redact(body) {
    let out = body;
    for (const secret of secrets) out = out.split(secret).join("[secret]");
    for (const shape of KEY_SHAPES) out = out.replace(shape, "[secret]");
    return out.length > 2000 ? `${out.slice(0, 2000)}…` : out;
  }

  function record(tool, body, outcome, code, costUsd) {
    if (!writeJournal) return;
    const entry = { seq: seq++, ts: new Date().toISOString(), tool, args: redact(body), outcome, code: code ?? null, costUsd, prev };
    entry.hash = entryHash(entry);
    prev = entry.hash;
    try { writeJournal(JSON.stringify(entry)); } catch { /* journaling must never break the agent */ }
  }

  function refuse(tool, body, code, message) { record(tool, body, "refused", code, 0); throw new GuardError(code, message); }

  function check(name, body, meta, raw) {
    if (permissions) {
      const rule = permissions[name];
      if (!rule) refuse(name, body, "tool_not_permitted", `${name}: this agent is not permitted to use this tool.`);
      if (rule.deny?.some(pattern => pattern.test(body))) refuse(name, body, "argument_denied", `${name}: these arguments are not permitted for this agent.`);
      if (rule.allow && !rule.allow.some(pattern => pattern.test(body))) refuse(name, body, "argument_not_allowed", `${name}: arguments are outside what this agent may do.`);
    }
    if (meta.network && (secrets.some(secret => raw.includes(secret)) || KEY_SHAPES.some(shape => { shape.lastIndex = 0; return shape.test(raw); })))
      refuse(name, body, "secret_blocked", `${name}: arguments contain a secret; refusing to send it over the network.`);
    const key = `${name}:${body}`;
    if ((failures.get(key) ?? 0) >= maxFailures)
      refuse(name, body, "loop_stopped", `${name}: failed ${maxFailures} times in a row with the same input; stop and report instead of retrying.`);
    const cost = meta.costUsd ?? 0;
    if (spent + cost > budget)
      refuse(name, body, "budget_exceeded", `${name}: would spend $${(spent + cost).toFixed(2)} of a $${budget.toFixed(2)} budget.`);
    return { key, cost, risky: meta.destructive === true || destructive.some(pattern => pattern.test(raw)) || (askBeforeSecretAccess && SECRET_ACCESS.test(raw)) };
  }

  return {
    get spentUsd() { return spent; },
    wrap(name, fn, meta = {}) {
      return async (...args) => {
        const body = text(args);
        const { key, cost, risky } = check(name, body, meta, scanText(args));
        if (risky) {
          const ok = await approve({ tool: name, args });
          if (ok !== true) refuse(name, body, "approval_denied", `${name}: destructive action needs human approval, which was not given.`);
        }
        spent += cost;
        try {
          const result = await fn(...args);
          failures.delete(key);
          record(name, body, risky ? "ok_approved" : "ok", null, cost);
          return result;
        } catch (error) {
          failures.set(key, (failures.get(key) ?? 0) + 1);
          record(name, body, "error", error instanceof Error ? error.message.slice(0, 120) : "error", cost);
          throw error;
        }
      };
    },
  };
}
