// agentleisure-guard: hard limits for AI agent tools, local or through the AgentLeisure Guard API. MIT.
export { GuardError, DEFAULT_DESTRUCTIVE, NETWORK_COMMAND, NETWORK_TOOL, SECRET_ACCESS, SECRET_FILES, classifyCall, isOutbound, KEY_SHAPES, scanText, scanUntrusted, entryHash, verifyJournal,
  agentLeisureApprover, createGuard } from "./agent-guard.mjs";
import { GuardError } from "./agent-guard.mjs";

// Ask the hosted Guard API about one tool call. Returns { decision: "allow" | "ask" | "deny", rule, reason, approval? }.
// With apiKey and requestApproval, an "ask" also opens a human approval request (approval.approve_url / status_url).
export async function checkToolCall(tool, args, { apiKey, baseUrl = "https://agentleisure.com", network, requestApproval = false,
  summary, notifyUrl, ttlMinutes, timeoutMs = 10_000 } = {}) {
  const response = await fetch(`${baseUrl}/api/guard/check`, {
    method: "POST",
    signal: AbortSignal.timeout(timeoutMs),
    headers: { "content-type": "application/json", ...(apiKey ? { authorization: `Bearer ${apiKey}` } : {}) },
    body: JSON.stringify({ tool, args, ...(network === undefined ? {} : { network }), request_approval: Boolean(requestApproval && apiKey),
      ...(summary ? { summary: String(summary).slice(0, 300) } : {}), ...(notifyUrl ? { notify_url: notifyUrl } : {}),
      ...(ttlMinutes ? { ttl_minutes: ttlMinutes } : {}) }),
  });
  const body = await response.json().catch(() => ({}));
  if (!body.decision) throw new GuardError("guard_unavailable", `Guard API error: ${body.error ?? response.status}`);
  return body;
}

// Wrap a tool so every call is checked by the Guard API first. allow -> runs; deny -> throws; ask -> waits for a human
// (needs apiKey) and runs only if approved. failClosed (default true) refuses the call when the API cannot be reached.
export function guardTool(name, fn, { apiKey, baseUrl = "https://agentleisure.com", network, notifyUrl, timeoutSeconds = 600,
  pollSeconds = 3, failClosed = true, timeoutMs = 10_000, onApprovalNeeded = url => console.error(`[agentleisure-guard] approval needed: ${url}`) } = {}) {
  return async (...args) => {
    let result;
    try { result = await checkToolCall(name, args.length === 1 ? args[0] : args, { apiKey, baseUrl, network, notifyUrl, requestApproval: true, timeoutMs }); }
    catch (error) { if (failClosed) throw error instanceof GuardError ? error : new GuardError("guard_unavailable", String(error)); return fn(...args); }
    if (result.decision === "deny") throw new GuardError(result.rule ?? "denied", `${name}: ${result.reason}`);
    if (result.decision === "ask") {
      if (!result.approval) throw new GuardError("approval_unavailable", `${name}: ${result.reason} (no approval: ${result.approval_error ?? "set apiKey"})`);
      await onApprovalNeeded(result.approval.approve_url, result);
      const deadline = Date.now() + timeoutSeconds * 1000;
      let approved = false;
      while (Date.now() < deadline) {
        await new Promise(resolve => setTimeout(resolve, pollSeconds * 1000));
        const response = await fetch(`${baseUrl}${result.approval.status_url}`, { headers: { authorization: `Bearer ${apiKey}` }, signal: AbortSignal.timeout(timeoutMs) }).catch(() => null);
        if (!response?.ok) continue;
        const { status } = await response.json();
        if (status === "approved") { approved = true; break; }
        if (status === "denied" || status === "expired") break;
      }
      if (!approved) throw new GuardError("approval_denied", `${name}: destructive action needs human approval, which was not given.`);
    }
    return fn(...args);
  };
}
