export class GuardError extends Error {
  code: string;
  constructor(code: string, message: string);
}

export const DEFAULT_DESTRUCTIVE: RegExp[];
export const NETWORK_COMMAND: RegExp;
export const NETWORK_TOOL: RegExp;
/** The same allow / ask / deny decision the Guard API, the MCP gateway and the Claude Code hook make, computed locally. */
export function classifyCall(call: { tool?: string; args?: unknown; network?: boolean }): { decision: "allow" | "ask" | "deny"; rule: string | null; reason: string };
export const SECRET_FILES: RegExp;
/** Credential files (.env, SSH keys, cloud credentials); opening one needs approval unless allowSecretAccess is set. */
export const SECRET_ACCESS: RegExp;
export const KEY_SHAPES: RegExp[];
export function scanText(value: unknown, depth?: number): string;
export type UntrustedFinding = { rule: string; severity: "low" | "medium" | "high"; why: string; excerpt: string };
/** Heuristic check of text the agent did not write (pages, issues, PR comments, tool results) for instructions aimed at an AI. */
export function scanUntrusted(input: unknown): { risk: "none" | "low" | "medium" | "high"; findings: UntrustedFinding[] };

export type JournalEntry = { seq: number; ts: string; tool: string; args: string; outcome: string; code: string | null;
  costUsd: number; prev: string; hash: string };
export function entryHash(entry: Omit<JournalEntry, "hash">): string;
export function verifyJournal(lines: string | string[]): { ok: boolean; entries: number; brokenAt?: number; reason?: string };

export type ApproveFn = (call: { tool: string; args: unknown[] }) => Promise<boolean> | boolean;
export function agentLeisureApprover(options: { apiKey: string; baseUrl?: string; notifyUrl?: string; ttlMinutes?: number;
  timeoutSeconds?: number; pollSeconds?: number; onRequest?: (approveUrl: string, request: unknown) => unknown }): ApproveFn;

export type GuardOptions = {
  approve?: ApproveFn;
  destructivePatterns?: RegExp[];
  secretValues?: (string | undefined)[];
  maxFailures?: number;
  budgetUsd?: number;
  permissions?: Record<string, { allow?: RegExp[]; deny?: RegExp[] }>;
  journal?: (line: string) => void;
  /** Set true to let the agent open .env, SSH keys and cloud credentials without approval. */
  allowSecretAccess?: boolean;
};
export type ToolMeta = { network?: boolean; costUsd?: number; destructive?: boolean };
export function createGuard(options?: GuardOptions): {
  readonly spentUsd: number;
  wrap<A extends unknown[], R>(name: string, fn: (...args: A) => R | Promise<R>, meta?: ToolMeta): (...args: A) => Promise<R>;
};

export type GuardDecision = {
  object: "agentleisure.guard_decision";
  decision: "allow" | "ask" | "deny";
  rule: string | null;
  reason: string;
  approval?: { id: string; status: "pending"; expires_at: string; approve_url: string; status_url: string; notified: boolean };
  approval_error?: string;
};
export function checkToolCall(tool: string, args: unknown, options?: { apiKey?: string; baseUrl?: string; network?: boolean;
  requestApproval?: boolean; summary?: string; notifyUrl?: string; ttlMinutes?: number; timeoutMs?: number }): Promise<GuardDecision>;
export function guardTool<A extends unknown[], R>(name: string, fn: (...args: A) => R | Promise<R>, options?: { apiKey?: string;
  baseUrl?: string; network?: boolean; notifyUrl?: string; timeoutSeconds?: number; pollSeconds?: number; failClosed?: boolean; timeoutMs?: number;
  onApprovalNeeded?: (approveUrl: string, decision: GuardDecision) => unknown }): (...args: A) => Promise<R>;
