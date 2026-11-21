import type { ChildProcess } from "node:child_process";

export type McpGuardOptions = {
  /** Called for destructive calls and credential access; return true to let the call through. */
  approve?: ((call: { tool: string; args: unknown[] }) => Promise<boolean> | boolean) | null;
  /** With no approver: "block" (default) refuses such calls, "allow" forwards them with a warning. */
  askMode?: "block" | "allow";
  /** Refuse a call repeated more than this many times within loopWindowMs (default 10; 0 turns it off). */
  loopLimit?: number;
  loopWindowMs?: number;
  /** Scan tool results and tool descriptions for instructions aimed at the agent (default true). */
  scan?: boolean;
  /** After a human approves a call, let the exact same call through for this many milliseconds (default 0 = always ask). */
  rememberApprovalMs?: number;
  /** Path of a hash-chained JSON-lines journal. */
  journal?: string | null;
  log?: (message: string) => void;
  now?: () => number;
};

export type JsonRpcMessage = Record<string, unknown>;

export function createMcpGuard(options?: McpGuardOptions): {
  fromClient(message: unknown): Promise<{ forward?: unknown; reply?: JsonRpcMessage }>;
  fromServer(message: unknown): unknown;
};

export function runMcpGuard(command: string, args: string[], options?: McpGuardOptions & {
  env?: NodeJS.ProcessEnv; approvalTimeoutSeconds?: number }): ChildProcess;

/** Guard a remote MCP server over Streamable HTTP; the MCP client still talks stdio to this process. */
export function runMcpGuardRemote(url: string, options?: McpGuardOptions & { env?: NodeJS.ProcessEnv; approvalTimeoutSeconds?: number;
  headers?: Record<string, string>; upstreamTimeoutMs?: number }): void;
export function readEventStream(body: AsyncIterable<Uint8Array>): AsyncGenerator<string>;
export function quoteWindowsArg(arg: string): string;
export function windowsCommandLine(command: string, args: string[]): string;
