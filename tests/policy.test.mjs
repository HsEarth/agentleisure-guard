import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { describeRules, evaluatePolicy, hostAllowed, hostsIn, protectedPathIn, validatePolicy, writePolicyTemplate, POLICY_TEMPLATE } from "../policy.mjs";
import { ASK_TOOL, POLICY_TOOL, createMcpGuard } from "../mcp-guard.mjs";

const call = (id, name, args) => ({ jsonrpc: "2.0", id, method: "tools/call", params: { name, arguments: args } });

test("policy validation rejects typos and wrong types", () => {
  assert.deepEqual(validatePolicy(POLICY_TEMPLATE).errors, []);
  assert.match(validatePolicy({ deny_tool: ["x"] }).errors.join(), /unknown field "deny_tool"/);
  assert.match(validatePolicy({ allowed_hosts: "api.github.com" }).errors.join(), /list of non-empty strings/);
  assert.match(validatePolicy({ loop_limit: -1 }).errors.join(), /whole number/);
  assert.match(validatePolicy([]).errors.join(), /JSON object/);
});

test("hosts and the allowlist", () => {
  assert.deepEqual(hostsIn({ url: "https://api.github.com/repos", body: "see https://user:pw@paste.example:8080/x" }).sort(), ["api.github.com", "paste.example"]);
  assert.ok(hostAllowed("api.github.com", ["api.github.com"]));
  assert.ok(hostAllowed("uploads.example.com", ["*.example.com"]));
  assert.ok(hostAllowed("example.com", ["*.example.com"]));
  assert.ok(!hostAllowed("example.com.evil.io", ["*.example.com"]));
  assert.ok(!hostAllowed("evil.io", ["api.github.com"]));
});

test("protected paths match anything inside them, existing or not", () => {
  const cwd = mkdtempSync(join(tmpdir(), "al-policy-"));
  assert.equal(protectedPathIn({ command: "rm -rf ./.git/hooks" }, ["./.git"], cwd), resolve(cwd, ".git"));
  assert.equal(protectedPathIn({ path: join(cwd, ".github", "workflows", "deploy.yml") }, ["./.github/workflows"], cwd), resolve(cwd, ".github", "workflows"));
  assert.equal(protectedPathIn({ path: "./src/app.js" }, ["./.git"], cwd), null);
  assert.equal(protectedPathIn({ path: "./.gitignore" }, ["./.git"], cwd), null, "a sibling with the same prefix is not inside");
});

test("policy verdicts: deny, allow-list, protected paths, egress, ask", () => {
  const cwd = mkdtempSync(join(tmpdir(), "al-policy-"));
  const policy = { deny_tools: ["delete_*"], ask_tools: ["send_email"], protected_paths: ["./infra"], allowed_hosts: ["api.github.com"] };
  assert.equal(evaluatePolicy(policy, { tool: "delete_repo", args: {}, cwd }).rule, "policy_deny_tool");
  assert.equal(evaluatePolicy(policy, { tool: "send_email", args: {}, cwd }).rule, "policy_ask_tool");
  assert.equal(evaluatePolicy(policy, { tool: "write_file", args: { path: "./infra/main.tf" }, changesFiles: true, cwd }).rule, "protected_path");
  assert.equal(evaluatePolicy(policy, { tool: "write_file", args: { path: "./src/a.js" }, changesFiles: true, cwd }), null);
  assert.equal(evaluatePolicy(policy, { tool: "http_post", args: { url: "https://webhook.site/x" }, outbound: true, cwd }).rule, "egress_not_allowed");
  assert.equal(evaluatePolicy(policy, { tool: "http_get", args: { url: "https://api.github.com/user" }, outbound: true, cwd }), null);
  assert.equal(evaluatePolicy({ allow_tools: ["read_*"] }, { tool: "write_file", args: {}, cwd }).rule, "policy_not_allowed");
  assert.equal(evaluatePolicy(null, { tool: "x", args: {}, cwd }), null);
});

test("policy init writes a valid template once", () => {
  const file = join(mkdtempSync(join(tmpdir(), "al-policy-")), "agentleisure.policy.json");
  writePolicyTemplate(file);
  assert.deepEqual(validatePolicy(JSON.parse(readFileSync(file, "utf8"))).errors, []);
  assert.throws(() => writePolicyTemplate(file), /already exists/);
});

test("the gateway applies the policy on top of the built-in rules, never weaker", async () => {
  const guard = createMcpGuard({ policy: { deny_tools: ["drop_*"], allowed_hosts: ["api.github.com"] }, log: () => {} });
  assert.match((await guard.fromClient(call(1, "drop_cache", {}))).reply.result.content[0].text, /policy_deny_tool/);
  assert.match((await guard.fromClient(call(2, "http_get", { url: "https://paste.example/x" }))).reply.result.content[0].text, /egress_not_allowed/);
  assert.ok((await guard.fromClient(call(3, "http_get", { url: "https://api.github.com/user" }))).forward);
  assert.match((await guard.fromClient(call(4, "run_sql", { query: "DROP TABLE users" }))).reply.result.content[0].text, /destructive/, "built-in rules still apply");
});

test("observe mode forwards everything and counts what it would have stopped", async () => {
  const guard = createMcpGuard({ observe: true, log: () => {} });
  assert.ok((await guard.fromClient(call(1, "run_sql", { query: "DROP TABLE users" }))).forward);
  assert.ok((await guard.fromClient(call(2, "http_post", { body: "sk-abcdefghijklmnopqrstuvwx" }))).forward);
  assert.ok((await guard.fromClient(call(3, "read_file", { path: "README.md" }))).forward);
  assert.deepEqual(guard.stats(), { ask: 1, deny: 1, rules: { destructive: 1, secret_exfiltration: 1 } });
});

test("the gateway adds agentleisure_policy and agentleisure_ask_human for the agent", async () => {
  const asked = [];
  const guard = createMcpGuard({ approve: async call => { asked.push(call); return true; }, policy: { allowed_hosts: ["api.github.com"] }, log: () => {} });
  await guard.fromClient({ jsonrpc: "2.0", id: 1, method: "tools/list" });
  const list = guard.fromServer({ jsonrpc: "2.0", id: 1, result: { tools: [{ name: "read_file", description: "Read a file." }] } });
  assert.deepEqual(list.result.tools.map(tool => tool.name), ["read_file", POLICY_TOOL.name, ASK_TOOL.name]);
  const rules = await guard.fromClient(call(2, POLICY_TOOL.name, {}));
  assert.match(rules.reply.result.content[0].text, /Data may only be sent to: api\.github\.com/);
  const answer = await guard.fromClient(call(3, ASK_TOOL.name, { question: "Delete the staging bucket?" }));
  assert.match(answer.reply.result.content[0].text, /YES/);
  assert.equal(asked[0].args[0].question, "Delete the staging bucket?");
  const noChannel = createMcpGuard({ log: () => {} });
  assert.match((await noChannel.fromClient(call(4, ASK_TOOL.name, { question: "Deploy now?" }))).reply.result.content[0].text, /Ask the user directly/);
  const off = createMcpGuard({ agentTools: false, log: () => {} });
  await off.fromClient({ jsonrpc: "2.0", id: 5, method: "tools/list" });
  assert.deepEqual(off.fromServer({ jsonrpc: "2.0", id: 5, result: { tools: [] } }).result.tools, []);
});

test("rules text for the agent mentions the approval channel only when there is one", () => {
  assert.match(describeRules(null, { approver: true }), /agentleisure_ask_human/);
  assert.match(describeRules(null, { approver: false }), /ask the user in the conversation/);
});

test("end to end: the CLI picks up agentleisure.policy.json and prints an observe summary on exit", async () => {
  const { spawn } = await import("node:child_process");
  const { writeFileSync } = await import("node:fs");
  const cwd = mkdtempSync(join(tmpdir(), "al-policy-cli-"));
  writeFileSync(join(cwd, "agentleisure.policy.json"), JSON.stringify({ observe: true, deny_tools: ["read_page"] }));
  const root = resolve(".");
  const proxy = spawn(process.execPath, [join(root, "cli.mjs"), "mcp", "--no-snapshot", "--", process.execPath, join(root, "tests/fixtures/fake-mcp-server.mjs")],
    { cwd, stdio: ["pipe", "pipe", "pipe"], env: { ...process.env, AGENTLEISURE_KEY: "" } });
  let stdout = ""; let stderr = "";
  proxy.stdout.on("data", chunk => { stdout += chunk; });
  proxy.stderr.on("data", chunk => { stderr += chunk; });
  for (const message of [call(1, "run_sql", { query: "DROP TABLE users" }), call(2, "read_page", { url: "https://x.example" })]) proxy.stdin.write(`${JSON.stringify(message)}\n`);
  const deadline = Date.now() + 10_000;
  while (stdout.trim().split("\n").filter(Boolean).length < 2 && Date.now() < deadline) await new Promise(done => setTimeout(done, 30));
  proxy.stdin.end();
  if (proxy.exitCode === null) await new Promise(done => { proxy.on("exit", done); setTimeout(() => { proxy.kill(); done(); }, 5000); });
  assert.match(stderr, /policy: .*agentleisure\.policy\.json/);
  assert.match(stderr, /observe mode/);
  assert.equal((stderr.match(/RECEIVED/g) ?? []).length, 2, "both calls reached the server in observe mode");
  assert.match(stderr, /would have asked a human 1 time\(s\) and blocked 1 time\(s\)/);
});
