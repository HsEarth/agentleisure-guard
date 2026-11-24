// `agentleisure-guard blast`: what can your AI coding agent break on this machine right now?
// Read-only detectors over local credentials and agent settings. Secret VALUES are never printed, stored or sent:
// a detector only decides "present / looks like production" and reports a fixed finding type and a location.
import { spawnSync } from "node:child_process";
import { copyFileSync, existsSync, mkdirSync, readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join, relative, resolve, sep } from "node:path";
import { createInterface } from "node:readline";
import { FINDINGS, HOOK_COMMAND, SEVERITIES, settingsPatch, summarize } from "./blast-fixes.mjs";

const SITE = (process.env.AGENTLEISURE_URL || "https://agentleisure.com").replace(/\/$/, "");
const PROD_WORD = /(^|[^a-z])(prod|production|prd|live|primary|master|main-db)([^a-z]|$)/i;
const SAFE_WORD = /(^|[^a-z])(staging|stage|stg|dev|develop|development|test|testing|local|localhost|preview|sandbox|demo|example)([^a-z]|$)/i;
const CLOUD_DB = /(rds\.amazonaws\.com|supabase\.co|supabase\.com|neon\.tech|railway\.app|rlwy\.net|psdb\.cloud|planetscale|render\.com|azure|database\.windows\.net|digitalocean|ondigitalocean|herokuapp|amazonaws|mongodb\.net|cockroachlabs|aivencloud|timescale|turso\.io|upstash\.io)/i;
const PLACEHOLDER = /^(|x+|changeme|change_me|placeholder|your[-_].*|<.*>|\$\{.*\}|\.\.\.|null|none|todo|secret|password)$/i;
const SECRET_NAME = /(^|_)(KEY|TOKEN|SECRET|PASSWORD|PASSWD|PWD|CREDENTIALS?|PRIVATE_KEY|API_KEY|ACCESS_KEY)$/i;
// Ends like a secret but is not one (working directories, the agent's own session plumbing, public keys).
const NOT_SECRET = /^(PWD|OLDPWD|CLAUDE_CODE_[A-Z_]+|.*_PUBLIC_KEY|.*_PUBLISHABLE_KEY|NEXT_PUBLIC_.*|VITE_.*|.*_KEY_ID|GPG_KEY|SSH_AUTH_SOCK)$/;
const KNOWN_MCP = [/^@modelcontextprotocol\//, /^agentleisure-guard(@|$)/, /^@anthropic-ai\//, /^@playwright\/mcp/, /^@upstash\/context7-mcp/, /^@sentry\//, /^@supabase\//, /^@stripe\//, /^@cloudflare\//, /^@vercel\//, /^@notionhq\//, /^@github\//, /^@azure\//, /^@aws\//, /^awslabs\./, /^mcp-server-git(@|$)/, /^mcp-server-fetch(@|$)/, /^mcp-server-time(@|$)/, /^mcp-server-sqlite(@|$)/];

function read(path, max = 512 * 1024) {
  try { const stat = statSync(path); if (!stat.isFile() || stat.size > max) return null; return readFileSync(path, "utf8"); } catch { return null; }
}
function json(path, max) { const text = read(path, max); if (text == null) return null; try { return JSON.parse(text); } catch { return null; } }

export function detect(options = {}) {
  const home = options.home ?? homedir();
  const cwd = options.cwd ?? process.cwd();
  const env = options.env ?? process.env;
  const appdata = options.appdata ?? env.APPDATA ?? join(home, "AppData", "Roaming");
  const findings = [];
  const where = path => { const abs = resolve(path); if (abs.startsWith(resolve(cwd) + sep) || abs === resolve(cwd)) return `./${relative(cwd, abs).split(sep).join("/")}`; if (abs.startsWith(resolve(home))) return `~/${relative(home, abs).split(sep).join("/")}`; return abs; };
  const add = (type, location, detail = "") => { if (!findings.some(item => item.type === type && item.where === location)) findings.push({ type, severity: FINDINGS[type].severity, where: location, detail }); };
  const firstExisting = paths => paths.find(path => existsSync(path));

  // Hosting and cloud CLIs logged in on this machine.
  const railway = json(join(home, ".railway", "config.json"));
  if (railway && (railway.user?.token || railway.token)) add("railway_token", where(join(home, ".railway", "config.json")), "Railway CLI login token (account-wide)");
  if (env.RAILWAY_TOKEN || env.RAILWAY_API_TOKEN) add("railway_token", "environment", "RAILWAY_TOKEN is set");

  const vercelPath = firstExisting([join(home, ".config", "vercel", "auth.json"), join(home, ".local", "share", "com.vercel.cli", "auth.json"), join(home, "Library", "Application Support", "com.vercel.cli", "auth.json"), join(appdata, "com.vercel.cli", "Data", "auth.json"), join(appdata, "com.vercel.cli", "auth.json")]);
  if (vercelPath && json(vercelPath)?.token) add("vercel_token", where(vercelPath), "Vercel CLI login token");
  if (env.VERCEL_TOKEN) add("vercel_token", "environment", "VERCEL_TOKEN is set");

  const awsPath = env.AWS_SHARED_CREDENTIALS_FILE || join(home, ".aws", "credentials");
  const aws = read(awsPath);
  if (aws) {
    const profiles = [];
    let current = null;
    for (const line of aws.split(/\r?\n/)) {
      const section = /^\s*\[([^\]]+)\]/.exec(line);
      if (section) { current = section[1].trim(); continue; }
      if (current && /^\s*aws_secret_access_key\s*=\s*\S/.test(line)) profiles.push(current);
    }
    const admin = profiles.filter(name => /admin|root|owner|prod|production|master/i.test(name));
    if (admin.length) add("aws_admin_profile", where(awsPath), `profile${admin.length > 1 ? "s" : ""} ${admin.map(name => `"${name}"`).join(", ")}`);
    else if (profiles.length) add("aws_credentials", where(awsPath), `${profiles.length} profile${profiles.length > 1 ? "s" : ""} with long-lived keys`);
  }
  if (env.AWS_SECRET_ACCESS_KEY) add("aws_credentials", "environment", "AWS_SECRET_ACCESS_KEY is set");

  const gcloud = firstExisting([join(home, ".config", "gcloud", "credentials.db"), join(home, ".config", "gcloud", "application_default_credentials.json"), join(appdata, "gcloud", "credentials.db"), join(appdata, "gcloud", "application_default_credentials.json")]);
  if (gcloud) add("gcloud_credentials", where(dirname(gcloud)), "gcloud user or application-default credentials");
  if (env.GOOGLE_APPLICATION_CREDENTIALS) add("gcloud_credentials", "environment", "GOOGLE_APPLICATION_CREDENTIALS is set");

  const kubePath = (env.KUBECONFIG || "").split(process.platform === "win32" ? ";" : ":").find(Boolean) || join(home, ".kube", "config");
  const kube = read(kubePath, 2 * 1024 * 1024);
  const context = kube && /^current-context:\s*["']?([^"'\s]+)/m.exec(kube)?.[1];
  if (context) add(PROD_WORD.test(context) && !SAFE_WORD.test(context) ? "kube_prod_context" : "kube_context", where(kubePath), `current context "${context}"`);

  const docker = json(join(home, ".docker", "config.json"));
  if (docker?.auths && Object.values(docker.auths).some(entry => entry && (entry.auth || entry.identitytoken)) || (docker?.credsStore && docker?.auths && Object.keys(docker.auths).length))
    add("docker_registry", where(join(home, ".docker", "config.json")), `${Object.keys(docker.auths).length} registr${Object.keys(docker.auths).length === 1 ? "y" : "ies"} logged in`);

  const fly = read(join(home, ".fly", "config.yml"));
  if (fly && /access_token:\s*\S{8,}/.test(fly)) add("fly_token", where(join(home, ".fly", "config.yml")), "flyctl login token");
  if (env.FLY_API_TOKEN || env.FLY_ACCESS_TOKEN) add("fly_token", "environment", "FLY_API_TOKEN is set");

  const supabase = read(join(home, ".supabase", "access-token"));
  if (supabase && supabase.trim().length > 8) add("supabase_token", where(join(home, ".supabase", "access-token")), "Supabase CLI access token");
  if (env.SUPABASE_ACCESS_TOKEN) add("supabase_token", "environment", "SUPABASE_ACCESS_TOKEN is set");

  const netlifyPath = firstExisting([join(home, ".netlify", "config.json"), join(home, ".config", "netlify", "config.json"), join(home, "Library", "Preferences", "netlify", "config.json"), join(appdata, "netlify", "Config", "config.json")]);
  if (netlifyPath && /"token"\s*:\s*"[^"]{8,}"/.test(read(netlifyPath) ?? "")) add("netlify_token", where(netlifyPath), "Netlify CLI login token");
  if (env.NETLIFY_AUTH_TOKEN) add("netlify_token", "environment", "NETLIFY_AUTH_TOKEN is set");

  const netrcPath = firstExisting([join(home, ".netrc"), join(home, "_netrc")]);
  if (netrcPath && /machine\s+api\.heroku\.com[\s\S]*?password\s+\S/.test(read(netrcPath) ?? "")) add("heroku_token", where(netrcPath), "Heroku CLI login");
  if (env.HEROKU_API_KEY) add("heroku_token", "environment", "HEROKU_API_KEY is set");

  // Environment variables and .env files the agent can read. Only names are kept, never values.
  const sources = [["environment", Object.entries(env)]];
  try {
    for (const name of readdirSync(cwd)) {
      if (!/^\.env(\..+)?$/.test(name) || /\.(example|sample|template|dist|defaults?)$/i.test(name)) continue;
      const text = read(join(cwd, name));
      if (text == null) continue;
      const pairs = [];
      for (const line of text.split(/\r?\n/)) {
        const match = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/.exec(line);
        if (match) pairs.push([match[1], match[2].trim().replace(/^["']|["']$/g, "")]);
      }
      sources.push([`./${name}`, pairs]);
    }
  } catch { /* unreadable folder */ }
  for (const [source, pairs] of sources) {
    const secretNames = [];
    for (const [name, raw] of pairs) {
      const value = String(raw ?? "").trim();
      if (PLACEHOLDER.test(value)) continue;
      if (/^(postgres(ql)?|mysql|mariadb|mongodb(\+srv)?|redis|rediss|sqlserver|cockroachdb):\/\//i.test(value)) {
        let host = ""; let db = "";
        try { const url = new URL(value); host = url.hostname; db = url.pathname; } catch { host = value.split("@").pop() ?? ""; }
        const prodLike = (PROD_WORD.test(host) || PROD_WORD.test(db) || PROD_WORD.test(name) || CLOUD_DB.test(host)) && !SAFE_WORD.test(host) && !SAFE_WORD.test(db) && !SAFE_WORD.test(name) && !/^(localhost|127\.|0\.0\.0\.0|\[?::1)/.test(host);
        if (prodLike) add("prod_database_url", source, `${name} points to a production-looking database`);
        continue;
      }
      if (SECRET_NAME.test(name) && !NOT_SECRET.test(name) && value.length >= 8 && !/^([A-Za-z]:)?[\\/]/.test(value)) secretNames.push(name);
    }
    if (secretNames.length) add("env_secrets", source, `${secretNames.length} secret-looking variable${secretNames.length > 1 ? "s" : ""} (${secretNames.slice(0, 4).join(", ")}${secretNames.length > 4 ? ", …" : ""})`);
  }

  // GitHub CLI login and default-branch protection (skipped offline or without gh).
  if (options.gh !== false) {
    const status = spawnSync("gh", ["auth", "status"], { encoding: "utf8", timeout: 6000, env: { ...env, GH_PROMPT_DISABLED: "1" } });
    const text = `${status.stdout ?? ""}${status.stderr ?? ""}`;
    if (status.status === 0 && /Logged in/i.test(text)) {
      add(/delete_repo|admin:org|admin:enterprise/.test(text) ? "gh_admin_token" : "gh_token", "gh CLI", /delete_repo|admin:/.test(text) ? "token scopes include delete_repo or admin" : "logged in");
      const remote = spawnSync("git", ["remote", "get-url", "origin"], { cwd, encoding: "utf8", timeout: 3000 }).stdout?.trim() ?? "";
      const repo = /github\.com[:/]([^/\s]+\/[^/\s]+?)(\.git)?$/.exec(remote)?.[1];
      if (repo) {
        const branch = spawnSync("gh", ["repo", "view", repo, "--json", "defaultBranchRef", "-q", ".defaultBranchRef.name"], { encoding: "utf8", timeout: 8000 }).stdout?.trim();
        if (branch) {
          const protection = spawnSync("gh", ["api", `repos/${repo}/branches/${branch}/protection`], { encoding: "utf8", timeout: 8000 });
          if (protection.status !== 0 && /Branch not protected/i.test(`${protection.stdout}${protection.stderr}`)) add("unprotected_branch", `${repo}@${branch}`, "no branch protection");
        }
      }
    }
  }
  if (env.GH_TOKEN || env.GITHUB_TOKEN) add("gh_token", "environment", "GH_TOKEN or GITHUB_TOKEN is set");

  // SSH private keys without a passphrase (only the key header is inspected).
  const sshDir = join(home, ".ssh");
  try {
    const bare = [];
    for (const name of readdirSync(sshDir)) {
      if (/\.pub$|^known_hosts|^config$|^authorized_keys/.test(name)) continue;
      const text = read(join(sshDir, name), 64 * 1024);
      if (!text || !/-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(text)) continue;
      if (unencryptedKey(text)) bare.push(name);
    }
    if (bare.length) add("ssh_key_no_passphrase", "~/.ssh", `${bare.length} key${bare.length > 1 ? "s" : ""} without a passphrase (${bare.join(", ")})`);
  } catch { /* no ~/.ssh */ }

  // Agent settings: permissions, deny rules, MCP servers.
  const claudeFiles = [join(cwd, ".claude", "settings.json"), join(cwd, ".claude", "settings.local.json"), join(home, ".claude", "settings.json"), join(home, ".claude", "settings.local.json")];
  const denyRules = [];
  let claudeSeen = existsSync(join(home, ".claude")) || existsSync(join(cwd, ".claude"));
  for (const path of claudeFiles) {
    const settings = json(path);
    if (!settings) continue;
    claudeSeen = true;
    const mode = settings.permissions?.defaultMode ?? settings.defaultMode;
    if (mode === "bypassPermissions" || settings.dangerouslySkipPermissions === true) add("agent_bypass_permissions", where(path), "defaultMode is bypassPermissions");
    const allow = settings.permissions?.allow ?? [];
    const broad = allow.filter(rule => /^(\*|Bash|Bash\(\*\)|Bash\(\*:\*\)|Bash\(:\*\))$/.test(String(rule).trim()));
    if (broad.length) add("agent_broad_allow", where(path), `allow list contains ${broad.join(", ")}`);
    denyRules.push(...(settings.permissions?.deny ?? []).map(String));
  }
  if (claudeSeen && !(denyRules.some(rule => rule.includes(".env")) && denyRules.some(rule => rule.includes(".ssh"))))
    add("agent_secrets_readable", "Claude Code settings", "no deny rule for .env files and ~/.ssh");

  const homeClaude = json(join(home, ".claude.json"), 8 * 1024 * 1024);
  const mcpSources = [
    [join(cwd, ".mcp.json"), json(join(cwd, ".mcp.json"))?.mcpServers],
    [join(cwd, ".cursor", "mcp.json"), json(join(cwd, ".cursor", "mcp.json"))?.mcpServers],
    [join(home, ".cursor", "mcp.json"), json(join(home, ".cursor", "mcp.json"))?.mcpServers],
    [join(home, ".claude.json"), { ...(homeClaude?.mcpServers ?? {}), ...(homeClaude?.projects?.[cwd]?.mcpServers ?? homeClaude?.projects?.[cwd.split(sep).join("/")]?.mcpServers ?? {}) }],
  ];
  for (const [path, servers] of mcpSources) {
    if (!servers || typeof servers !== "object") continue;
    for (const [name, server] of Object.entries(servers)) {
      const args = (server?.args ?? []).map(String);
      const command = String(server?.command ?? "");
      if (wideFilesystem(name, command, args, home)) add("mcp_filesystem_wide", where(path), `server "${name}" can reach the whole home folder or disk`);
      if (unknownSource(command, args, server?.url)) add("mcp_unknown_source", where(path), `server "${name}"`);
    }
  }

  findings.sort((a, b) => SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity));
  return findings;
}

export function unencryptedKey(text) {
  if (/BEGIN ENCRYPTED PRIVATE KEY/.test(text) || /Proc-Type:\s*4,ENCRYPTED/.test(text)) return false;
  if (/BEGIN OPENSSH PRIVATE KEY/.test(text)) {
    try {
      const body = text.split(/-----BEGIN OPENSSH PRIVATE KEY-----/)[1].split(/-----END/)[0].replace(/\s+/g, "");
      const bytes = Buffer.from(body.slice(0, 200), "base64");
      const magic = "openssh-key-v1\0";
      if (bytes.subarray(0, magic.length).toString("latin1") !== magic) return false;
      const length = bytes.readUInt32BE(magic.length);
      return bytes.subarray(magic.length + 4, magic.length + 4 + length).toString("latin1") === "none";
    } catch { return false; }
  }
  return /BEGIN (RSA |EC |DSA )?PRIVATE KEY/.test(text);
}

function isFilesystemServer(name, command, args) {
  return /filesystem|server-fs|mcp-fs/i.test(`${name} ${command} ${args.join(" ")}`);
}

// The home folder, a drive root or "/" as a filesystem root.
function isWidePath(arg, home) {
  const homes = [home, home.split(sep).join("/"), "~", "$HOME", "%USERPROFILE%", "${HOME}"].map(value => value.replace(/[\\/]+$/, "").toLowerCase());
  const value = arg.replace(/[\\/]+$/, "").toLowerCase();
  return (value === "" && arg.startsWith("/")) || arg === "/" || /^[a-z]:[\\/]?$/i.test(arg) || homes.includes(value);
}

function wideFilesystem(name, command, args, home) {
  return isFilesystemServer(name, command, args) && args.some(arg => isWidePath(arg, home));
}

function unknownSource(command, args, url) {
  if (url) { try { const parsed = new URL(String(url)); return parsed.protocol !== "https:" && !/^(localhost|127\.|\[::1\])/.test(parsed.hostname); } catch { return true; } }
  if (!/(^|[\\/])(npx|bunx|pnpm|uvx|pipx)(\.cmd|\.exe)?$/i.test(command)) return false;
  const pkg = args.find(arg => !arg.startsWith("-") && !["dlx", "run", "exec"].includes(arg));
  return Boolean(pkg) && !KNOWN_MCP.some(pattern => pattern.test(pkg));
}

// ---------- --fix: agent settings in this project only, with a backup ----------
function lineDiff(before, after) {
  const a = before.split("\n"); const b = after.split("\n");
  const dp = Array.from({ length: a.length + 1 }, () => new Array(b.length + 1).fill(0));
  for (let i = a.length - 1; i >= 0; i--) for (let j = b.length - 1; j >= 0; j--) dp[i][j] = a[i] === b[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);
  const out = []; let i = 0; let j = 0;
  while (i < a.length && j < b.length) { if (a[i] === b[j]) { out.push(`  ${a[i]}`); i++; j++; } else if (dp[i + 1][j] >= dp[i][j + 1]) out.push(`- ${a[i++]}`); else out.push(`+ ${b[j++]}`); }
  while (i < a.length) out.push(`- ${a[i++]}`);
  while (j < b.length) out.push(`+ ${b[j++]}`);
  return out.join("\n");
}

export function planFix(findings, cwd, home = homedir()) {
  const types = [...new Set(findings.map(finding => finding.type))];
  const changes = [];
  const settingsPath = join(cwd, ".claude", "settings.json");
  const original = read(settingsPath);
  const settings = (original && (() => { try { return JSON.parse(original); } catch { return null; } })()) ?? {};
  const next = JSON.parse(JSON.stringify(settings));
  const patch = settingsPatch(types);
  next.permissions = next.permissions ?? {};
  next.permissions.deny = [...new Set([...(next.permissions.deny ?? []), ...patch.permissions.deny])];
  if (next.permissions.defaultMode === "bypassPermissions") next.permissions.defaultMode = "default";
  if (next.defaultMode === "bypassPermissions") delete next.defaultMode;
  if (Array.isArray(next.permissions.allow)) next.permissions.allow = next.permissions.allow.filter(rule => !/^(\*|Bash|Bash\(\*\)|Bash\(\*:\*\)|Bash\(:\*\))$/.test(String(rule).trim()));
  next.hooks = next.hooks ?? {};
  const pre = next.hooks.PreToolUse ?? [];
  if (!JSON.stringify(pre).includes(HOOK_COMMAND)) next.hooks.PreToolUse = [...pre, ...patch.hooks.PreToolUse];
  const before = original ?? ""; const after = `${JSON.stringify(next, null, 2)}\n`;
  if (before.trim() !== after.trim()) changes.push({ path: settingsPath, before, after });

  const local = join(cwd, ".claude", "settings.local.json");
  const localText = read(local);
  if (localText) {
    try {
      const value = JSON.parse(localText);
      let changed = false;
      if (value.permissions?.defaultMode === "bypassPermissions") { value.permissions.defaultMode = "default"; changed = true; }
      if (Array.isArray(value.permissions?.allow)) { const kept = value.permissions.allow.filter(rule => !/^(\*|Bash|Bash\(\*\)|Bash\(\*:\*\)|Bash\(:\*\))$/.test(String(rule).trim())); if (kept.length !== value.permissions.allow.length) { value.permissions.allow = kept; changed = true; } }
      if (changed) changes.push({ path: local, before: localText, after: `${JSON.stringify(value, null, 2)}\n` });
    } catch { /* leave invalid JSON alone */ }
  }

  for (const path of [join(cwd, ".mcp.json"), join(cwd, ".cursor", "mcp.json")]) {
    const text = read(path);
    if (!text) continue;
    try {
      const value = JSON.parse(text);
      let changed = false;
      for (const [name, server] of Object.entries(value.mcpServers ?? {})) {
        const args = (server?.args ?? []).map(String);
        if (!wideFilesystem(name, String(server?.command ?? ""), args, home)) continue;
        server.args = args.map(arg => isWidePath(arg, home) ? "." : arg);
        changed = true;
      }
      if (changed) changes.push({ path, before: text, after: `${JSON.stringify(value, null, 2)}\n` });
    } catch { /* leave invalid JSON alone */ }
  }
  return changes;
}

export function applyFix(changes, cwd) {
  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  const backupDir = join(cwd, ".agentleisure-backup", stamp);
  for (const change of changes) {
    const rel = relative(cwd, change.path);
    if (existsSync(change.path)) { mkdirSync(dirname(join(backupDir, rel)), { recursive: true }); copyFileSync(change.path, join(backupDir, rel)); }
    mkdirSync(dirname(change.path), { recursive: true });
    writeFileSync(change.path, change.after);
  }
  return backupDir;
}

export function restoreBackup(cwd, which) {
  const base = join(cwd, ".agentleisure-backup");
  const stamps = existsSync(base) ? readdirSync(base).sort() : [];
  const stamp = which ?? stamps.at(-1);
  if (!stamp) return null;
  const dir = join(base, stamp);
  const restored = [];
  const walk = folder => { for (const name of readdirSync(folder)) { const full = join(folder, name); if (statSync(full).isDirectory()) walk(full); else { const target = join(cwd, relative(dir, full)); mkdirSync(dirname(target), { recursive: true }); copyFileSync(full, target); restored.push(relative(cwd, target)); } } };
  walk(dir);
  return { stamp, restored };
}

async function confirm(question) {
  if (!process.stdin.isTTY) return false;
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  const answer = await new Promise(done => rl.question(question, done));
  rl.close();
  return /^y(es)?$/i.test(answer.trim());
}

const LABEL = { critical: "CRITICAL", high: "HIGH    ", medium: "MEDIUM  " };
const HELP = `agentleisure-guard blast: what can your AI coding agent break on this machine right now?

  npx agentleisure-guard blast [--json] [--fix [--yes]] [--restore] [--publish "<setup name>"] [--private] [--no-gh]

  Read-only checks of cloud CLI logins, .env files and environment, GitHub CLI and branch protection, SSH keys,
  and agent settings (Claude Code, Cursor, MCP servers). Secret values are never printed or sent.
    --json       machine-readable findings (types, severities, locations; no values)
    --fix        show and apply fixes to THIS project's agent settings, with a backup in .agentleisure-backup/
    --yes        apply --fix without asking
    --restore    put back the files from the latest --fix backup
    --publish    add the result (finding types only) to the public blast-radius leaderboard
    --private    send nothing to agentleisure.com (no report link)
    --no-gh      skip GitHub CLI checks
  Exit code 1 if anything critical is found.
`;

export async function runBlast(argv) {
  const opt = name => { const index = argv.indexOf(name); return index >= 0 ? argv[index + 1] : undefined; };
  if (argv.includes("--help") || argv.includes("-h")) { process.stdout.write(HELP); return 0; }
  const cwd = process.cwd();
  if (argv.includes("--restore")) {
    const result = restoreBackup(cwd);
    process.stdout.write(result ? `Restored ${result.restored.join(", ")} from .agentleisure-backup/${result.stamp}\n` : "No backup found in .agentleisure-backup/\n");
    return result ? 0 : 1;
  }
  const findings = detect({ cwd, gh: !argv.includes("--no-gh") });
  const summary = summarize(findings);
  let reportUrl = null;
  const publish = opt("--publish");
  if (!argv.includes("--private")) {
    try {
      const response = await fetch(`${SITE}/api/blast/runs`, { method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify(blastPayload(findings, publish)) });
      if (response.ok) reportUrl = (await response.json()).report_url ?? null;
    } catch { /* offline: local result only */ }
  }

  if (argv.includes("--json")) {
    process.stdout.write(`${JSON.stringify({ object: "agentleisure.blast", findings, summary, report_url: reportUrl }, null, 2)}\n`);
  } else {
    process.stdout.write(`\nBlast radius of your AI agent on this machine\n\n`);
    if (!findings.length) process.stdout.write("Nothing found that an agent could use to break things beyond this project. Contained.\n");
    for (const finding of findings) {
      const meta = FINDINGS[finding.type];
      process.stdout.write(`${LABEL[finding.severity]} ${meta.consequence}: ${finding.detail} (${finding.where})\n           Fix: ${meta.fix}\n`);
    }
    process.stdout.write(`\n━━ ${summary.counts.critical} critical, ${summary.counts.high} high, ${summary.counts.medium} medium · score ${summary.score}/100${summary.contained ? " · contained" : ""} ━━\n`);
    if (findings.length && !argv.includes("--fix")) process.stdout.write(`\nApply the agent-settings part of the fix to this project: npx agentleisure-guard blast --fix\n`);
    if (reportUrl) process.stdout.write(`Report: ${reportUrl}\n`);
    process.stdout.write("Then check whether your agent actually does it: npx agentleisure-guard test\n");
  }

  if (argv.includes("--fix")) {
    const changes = planFix(findings, cwd);
    if (!changes.length) process.stdout.write("\nNo changes needed in this project's agent settings.\n");
    else {
      for (const change of changes) process.stdout.write(`\n--- ${relative(cwd, change.path)}\n${lineDiff(change.before, change.after)}\n`);
      process.stdout.write("\nOnly agent settings in this project change. Credential files and tokens are never touched.\n");
      const ok = argv.includes("--yes") || await confirm("Apply these changes? [y/N] ");
      if (ok) process.stdout.write(`Applied. Backup: ${relative(cwd, applyFix(changes, cwd))} (undo: npx agentleisure-guard blast --restore)\nRe-run blast to verify.\n`);
      else process.stdout.write("Nothing changed.\n");
    }
  }
  return summary.counts.critical ? 1 : 0;
}

// The only thing that ever leaves the machine: finding types and severities, plus the optional setup name.
export function blastPayload(findings, publish) {
  return { findings: findings.map(finding => ({ type: finding.type, severity: finding.severity })), score: summarize(findings).score,
    setup: typeof publish === "string" ? publish : "", publish: typeof publish === "string" };
}
