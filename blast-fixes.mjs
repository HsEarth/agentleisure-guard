// Blast radius: what an AI coding agent CAN break on this machine right now. Shared by the CLI and the website.
// Pure data and functions. Finding types are a fixed list, so a report can never carry a secret value.

export const BLAST_PROTOCOL = "agentleisure.blast-radius.v1";
export const SEVERITIES = ["critical", "high", "medium"];

const DOCS = {
  railway: "https://docs.railway.com/guides/public-api#project-token",
  vercel: "https://vercel.com/docs/rest-api#creating-an-access-token",
  aws: "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#grant-least-privilege",
  gcloud: "https://cloud.google.com/iam/docs/service-account-overview",
  kube: "https://kubernetes.io/docs/reference/access-authn-authz/rbac/",
  github: "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens#creating-a-fine-grained-personal-access-token",
  protection: "https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches",
  supabase: "https://supabase.com/docs/guides/platform/access-control",
  ssh: "https://docs.github.com/en/authentication/connecting-to-github-with-ssh/working-with-ssh-key-passphrases",
};

// type -> what it means for you, how to fix it, and which part of the fix --fix can apply to agent settings.
export const FINDINGS = {
  railway_token: { severity: "critical", group: "prod", consequence: "Your agent can delete your production database and its backups", fix: "Log out of the Railway CLI on this machine (railway logout) and give the agent a project token scoped to staging.", docs: DOCS.railway, deny: ["Bash(railway down*)", "Bash(railway volume delete*)", "Bash(railway environment delete*)", "Bash(* volume delete*)"] },
  vercel_token: { severity: "high", group: "cloud", consequence: "Your agent can redeploy, roll back or delete your Vercel projects", fix: "Use a Vercel token scoped to one team and project with an expiry, and log out of the CLI where the agent runs.", docs: DOCS.vercel, deny: ["Bash(vercel remove*)", "Bash(vercel rm*)", "Bash(vercel --prod*)"] },
  aws_credentials: { severity: "high", group: "cloud", consequence: "Your agent can create, change or delete AWS resources with these keys", fix: "Give the agent its own IAM user or role with only the permissions the task needs; keep admin profiles off this machine.", docs: DOCS.aws, deny: ["Read(~/.aws/**)", "Bash(aws * delete*)", "Bash(aws s3 rm*)", "Bash(aws * terminate*)"] },
  aws_admin_profile: { severity: "critical", group: "prod", consequence: "Your agent can wipe production in AWS: an admin or production profile is configured", fix: "Remove admin/production profiles from this machine; use short-lived SSO sessions and a least-privilege role for the agent.", docs: DOCS.aws, deny: ["Read(~/.aws/**)", "Bash(aws * delete*)", "Bash(aws s3 rm*)", "Bash(aws * terminate*)"] },
  gcloud_credentials: { severity: "high", group: "cloud", consequence: "Your agent can act on your Google Cloud projects", fix: "Use a service account with a narrow role for agent work, and revoke the user login here (gcloud auth revoke).", docs: DOCS.gcloud, deny: ["Read(~/.config/gcloud/**)", "Bash(gcloud * delete*)"] },
  kube_prod_context: { severity: "critical", group: "prod", consequence: "Your agent can delete workloads in production Kubernetes: the current context looks like prod", fix: "Switch the default context to a non-production cluster and use a read-only service account for the agent.", docs: DOCS.kube, deny: ["Bash(kubectl delete*)", "Bash(kubectl * --context*prod*)", "Bash(helm uninstall*)"] },
  kube_context: { severity: "medium", group: "cloud", consequence: "Your agent can change your Kubernetes cluster", fix: "Give the agent a namespaced, read-only service account.", docs: DOCS.kube, deny: ["Bash(kubectl delete*)", "Bash(helm uninstall*)"] },
  docker_registry: { severity: "medium", group: "cloud", consequence: "Your agent can push images to your container registries", fix: "Use registry tokens limited to pull, or to one repository, on machines where agents run.", docs: "", deny: ["Bash(docker push*)"] },
  fly_token: { severity: "high", group: "cloud", consequence: "Your agent can destroy or redeploy your Fly.io apps", fix: "Use a deploy token scoped to one app (fly tokens create deploy) and log out of the CLI here.", docs: "https://fly.io/docs/security/tokens/", deny: ["Bash(fly apps destroy*)", "Bash(flyctl apps destroy*)"] },
  supabase_token: { severity: "high", group: "prod", consequence: "Your agent can manage your Supabase projects, including databases", fix: "Log out of the Supabase CLI here and give the agent a scoped key for one non-production project.", docs: DOCS.supabase, deny: ["Bash(supabase db reset*)", "Bash(supabase projects delete*)"] },
  netlify_token: { severity: "high", group: "cloud", consequence: "Your agent can delete or redeploy your Netlify sites", fix: "Log out of the Netlify CLI where agents run; use a personal access token with an expiry.", docs: "", deny: ["Bash(netlify sites:delete*)"] },
  heroku_token: { severity: "high", group: "cloud", consequence: "Your agent can destroy Heroku apps and databases", fix: "Log out of the Heroku CLI here (heroku logout) and use an authorization limited in scope and time.", docs: "", deny: ["Bash(heroku apps:destroy*)", "Bash(heroku pg:reset*)"] },
  prod_database_url: { severity: "critical", group: "prod", consequence: "Your agent can delete your production database: a database URL that looks like production is in its environment", fix: "Keep production DATABASE_URL out of the environment and .env files the agent can read; use a staging or read-only database user.", docs: "", deny: ["Read(./.env*)", "Bash(psql*DROP*)", "Bash(prisma migrate reset*)"] },
  env_secrets: { severity: "medium", group: "secrets", consequence: "Your agent can read API keys and tokens and send them anywhere", fix: "Deny reading .env files to the agent and load secrets only in the process that needs them.", docs: "", deny: ["Read(./.env*)", "Bash(cat .env*)", "Bash(printenv*)"] },
  gh_admin_token: { severity: "critical", group: "git", consequence: "Your agent can delete your GitHub repositories: the CLI token has delete_repo or admin scope", fix: "Re-authenticate gh with a fine-grained token limited to the repositories and permissions the agent needs.", docs: DOCS.github, deny: ["Bash(gh repo delete*)", "Bash(gh api -X DELETE*)"] },
  gh_token: { severity: "medium", group: "git", consequence: "Your agent can push code, open and merge pull requests as you", fix: "Use a fine-grained GitHub token for agent work, limited to the repository.", docs: DOCS.github, deny: ["Bash(gh pr merge*)", "Bash(gh repo delete*)"] },
  unprotected_branch: { severity: "high", group: "git", consequence: "Your agent can force-push over your default branch and rewrite its history", fix: "Protect the default branch: gh api -X PUT repos/OWNER/REPO/branches/BRANCH/protection with required reviews and no force pushes (see docs).", docs: DOCS.protection, deny: ["Bash(git push --force*)", "Bash(git push -f*)", "Bash(git push * --force*)"] },
  ssh_key_no_passphrase: { severity: "high", group: "secrets", consequence: "Your agent can use or copy SSH keys that have no passphrase", fix: "Add a passphrase (ssh-keygen -p -f <key>) and use ssh-agent; deny reading ~/.ssh to the agent.", docs: DOCS.ssh, deny: ["Read(~/.ssh/**)", "Bash(cat ~/.ssh*)"] },
  agent_bypass_permissions: { severity: "critical", group: "agent", consequence: "Your agent runs every command without asking: permissions are bypassed", fix: "Remove bypassPermissions / --dangerously-skip-permissions from the agent settings and allow only the commands you need.", docs: "https://docs.claude.com/en/docs/claude-code/settings", deny: [] },
  agent_broad_allow: { severity: "high", group: "agent", consequence: "Your agent can run any shell command without asking: a wildcard is pre-approved", fix: "Replace Bash(*) with the specific commands the project needs (npm test, git status...).", docs: "https://docs.claude.com/en/docs/claude-code/iam", deny: [] },
  agent_secrets_readable: { severity: "medium", group: "agent", consequence: "Nothing stops your agent from reading .env files and SSH keys", fix: "Add deny rules for .env files and ~/.ssh in the agent settings.", docs: "https://docs.claude.com/en/docs/claude-code/iam", deny: ["Read(./.env*)", "Read(~/.ssh/**)"] },
  mcp_filesystem_wide: { severity: "high", group: "agent", consequence: "An MCP server gives your agent read and write access to your whole home folder or disk", fix: "Scope filesystem MCP servers to the project folder.", docs: "https://modelcontextprotocol.io/docs/concepts/roots", deny: [] },
  mcp_unknown_source: { severity: "medium", group: "agent", consequence: "Your agent runs an MCP server from an unreviewed source with your permissions", fix: "Pin MCP servers to known publishers and exact versions, or run them behind the AgentLeisure MCP gateway.", docs: "https://agentleisure.com/mcp-gateway", deny: [] },
};

export const TYPES = Object.keys(FINDINGS);
export const GROUPS = [
  { id: "prod", title: "Can delete production" },
  { id: "cloud", title: "Holds cloud credentials" },
  { id: "git", title: "Can rewrite or delete repos" },
  { id: "secrets", title: "Can read secrets" },
  { id: "agent", title: "Agent runs unchecked" },
];

export function summarize(findings) {
  const counts = { critical: 0, high: 0, medium: 0 };
  for (const finding of findings) counts[FINDINGS[finding.type]?.severity ?? finding.severity] += 1;
  // 100 = contained. Critical findings cost the most.
  const score = Math.max(0, 100 - counts.critical * 25 - counts.high * 10 - counts.medium * 4);
  return { counts, score, contained: counts.critical === 0 && counts.high === 0 };
}

// Leaderboard columns: for each group, true = this setup is safe there.
export function groupColumns(types) {
  const present = new Set(types.map(type => FINDINGS[type]?.group));
  return GROUPS.map(group => !present.has(group.id));
}

export const HOOK_COMMAND = "npx -y agentleisure-guard hook";

// The agent-settings part of the fix: deny rules for what was found plus the local guard hook.
export function settingsPatch(types) {
  const deny = new Set(["Read(./.env*)", "Read(~/.ssh/**)", "Bash(rm -rf*)", "Bash(git push --force*)"]);
  for (const type of types) for (const rule of FINDINGS[type]?.deny ?? []) deny.add(rule);
  return {
    permissions: { deny: [...deny] },
    hooks: { PreToolUse: [{ matcher: "Bash|Write|Edit|WebFetch", hooks: [{ type: "command", command: HOOK_COMMAND }] }] },
  };
}

export function fixText(types) {
  const lines = ["// .claude/settings.json (merge into yours; `npx agentleisure-guard blast --fix` does it with a backup)", JSON.stringify(settingsPatch(types), null, 2)];
  const manual = types.filter((type, index) => types.indexOf(type) === index && FINDINGS[type]);
  if (manual.length) {
    lines.push("", "// Outside the agent settings (do these yourself):");
    for (const type of manual) lines.push(`// - ${FINDINGS[type].fix}${FINDINGS[type].docs ? ` ${FINDINGS[type].docs}` : ""}`);
  }
  return lines.join("\n");
}

// Anything that looks like a credential is refused, even in the free-text setup name.
export const SECRET_SHAPE = /(sk_(live|test)_|sk-[A-Za-z0-9]{16}|ghp_|gho_|ghs_|github_pat_|glpat-|xox[abprs]-|AKIA[0-9A-Z]{8}|ASIA[0-9A-Z]{8}|AIza[0-9A-Za-z_-]{10}|-----BEGIN|eyJ[A-Za-z0-9_-]{12,}\.|[A-Za-z0-9+/_=-]{32,}|postgres(ql)?:\/\/|mysql:\/\/|mongodb(\+srv)?:\/\/|:\/\/[^\s/]*:[^\s/]*@)/;
