// Undo for agents: before a call that deletes, moves or overwrites local files, copy what it will touch into a snapshot.
// `agentleisure-guard undo` lists snapshots and restores one. Snapshots live in ~/.agentleisure/snapshots by default.
import { cpSync, existsSync, lstatSync, mkdirSync, readdirSync, readFileSync, renameSync, rmSync, statSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { isAbsolute, join, resolve } from "node:path";
import { DEFAULT_DESTRUCTIVE, scanText } from "./agent-guard.mjs";

export const DEFAULT_SNAPSHOT_DIR = join(homedir(), ".agentleisure", "snapshots");
const WRITE_TOOL = /(write|edit|move|rename|delete|remove|unlink|rm\b|rmdir|overwrite|replace|truncate|save|patch)/i;
const MAX_BYTES = 200 * 1024 * 1024;
const KEEP = 100;

// Does this call change or remove files? Destructive rules, or a tool whose name says it writes, moves or deletes.
export function changesFiles(tool, args) {
  const body = `${tool}\n${scanText(args)}`;
  return WRITE_TOOL.test(tool) || DEFAULT_DESTRUCTIVE.some(pattern => pattern.test(body));
}

// Existing local paths mentioned in the arguments: string values, and words in command lines.
export function pathsIn(args, cwd = process.cwd()) {
  const found = new Set();
  const consider = raw => {
    const value = raw.trim().replace(/^['"]|['"]$/g, "");
    if (!value || value.length > 1024 || /^[a-z]+:\/\//i.test(value) || value === "/" || /^[A-Za-z]:[\\/]?$/.test(value) || value === "." || value === "~") return;
    const full = isAbsolute(value) ? value : resolve(cwd, value.replace(/^~(?=[\\/])/, homedir()));
    if (full === homedir() || full === resolve(cwd)) return;
    try { if (existsSync(full)) found.add(full); } catch { /* not a path */ }
  };
  const walk = (value, depth = 0) => {
    if (depth > 6 || value == null) return;
    if (typeof value === "string") { consider(value); for (const word of value.split(/\s+/)) if (/[\\/.]/.test(word) && !word.startsWith("-")) consider(word); return; }
    if (typeof value === "object") for (const item of Object.values(value)) walk(item, depth + 1);
  };
  walk(args);
  // Drop paths inside other found paths: copying the parent already covers them.
  return [...found].filter(path => ![...found].some(other => other !== path && path.startsWith(other.endsWith("/") || other.endsWith("\\") ? other : `${other}${path.includes("\\") ? "\\" : "/"}`)));
}

function sizeOf(path, limit) {
  let total = 0;
  const stack = [path];
  while (stack.length) {
    const current = stack.pop();
    const info = lstatSync(current);
    if (info.isSymbolicLink()) continue;
    if (info.isDirectory()) for (const name of readdirSync(current)) stack.push(join(current, name));
    else total += info.size;
    if (total > limit) return total;
  }
  return total;
}

export function takeSnapshot({ tool, args, dir = DEFAULT_SNAPSHOT_DIR, cwd = process.cwd(), now = Date.now() }) {
  const paths = pathsIn(args, cwd);
  if (!paths.length) return null;
  let bytes = 0;
  for (const path of paths) { bytes += sizeOf(path, MAX_BYTES); if (bytes > MAX_BYTES) return { skipped: "too_large", paths }; }
  const id = `${new Date(now).toISOString().replace(/[-:]/g, "").replace(/\..+/, "")}-${Math.random().toString(36).slice(2, 7)}`;
  const target = join(dir, id);
  mkdirSync(target, { recursive: true });
  const items = paths.map((original, index) => {
    const stored = join(target, String(index));
    cpSync(original, stored, { recursive: true, verbatimSymlinks: true, errorOnExist: false });
    return { original, stored: String(index), type: statSync(original).isDirectory() ? "dir" : "file" };
  });
  writeFileSync(join(target, "manifest.json"), JSON.stringify({ id, ts: new Date(now).toISOString(), tool, args: scanText(args).slice(0, 500), items }, null, 2));
  prune(dir);
  return { id, paths, bytes };
}

export function listSnapshots(dir = DEFAULT_SNAPSHOT_DIR) {
  if (!existsSync(dir)) return [];
  return readdirSync(dir).filter(name => existsSync(join(dir, name, "manifest.json"))).sort().reverse()
    .map(name => JSON.parse(readFileSync(join(dir, name, "manifest.json"), "utf8")));
}

function prune(dir) {
  for (const old of listSnapshots(dir).slice(KEEP)) rmSync(join(dir, old.id), { recursive: true, force: true });
}

// Put every item back. Whatever is there now is first moved into a new snapshot, so an undo can itself be undone.
export function restoreSnapshot(id, dir = DEFAULT_SNAPSHOT_DIR, now = Date.now()) {
  if (!/^[0-9T]+-[a-z0-9]+$/.test(id)) throw new Error("bad snapshot id");
  const manifestPath = join(dir, id, "manifest.json");
  if (!existsSync(manifestPath)) throw new Error(`snapshot ${id} not found`);
  const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
  const current = manifest.items.map(item => item.original).filter(path => existsSync(path));
  const before = current.length ? takeSnapshot({ tool: `undo ${id} (state before restore)`, args: current, dir, now }) : null;
  for (const item of manifest.items) {
    if (existsSync(item.original)) {
      const aside = `${item.original}.agentleisure-undo-${now}`;
      renameSync(item.original, aside);
      rmSync(aside, { recursive: true, force: true });
    }
    cpSync(join(dir, id, item.stored), item.original, { recursive: true, verbatimSymlinks: true });
  }
  return { restored: manifest.items.map(item => item.original), previous: before?.id ?? null };
}
