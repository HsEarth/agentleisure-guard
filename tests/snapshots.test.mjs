import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { changesFiles, listSnapshots, pathsIn, restoreSnapshot, takeSnapshot } from "../snapshots.mjs";
import { createMcpGuard } from "../mcp-guard.mjs";

function workspace() {
  const root = mkdtempSync(join(tmpdir(), "al-undo-"));
  const project = join(root, "project"); const store = join(root, "snapshots");
  mkdirSync(join(project, "src"), { recursive: true });
  writeFileSync(join(project, "src", "app.js"), "console.log('v1');\n");
  writeFileSync(join(project, "notes.txt"), "keep me\n");
  return { root, project, store };
}

test("which calls change files", () => {
  assert.ok(changesFiles("write_file", { path: "a" }));
  assert.ok(changesFiles("shell", { command: "rm -rf build" }));
  assert.ok(changesFiles("move_file", {}));
  assert.ok(!changesFiles("read_file", { path: "a" }));
  assert.ok(!changesFiles("search", { query: "x" }));
});

test("paths: existing ones only, no roots, nested paths collapse into their parent", () => {
  const { project } = workspace();
  const found = pathsIn({ command: `rm -rf ${join(project, "src")} ${join(project, "src", "app.js")} /definitely/missing`, also: "/" }, project);
  assert.deepEqual(found, [join(project, "src")]);
  assert.deepEqual(pathsIn({ path: project }, project), [], "the working directory itself is not snapshotted");
});

test("snapshot, delete, undo, and undo the undo", () => {
  const { project, store } = workspace();
  const file = join(project, "notes.txt"); const dir = join(project, "src");
  const shot = takeSnapshot({ tool: "shell", args: { command: `rm -rf ${dir} ${file}` }, dir: store, cwd: project, now: 1_000 });
  rmSync(dir, { recursive: true }); rmSync(file);
  assert.ok(!existsSync(file));
  const restored = restoreSnapshot(shot.id, store, 2_000);
  assert.equal(readFileSync(file, "utf8"), "keep me\n");
  assert.equal(readFileSync(join(dir, "app.js"), "utf8"), "console.log('v1');\n");
  assert.equal(restored.previous, null, "nothing was there to save");
  writeFileSync(file, "edited after restore\n");
  const second = restoreSnapshot(shot.id, store, 3_000);
  assert.equal(readFileSync(file, "utf8"), "keep me\n");
  assert.ok(second.previous, "the edited state was saved before the second restore");
  restoreSnapshot(second.previous, store, 4_000);
  assert.equal(readFileSync(file, "utf8"), "edited after restore\n");
  assert.ok(listSnapshots(store).length >= 2);
  assert.throws(() => restoreSnapshot("../../etc", store), /bad snapshot id/);
});

test("the gateway snapshots before a file-changing call and tells the agent how to undo", async () => {
  const { project, store } = workspace();
  const file = join(project, "notes.txt");
  const guard = createMcpGuard({ snapshotDir: store, log: () => {} });
  const forwarded = await guard.fromClient({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "write_file", arguments: { path: file, content: "new" } } });
  assert.ok(forwarded.forward);
  const [snapshot] = listSnapshots(store);
  assert.equal(snapshot.items[0].original, file);
  const result = guard.fromServer({ jsonrpc: "2.0", id: 1, result: { content: [{ type: "text", text: "written" }] } });
  assert.match(result.result.content.at(-1).text, new RegExp(`agentleisure-guard undo ${snapshot.id}`));
  await guard.fromClient({ jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "read_file", arguments: { path: file } } });
  assert.equal(listSnapshots(store).length, 1, "reads are not snapshotted");
});
