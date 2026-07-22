import fs from "node:fs";
import path from "node:path";
import { spawn } from "node:child_process";
import { ConfigStore, scanText } from "./policy.mjs";
const root = process.env.HERDR_PLUGIN_ROOT ?? path.resolve(new URL("..", import.meta.url).pathname);
const configDir = process.env.HERDR_PLUGIN_CONFIG_DIR ?? path.join(process.env.HOME ?? ".", ".config/herdr-guard");
const stateDir = process.env.HERDR_PLUGIN_STATE_DIR ?? path.join(process.env.HOME ?? ".", ".local/state/herdr-guard");
const store = () => new ConfigStore({ configDir, defaultsPath: path.join(root, "src/rules-default.json") });
const herdr = process.env.HERDR_BIN_PATH ?? "herdr";
function run(args) { return new Promise((resolve) => { const p = spawn(herdr, args, {stdio:"inherit"}); p.on("close", (code) => resolve(code ?? 1)); }); }
function seed() { const s = store(); s.seedIfMissing(); return s; }
const action = process.argv[2] ?? "status";
if (action === "startup") { seed(); process.exit(0); }
if (action === "watchdog") { const payload = process.env.HERDR_PLUGIN_EVENT_JSON ?? ""; let id = null; try { id = fs.readFileSync(path.join(stateDir, "guard-pane.id"), "utf8").trim(); } catch {} if (id && payload.includes(id)) await run(["notification", "show", "herdr-guard", "Guard pane exited; reopen it with the Guard action."]); process.exit(0); }
if (action === "open") process.exit(await run(["plugin", "pane", "open", "--plugin", "structupath.guard", "--entrypoint", "guard", "--placement", "split", "--focus"]));
const s = seed();
if (action === "pause" || action === "resume") { s.load(); const until = action === "pause" ? Date.now() + 15 * 60 * 1000 : null; s.setEnforcement(action === "pause" ? "paused" : "active", { pausedUntil: until }); console.log(`${action}: enforcement ${action === "pause" ? "paused" : "active"}`); process.exit(0); }
if (action === "reset-rules") { if (fs.existsSync(s.file)) fs.copyFileSync(s.file, `${s.file}.backup-${Date.now()}`); fs.rmSync(s.file, {force:true}); s.seedIfMissing(); console.log(`rules reset in ${s.file}`); process.exit(0); }
if (action === "test") { const input = process.argv.slice(3).join(" "); if (!input) { console.error("usage: action test <command text>"); process.exit(2); } const loaded = s.load(); for (const match of scanText(`$ ${input}`, loaded.config?.rules ?? [])) console.log(`${match.rule.severity}\t${match.rule.id}\t${match.rule.reason}`); process.exit(0); }
console.error(`unknown action: ${action}`); process.exit(2);
