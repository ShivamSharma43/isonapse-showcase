#!/usr/bin/env node
// Merge the Isonapse hook entries into a Gemini CLI settings.json without
// touching any other setting. Prints the merged JSON; never writes in place.
//
//   node render-settings.mjs --node /abs/node --adapter /abs/gemini_hook.mjs \
//     --hook /abs/isonapse-hook --pin-file ~/.isonapse/adk/hook.sha256 \
//     --host adk-gemini-<digest> [--settings ~/.gemini/settings.json] [--no-ask]
import {readFileSync, existsSync} from "node:fs";
import {isAbsolute, resolve} from "node:path";
import {parseArgs} from "node:util";

const {values} = parseArgs({options: {
  node: {type: "string"}, adapter: {type: "string"}, hook: {type: "string"},
  "pin-file": {type: "string"}, host: {type: "string"}, settings: {type: "string"}, "no-ask": {type: "boolean"},
}, strict: true});
for (const key of ["node", "adapter", "hook", "pin-file", "host"]) {
  if (!values[key]) throw new Error(`--${key} is required`);
  if (key !== "host" && !isAbsolute(values[key])) throw new Error(`--${key} must be an absolute path`);
  if (key !== "host" && /'/.test(values[key])) throw new Error(`--${key} must not contain a single quote`);
}
if (!/^[a-z][a-z0-9-]{0,92}$/.test(values.host)) throw new Error("--host must be the registered host id");

const template = readFileSync(resolve(import.meta.dirname, "settings.hooks.template.json"), "utf8")
  .replaceAll("__NODE__", values.node).replaceAll("__ADAPTER__", values.adapter)
  .replaceAll("__HOOK_SHA256_FILE__", values["pin-file"]).replaceAll("__HOOK__", values.hook)
  .replaceAll("__HOST_ID__", values.host);
const ours = JSON.parse(template).hooks;
if (values["no-ask"]) for (const list of Object.values(ours)) for (const entry of list) for (const h of entry.hooks) h.command += " --no-ask";

const settings = values.settings && existsSync(values.settings) ? JSON.parse(readFileSync(values.settings, "utf8")) : {};
settings.hooks ??= {};
for (const [event, entries] of Object.entries(ours)) {
  // Replace a previous Isonapse entry, keep everyone else's hooks.
  const others = (settings.hooks[event] ?? []).filter(e => !(e.hooks ?? []).some(h => h.name === "isonapse"));
  settings.hooks[event] = [...entries, ...others];
}
process.stdout.write(JSON.stringify(settings, null, 2) + "\n");
