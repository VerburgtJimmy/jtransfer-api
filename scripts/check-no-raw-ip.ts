#!/usr/bin/env bun
// CI guardrail for IP minimization. See docs/audit/19-ip-minimization.md §4.6.
//
// Fails the build if any of the following slip back in:
//   1. `inet(` reappears in schema or migrations (no raw-IP columns).
//   2. The deleted `normalizeClientIp` / `ipForStorage` helpers are
//      reintroduced anywhere in `src/`.
//   3. Raw client-IP header reads (`cf-connecting-ip`, `x-forwarded-for`)
//      appear outside `src/utils/ipContext.ts` — the single chokepoint.
//
// Run via `bun run check:no-raw-ip` (wired into `bun run check`).

import { readdir, readFile } from "node:fs/promises";
import { join, relative } from "node:path";

const REPO = new URL("..", import.meta.url).pathname;
const SRC = join(REPO, "src");
const MIGRATIONS = join(REPO, "drizzle");

interface Finding {
  rule: string;
  file: string;
  line: number;
  snippet: string;
}

const findings: Finding[] = [];

function record(rule: string, file: string, contents: string, predicate: (line: string) => boolean) {
  const lines = contents.split("\n");
  for (let i = 0; i < lines.length; i++) {
    if (predicate(lines[i])) {
      findings.push({
        rule,
        file: relative(REPO, file),
        line: i + 1,
        snippet: lines[i].trim().slice(0, 120),
      });
    }
  }
}

async function walk(dir: string, ext: RegExp): Promise<string[]> {
  const out: string[] = [];
  const entries = await readdir(dir, { withFileTypes: true });
  for (const e of entries) {
    const full = join(dir, e.name);
    if (e.isDirectory()) {
      if (e.name === "node_modules" || e.name === ".git" || e.name === "dist") continue;
      out.push(...(await walk(full, ext)));
    } else if (ext.test(e.name)) {
      out.push(full);
    }
  }
  return out;
}

function isCommentLine(line: string): boolean {
  const t = line.trim();
  return t.startsWith("//") || t.startsWith("*") || t.startsWith("/*");
}

const SELF = join(REPO, "scripts/check-no-raw-ip.ts");
const IP_CONTEXT = join(SRC, "utils/ipContext.ts");

const tsFiles = await walk(SRC, /\.(ts|tsx)$/);
const migrationFiles = (await walk(MIGRATIONS, /\.sql$/)).filter((f) => !f.includes("/meta/"));
const schemaFile = join(SRC, "db/schema.ts");

// Rule 1: no `inet(` in schema or migrations.
for (const file of [schemaFile, ...migrationFiles]) {
  let body: string;
  try {
    body = await readFile(file, "utf8");
  } catch {
    continue;
  }
  record("no-inet", file, body, (l) => /\binet\s*\(/.test(l) && !isCommentLine(l));
}

// Rule 2: deleted helpers must not return.
const DELETED_HELPERS = ["normalizeClientIp", "ipForStorage"] as const;
for (const file of tsFiles) {
  if (file === SELF) continue;
  const body = await readFile(file, "utf8");
  for (const name of DELETED_HELPERS) {
    record(`no-deleted-helper:${name}`, file, body, (l) =>
      new RegExp(`\\b${name}\\b`).test(l) && !isCommentLine(l),
    );
  }
}

// Rule 3: raw-IP header reads only allowed inside ipContext.ts.
const RAW_IP_HEADER_RE = /headers\.get\(\s*["'](cf-connecting-ip|x-forwarded-for)["']/i;
for (const file of tsFiles) {
  if (file === IP_CONTEXT || file === SELF) continue;
  const body = await readFile(file, "utf8");
  record("no-raw-ip-header-read", file, body, (l) => RAW_IP_HEADER_RE.test(l) && !isCommentLine(l));
}

if (findings.length > 0) {
  console.error(`[check-no-raw-ip] FAIL — ${findings.length} violation(s):\n`);
  for (const f of findings) {
    console.error(`  ${f.rule}\n    ${f.file}:${f.line}  ${f.snippet}`);
  }
  console.error(
    "\nIP minimization (audit doc 19 / ADR-0002) requires that no raw IP is " +
      "persisted, logged, keyed, or read outside src/utils/ipContext.ts. " +
      "Resolve the violations above before merging.",
  );
  process.exit(1);
}

console.log("[check-no-raw-ip] OK");
