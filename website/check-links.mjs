import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(fileURLToPath(import.meta.url));
const htmlPath = resolve(root, "index.html");
const html = readFileSync(htmlPath, "utf8");
const linkPattern = /\b(?:href|src)="([^"]+)"/g;
const failures = [];

for (const match of html.matchAll(linkPattern)) {
  const target = match[1];

  if (
    target.startsWith("#") ||
    target.startsWith("http://") ||
    target.startsWith("https://") ||
    target.startsWith("mailto:")
  ) {
    continue;
  }

  if (target.startsWith("../")) {
    failures.push(`${target} (escapes the deployed Pages artifact)`);
    continue;
  }

  const cleanTarget = target.split("#")[0].split("?")[0];
  const absoluteTarget = resolve(root, cleanTarget);

  if (!existsSync(absoluteTarget)) {
    failures.push(target);
  }
}

if (failures.length > 0) {
  console.error("Broken local links:");
  for (const failure of failures) {
    console.error(`- ${failure}`);
  }
  process.exit(1);
}

console.log("Local links ok");
