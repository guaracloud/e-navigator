import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(fileURLToPath(import.meta.url));
const failures = [];
const linkPattern = /\b(?:href|src)="([^"]+)"/g;

function htmlFiles(directory) {
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const path = resolve(directory, entry.name);
    if (entry.isDirectory()) return htmlFiles(path);
    return entry.isFile() && entry.name.endsWith(".html") ? [path] : [];
  });
}

function isInsideSite(path) {
  const pathFromRoot = relative(root, path);
  return pathFromRoot !== ".." && !pathFromRoot.startsWith(`..${sep}`);
}

function hasFragment(path, fragment) {
  if (!fragment || !path.endsWith(".html")) return true;
  const html = readFileSync(path, "utf8");
  const escaped = fragment.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return new RegExp(`\\b(?:id|name)="${escaped}"`).test(html);
}

for (const htmlPath of htmlFiles(root)) {
  const html = readFileSync(htmlPath, "utf8");

  for (const match of html.matchAll(linkPattern)) {
    const reference = match[1];
    if (
      reference.startsWith("http://") ||
      reference.startsWith("https://") ||
      reference.startsWith("mailto:") ||
      reference.startsWith("//")
    ) {
      continue;
    }

    const [pathPart, fragment = ""] = reference.split("#", 2);
    let target = pathPart
      ? pathPart.startsWith("/")
        ? resolve(root, `.${pathPart}`)
        : resolve(dirname(htmlPath), pathPart)
      : htmlPath;

    if (!isInsideSite(target)) {
      failures.push(`${relative(root, htmlPath)}: ${reference} escapes the deployed site`);
      continue;
    }
    if (existsSync(target) && statSync(target).isDirectory()) {
      target = resolve(target, "index.html");
    }
    if (!existsSync(target)) {
      failures.push(`${relative(root, htmlPath)}: ${reference} is missing`);
      continue;
    }
    if (!hasFragment(target, fragment)) {
      failures.push(`${relative(root, htmlPath)}: ${reference} has no matching fragment`);
    }
  }
}

if (failures.length > 0) {
  console.error("Broken local website links:");
  for (const failure of failures) console.error(`- ${failure}`);
  process.exit(1);
}

console.log(`Local website links ok across ${htmlFiles(root).length} HTML files`);
