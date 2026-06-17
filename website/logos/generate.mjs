/**
 * E-Navigator logo asset generator.
 *
 * Converts the chroma-key source logo into transparent source assets,
 * favicons, app icons, maskable icons, social cards, and background variants.
 */
import { mkdir, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import sharp from "sharp";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const BRAND_NAME = "E-Navigator";
const TAGLINE = "Rust and eBPF observability for Linux and Kubernetes";
const SOURCE_FILE = "e-navigator-logo-with-bg.png";
const SRC = path.resolve(__dirname, SOURCE_FILE);
const OUT_DIR = path.resolve(__dirname, "generated");

const BRAND = {
  background: "#0f0620",
  background2: "#24104a",
  purple: "#8b45f6",
  purpleLight: "#d9adff",
  violet: "#b263ff",
  ink: "#080413",
  white: "#ffffff",
};

const FAVICON_SIZES = [16, 32, 48, 96];
const APP_ICON_SIZES = [180, 192, 512];
const MASKABLE_ICON_SIZES = [192, 512];

function clamp(value, min, max) {
  return Math.max(min, Math.min(max, value));
}

function distance(a, b) {
  const dr = a.r - b.r;
  const dg = a.g - b.g;
  const db = a.b - b.b;
  return Math.sqrt(dr * dr + dg * dg + db * db);
}

function averageColor(samples) {
  const totals = samples.reduce(
    (acc, color) => ({
      r: acc.r + color.r,
      g: acc.g + color.g,
      b: acc.b + color.b,
    }),
    { r: 0, g: 0, b: 0 },
  );

  return {
    r: Math.round(totals.r / samples.length),
    g: Math.round(totals.g / samples.length),
    b: Math.round(totals.b / samples.length),
  };
}

function escapeXml(text) {
  return text
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

async function metadataFor(bufferOrPath) {
  const metadata = await sharp(bufferOrPath).metadata();
  return {
    width: metadata.width,
    height: metadata.height,
    format: metadata.format,
    hasAlpha: Boolean(metadata.hasAlpha),
  };
}

async function sampleKeyColor(inputPath) {
  const sampleSize = 32;
  const image = sharp(inputPath);
  const { width, height } = await image.metadata();

  const regions = [
    { left: 0, top: 0 },
    { left: width - sampleSize, top: 0 },
    { left: 0, top: height - sampleSize },
    { left: width - sampleSize, top: height - sampleSize },
    { left: Math.round((width - sampleSize) / 2), top: 0 },
    { left: Math.round((width - sampleSize) / 2), top: height - sampleSize },
    { left: 0, top: Math.round((height - sampleSize) / 2) },
    { left: width - sampleSize, top: Math.round((height - sampleSize) / 2) },
  ];

  const samples = [];
  for (const region of regions) {
    const { data } = await sharp(inputPath)
      .extract({ ...region, width: sampleSize, height: sampleSize })
      .raw()
      .toBuffer({ resolveWithObject: true });

    for (let i = 0; i < data.length; i += 3) {
      samples.push({ r: data[i], g: data[i + 1], b: data[i + 2] });
    }
  }

  return averageColor(samples);
}

function shouldKeyGreen(color, key, dist) {
  const greenDominant = color.g > color.r + 24 && color.g > color.b + 24;
  const brightGreen = color.g > 128 && color.r < 128 && color.b < 128;
  return greenDominant && (brightGreen || dist < 170);
}

async function chromaKey(inputPath) {
  const key = await sampleKeyColor(inputPath);
  const { data, info } = await sharp(inputPath)
    .ensureAlpha()
    .raw()
    .toBuffer({ resolveWithObject: true });

  const hardEdge = 70;
  const softEdge = 172;
  let transparentPixels = 0;
  let partialPixels = 0;
  let spillPixels = 0;

  for (let i = 0; i < data.length; i += 4) {
    const color = { r: data[i], g: data[i + 1], b: data[i + 2] };
    const dist = distance(color, key);

    if (!shouldKeyGreen(color, key, dist)) {
      continue;
    }

    if (dist <= hardEdge) {
      data[i + 3] = 0;
      transparentPixels++;
      continue;
    }

    if (dist < softEdge) {
      const alpha = Math.round(((dist - hardEdge) / (softEdge - hardEdge)) * 255);
      data[i + 3] = clamp(alpha, 0, 255);
      partialPixels++;
    }

    if (data[i + 3] > 0) {
      data[i + 1] = Math.min(color.g, Math.max(color.r, color.b) + 10);
      spillPixels++;
    }
  }

  return {
    key,
    transparentPixels,
    partialPixels,
    spillPixels,
    image: sharp(data, {
      raw: { width: info.width, height: info.height, channels: 4 },
    }),
  };
}

async function suppressGreenSpill(input) {
  const { data, info } = await sharp(input)
    .ensureAlpha()
    .raw()
    .toBuffer({ resolveWithObject: true });

  for (let i = 0; i < data.length; i += 4) {
    const r = data[i];
    const g = data[i + 1];
    const b = data[i + 2];
    const a = data[i + 3];
    if (a > 0 && g > r + 20 && g > b + 20) {
      data[i + 1] = Math.min(g, Math.max(r, b) + 10);
    }
  }

  return sharp(data, {
    raw: { width: info.width, height: info.height, channels: 4 },
  })
    .png()
    .toBuffer();
}

async function alphaStats(bufferOrPath) {
  const { data, info } = await sharp(bufferOrPath)
    .ensureAlpha()
    .raw()
    .toBuffer({ resolveWithObject: true });
  let transparent = 0;
  let opaque = 0;
  let partial = 0;

  for (let i = 3; i < data.length; i += 4) {
    if (data[i] === 0) transparent++;
    else if (data[i] === 255) opaque++;
    else partial++;
  }

  const pixels = info.width * info.height;
  return {
    transparent,
    opaque,
    partial,
    transparentRatio: Number((transparent / pixels).toFixed(4)),
    partialRatio: Number((partial / pixels).toFixed(4)),
  };
}

async function greenFringeStats(input) {
  const { data } = await sharp(input)
    .ensureAlpha()
    .raw()
    .toBuffer({ resolveWithObject: true });
  let suspicious = 0;
  let visible = 0;

  for (let i = 0; i < data.length; i += 4) {
    const r = data[i];
    const g = data[i + 1];
    const b = data[i + 2];
    const a = data[i + 3];
    if (a > 24) {
      visible++;
      if (g > r + 34 && g > b + 34) {
        suspicious++;
      }
    }
  }

  return { suspicious, visible };
}

function svgText({
  width,
  height,
  text,
  y,
  size,
  weight = 700,
  fill = BRAND.white,
  opacity = 1,
}) {
  return Buffer.from(`<svg width="${width}" height="${height}" xmlns="http://www.w3.org/2000/svg">
    <text x="${width / 2}" y="${y}" text-anchor="middle"
      font-family="Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, Segoe UI, sans-serif"
      font-size="${size}" font-weight="${weight}"
      fill="${fill}" opacity="${opacity}">${escapeXml(text)}</text>
  </svg>`);
}

function backgroundSvg(width, height, { rounded = 0 } = {}) {
  return Buffer.from(`<svg width="${width}" height="${height}" xmlns="http://www.w3.org/2000/svg">
    <defs>
      <linearGradient id="bg" x1="0%" y1="0%" x2="100%" y2="100%">
        <stop offset="0%" stop-color="${BRAND.background}"/>
        <stop offset="56%" stop-color="${BRAND.background2}"/>
        <stop offset="100%" stop-color="#35156d"/>
      </linearGradient>
      <radialGradient id="glow1" cx="50%" cy="33%" r="50%">
        <stop offset="0%" stop-color="${BRAND.purpleLight}" stop-opacity="0.26"/>
        <stop offset="100%" stop-color="${BRAND.purpleLight}" stop-opacity="0"/>
      </radialGradient>
      <radialGradient id="glow2" cx="72%" cy="72%" r="34%">
        <stop offset="0%" stop-color="${BRAND.violet}" stop-opacity="0.18"/>
        <stop offset="100%" stop-color="${BRAND.violet}" stop-opacity="0"/>
      </radialGradient>
    </defs>
    <rect width="${width}" height="${height}" rx="${rounded}" fill="url(#bg)"/>
    <ellipse cx="${width / 2}" cy="${height * 0.32}" rx="${width * 0.34}" ry="${height * 0.32}" fill="url(#glow1)"/>
    <ellipse cx="${width * 0.72}" cy="${height * 0.72}" rx="${width * 0.26}" ry="${height * 0.24}" fill="url(#glow2)"/>
  </svg>`);
}

async function writePng(assets, name, input, options = {}) {
  const outputPath = path.join(OUT_DIR, name);
  const prepared = options.skipSpillSuppression
    ? input
    : await suppressGreenSpill(input);
  await sharp(prepared)
    .png({ compressionLevel: 9, adaptiveFiltering: true })
    .toFile(outputPath);
  const asset = { name, path: outputPath, ...(await metadataFor(outputPath)) };
  assets.push(asset);
  return asset;
}

async function composeCentered({
  width,
  height,
  background,
  logo,
  logoSize,
  top,
}) {
  const resizedLogo = await sharp(logo)
    .resize(logoSize, logoSize, {
      fit: "contain",
      background: { r: 0, g: 0, b: 0, alpha: 0 },
    })
    .png()
    .toBuffer();
  const logoMeta = await sharp(resizedLogo).metadata();

  return sharp(background)
    .composite([
      {
        input: resizedLogo,
        left: Math.round((width - logoMeta.width) / 2),
        top: top ?? Math.round((height - logoMeta.height) / 2),
      },
    ])
    .png()
    .toBuffer();
}

async function createLogoOnFlatBackground(assets, name, logo, background) {
  const size = 1024;
  const base = {
    create: {
      width: size,
      height: size,
      channels: 4,
      background,
    },
  };

  return writePng(
    assets,
    name,
    await composeCentered({
      width: size,
      height: size,
      background: base,
      logo,
      logoSize: 900,
    }),
    { skipSpillSuppression: true },
  );
}

async function validateGeneratedAssets({
  assets,
  logoBuffer,
  sourceMeta,
  chromaStats,
}) {
  const byName = new Map(assets.map((asset) => [asset.name, asset]));
  const requiredDimensions = {
    "logo-square-transparent.png": [1024, 1024],
    "icon-transparent.png": [1024, 1024],
    "favicon-16.png": [16, 16],
    "favicon-32.png": [32, 32],
    "favicon-48.png": [48, 48],
    "favicon-96.png": [96, 96],
    "apple-touch-icon.png": [180, 180],
    "icon-192.png": [192, 192],
    "icon-512.png": [512, 512],
    "maskable-icon-192.png": [192, 192],
    "maskable-icon-512.png": [512, 512],
    "og-image.png": [1200, 630],
    "social-square.png": [1200, 1200],
    "logo-on-white.png": [1024, 1024],
    "logo-on-dark.png": [1024, 1024],
  };

  for (const [name, [width, height]] of Object.entries(requiredDimensions)) {
    const asset = byName.get(name);
    if (!asset) {
      throw new Error(`Missing generated asset: ${name}`);
    }
    if (asset.width !== width || asset.height !== height) {
      throw new Error(
        `${name} is ${asset.width}x${asset.height}, expected ${width}x${height}`,
      );
    }
  }

  const trimmedLogo = byName.get("logo-transparent.png");
  if (!trimmedLogo) {
    throw new Error("Missing generated asset: logo-transparent.png");
  }
  const minTrimmedSide = sourceMeta.width * 0.6;
  const maxTrimmedSide = sourceMeta.width * 0.9;
  if (
    trimmedLogo.width < minTrimmedSide ||
    trimmedLogo.height < minTrimmedSide ||
    trimmedLogo.width > maxTrimmedSide ||
    trimmedLogo.height > maxTrimmedSide
  ) {
    throw new Error(
      `logo-transparent.png trim is ${trimmedLogo.width}x${trimmedLogo.height}, expected each side between ${Math.round(minTrimmedSide)} and ${Math.round(maxTrimmedSide)}`,
    );
  }

  if (sourceMeta.width !== sourceMeta.height) {
    throw new Error(
      `Source logo must be square, got ${sourceMeta.width}x${sourceMeta.height}`,
    );
  }

  const sourcePixels = sourceMeta.width * sourceMeta.height;
  if (chromaStats.transparentPixels < sourcePixels * 0.25) {
    throw new Error(
      "Chroma-key removed too few pixels; source green may not have been extracted.",
    );
  }

  const logoStats = await alphaStats(logoBuffer);
  if (logoStats.transparentRatio < 0.18) {
    throw new Error(
      `Transparent logo has too little transparency: ${logoStats.transparentRatio}`,
    );
  }

  const allowedGreenPixels = {
    "logo-transparent.png": 48,
    "logo-square-transparent.png": 48,
    "icon-transparent.png": 48,
    "icon-512.png": 6,
    "maskable-icon-512.png": 8,
    "og-image.png": 16,
    "social-square.png": 18,
  };

  const fringeStats = {};
  for (const [name, allowed] of Object.entries(allowedGreenPixels)) {
    const stats = await greenFringeStats(byName.get(name).path);
    fringeStats[name] = stats;
    if (stats.suspicious > allowed) {
      throw new Error(
        `${name} has ${stats.suspicious} visible green-fringe pixels; allowed ${allowed}`,
      );
    }
  }

  return { logoStats, fringeStats };
}

async function main() {
  console.log(`${BRAND_NAME} Logo Generator\n`);
  await rm(OUT_DIR, { recursive: true, force: true });
  await mkdir(OUT_DIR, { recursive: true });

  const sourceMeta = await metadataFor(SRC);
  console.log(
    `1. Reading ${SOURCE_FILE} (${sourceMeta.width}x${sourceMeta.height})`,
  );

  console.log("2. Removing chroma-key background...");
  const keyed = await chromaKey(SRC);
  const transparentSourceBuffer = await keyed.image.png().toBuffer();
  console.log(
    `   key rgb(${keyed.key.r}, ${keyed.key.g}, ${keyed.key.b}); removed ${keyed.transparentPixels.toLocaleString()} pixels`,
  );

  const logoBuffer = await sharp(transparentSourceBuffer)
    .trim({ threshold: 8 })
    .png()
    .toBuffer();
  const squareLogoBuffer = await sharp(logoBuffer)
    .resize(1024, 1024, {
      fit: "contain",
      background: { r: 0, g: 0, b: 0, alpha: 0 },
    })
    .png()
    .toBuffer();
  const iconBuffer = await sharp(squareLogoBuffer)
    .resize(1024, 1024, {
      fit: "contain",
      background: { r: 0, g: 0, b: 0, alpha: 0 },
    })
    .png()
    .toBuffer();

  console.log("3. Writing transparent source assets...");
  const assets = [];
  await writePng(assets, "logo-transparent.png", logoBuffer);
  await writePng(assets, "logo-square-transparent.png", squareLogoBuffer);
  await writePng(assets, "icon-transparent.png", iconBuffer);

  console.log("4. Writing favicons and transparent app icons...");
  for (const size of FAVICON_SIZES) {
    const resized = await sharp(iconBuffer)
      .resize(size, size, {
        fit: "contain",
        background: { r: 0, g: 0, b: 0, alpha: 0 },
      })
      .png()
      .toBuffer();
    await writePng(assets, `favicon-${size}.png`, resized);
  }

  for (const size of APP_ICON_SIZES) {
    const resized = await sharp(iconBuffer)
      .resize(size, size, {
        fit: "contain",
        background: { r: 0, g: 0, b: 0, alpha: 0 },
      })
      .png()
      .toBuffer();
    const name = size === 180 ? "apple-touch-icon.png" : `icon-${size}.png`;
    await writePng(assets, name, resized);
  }

  console.log("5. Writing branded and maskable icons...");
  for (const size of [16, 32, 48, 96, 180, 192, 512]) {
    const background = backgroundSvg(size, size, {
      rounded: Math.round(size * 0.19),
    });
    const branded = await composeCentered({
      width: size,
      height: size,
      background,
      logo: iconBuffer,
      logoSize: Math.round(size * 0.84),
    });
    await writePng(assets, `favicon-branded-${size}.png`, branded, {
      skipSpillSuppression: true,
    });
  }

  for (const size of MASKABLE_ICON_SIZES) {
    const maskable = await composeCentered({
      width: size,
      height: size,
      background: backgroundSvg(size, size, { rounded: 0 }),
      logo: iconBuffer,
      logoSize: Math.round(size * 0.72),
    });
    await writePng(assets, `maskable-icon-${size}.png`, maskable, {
      skipSpillSuppression: true,
    });
  }

  console.log("6. Writing social and utility variants...");
  const ogWidth = 1200;
  const ogHeight = 630;
  const ogLogo = await sharp(iconBuffer)
    .resize(372, 372, { fit: "contain" })
    .png()
    .toBuffer();
  const ogLogoMeta = await sharp(ogLogo).metadata();
  const og = await sharp(backgroundSvg(ogWidth, ogHeight))
    .composite([
      {
        input: ogLogo,
        left: Math.round((ogWidth - ogLogoMeta.width) / 2),
        top: 38,
      },
      {
        input: svgText({
          width: ogWidth,
          height: 72,
          text: BRAND_NAME,
          y: 52,
          size: 52,
        }),
        left: 0,
        top: 424,
      },
      {
        input: svgText({
          width: ogWidth,
          height: 42,
          text: TAGLINE,
          y: 28,
          size: 22,
          weight: 500,
          opacity: 0.74,
        }),
        left: 0,
        top: 492,
      },
    ])
    .png()
    .toBuffer();
  await writePng(assets, "og-image.png", og, { skipSpillSuppression: true });

  const socialSquare = await composeCentered({
    width: 1200,
    height: 1200,
    background: backgroundSvg(1200, 1200),
    logo: iconBuffer,
    logoSize: 820,
    top: 110,
  });
  await writePng(assets, "social-square.png", socialSquare, {
    skipSpillSuppression: true,
  });

  await createLogoOnFlatBackground(assets, "logo-on-white.png", squareLogoBuffer, {
    r: 255,
    g: 255,
    b: 255,
    alpha: 255,
  });
  await createLogoOnFlatBackground(assets, "logo-on-dark.png", squareLogoBuffer, {
    r: 15,
    g: 6,
    b: 32,
    alpha: 255,
  });

  console.log("7. Validating generated assets...");
  const validation = await validateGeneratedAssets({
    assets,
    logoBuffer,
    sourceMeta,
    chromaStats: keyed,
  });

  const manifest = {
    brandName: BRAND_NAME,
    tagline: TAGLINE,
    source: SOURCE_FILE,
    sourceMetadata: sourceMeta,
    generatedAt: new Date().toISOString(),
    chromaKey: {
      sampledKey: keyed.key,
      transparentPixels: keyed.transparentPixels,
      partialPixels: keyed.partialPixels,
      spillPixels: keyed.spillPixels,
    },
    validation,
    assets: assets.map(({ name, width, height, format, hasAlpha }) => ({
      name,
      width,
      height,
      format,
      hasAlpha,
    })),
  };
  await writeFile(
    path.join(OUT_DIR, "manifest.json"),
    `${JSON.stringify(manifest, null, 2)}\n`,
  );
  assets.push({
    name: "manifest.json",
    path: path.join(OUT_DIR, "manifest.json"),
    format: "json",
  });

  for (const asset of assets) {
    if (asset.width && asset.height) {
      console.log(`   -> ${asset.name} (${asset.width}x${asset.height})`);
    } else {
      console.log(`   -> ${asset.name}`);
    }
  }

  console.log("\nGeneration complete.");
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
