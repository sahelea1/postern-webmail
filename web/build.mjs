// Builds the web client into ./dist. No plugins, no dev server:
//   node build.mjs          one build
//   node build.mjs --watch  rebuild on change
import { build, context } from "esbuild";
import { cpSync, mkdirSync, rmSync } from "node:fs";

const watch = process.argv.includes("--watch");
rmSync("dist", { recursive: true, force: true });
mkdirSync("dist/fonts", { recursive: true });
for (const f of ["index.html", "favicon.svg", "manifest.webmanifest"]) cpSync(`static/${f}`, `dist/${f}`);
for (const f of ["inter-latin-wght-normal.woff2", "inter-latin-ext-wght-normal.woff2"])
  cpSync(`node_modules/@fontsource-variable/inter/files/${f}`, `dist/fonts/${f}`);

const options = {
  entryPoints: { app: "src/main.tsx", style: "src/styles.css" },
  outdir: "dist",
  bundle: true,
  minify: !watch,
  sourcemap: watch,
  target: ["es2022"],
  format: "esm",
  jsx: "automatic",
  jsxImportSource: "preact",
  external: ["/fonts/*"],
  legalComments: "none",
  logLevel: "info",
};

if (watch) {
  const ctx = await context(options);
  await ctx.watch();
} else {
  await build(options);
}
