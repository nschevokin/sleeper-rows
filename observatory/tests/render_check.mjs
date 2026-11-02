// Headless-Chromium render check for the Agent Observatory.
// Usage: node render_check.mjs <replays-dir> <screenshot-path>
// Exits 0 on success, 1 on failed assertions, 77 if Playwright/Chromium is unavailable.
import { createRequire } from "node:module";
import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
let chromium;
try {
  ({ chromium } = require("playwright"));
} catch {
  try {
    ({ chromium } = require("/opt/npm-tools/node_modules/playwright"));
  } catch {
    console.error("playwright not available");
    process.exit(77);
  }
}

const [replaysDir, shotPath] = process.argv.slice(2);
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const TYPES = { ".html": "text/html", ".js": "text/javascript", ".css": "text/css", ".json": "application/json" };

function serve() {
  const server = http.createServer((req, res) => {
    const url = new URL(req.url, "http://x");
    let base = root;
    let rel = decodeURIComponent(url.pathname);
    if (rel.startsWith("/__replays__/")) {
      base = path.resolve(replaysDir);
      rel = rel.slice("/__replays__".length);
    }
    const file = path.normalize(path.join(base, rel === "/" ? "/index.html" : rel));
    if (!file.startsWith(base) || !fs.existsSync(file) || fs.statSync(file).isDirectory()) {
      res.writeHead(404).end("not found");
      return;
    }
    res.writeHead(200, { "content-type": TYPES[path.extname(file)] || "application/octet-stream" });
    fs.createReadStream(file).pipe(res);
  });
  return new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve(server)));
}

const failures = [];
const check = (ok, msg) => {
  console.log(`${ok ? "ok  " : "FAIL"} ${msg}`);
  if (!ok) failures.push(msg);
};

function watch(page, problems) {
  page.on("console", (m) => m.type() === "error" && problems.push(`console: ${m.text()}`));
  page.on("pageerror", (e) => problems.push(`pageerror: ${e.message}`));
  page.on("requestfailed", (r) => problems.push(`requestfailed: ${r.url()}`));
  page.on("response", (r) => r.status() >= 400 && problems.push(`http ${r.status()}: ${r.url()}`));
}

const server = await serve();
const origin = `http://127.0.0.1:${server.address().port}`;
let browser;
try {
  browser = await chromium.launch();
} catch (err) {
  console.error(`chromium unavailable: ${err.message}`);
  server.close();
  process.exit(77);
}

try {
  const ctx = await browser.newContext({ viewport: { width: 1400, height: 900 } });
  const page = await ctx.newPage();
  const problems = [];
  watch(page, problems);
  const external = [];
  page.on("request", (r) => {
    if (!r.url().startsWith(origin) && !r.url().startsWith("data:") && !r.url().startsWith("blob:")) external.push(r.url());
  });
  await page.goto(`${origin}/index.html?replays=__replays__/`);
  await page.waitForFunction(() => document.querySelectorAll("#scenario option").length > 0 && !document.getElementById("play").disabled);
  await page.waitForFunction(() => document.querySelectorAll(".panel canvas").length === 1);

  // Canvas is non-blank: many distinct colours once something has happened.
  await page.selectOption("#speed", "4");
  const distinct = () =>
    page.evaluate(() => {
      const c = document.querySelector(".panel canvas");
      const d = c.getContext("2d").getImageData(0, 0, c.width, c.height).data;
      const seen = new Set();
      for (let i = 0; i < d.length; i += 4 * 7) seen.add((d[i] << 16) | (d[i + 1] << 8) | d[i + 2]);
      return seen.size;
    });
  // Play advances the scrubber.
  const before = Number(await page.inputValue("#scrubber"));
  await page.click("#play");
  await page.waitForTimeout(900);
  const after = Number(await page.inputValue("#scrubber"));
  check(after > before, `scrubber advanced while playing (${before} -> ${after})`);
  await page.click("#pause");
  const paused = Number(await page.inputValue("#scrubber"));
  await page.waitForTimeout(250);
  check(Number(await page.inputValue("#scrubber")) === paused, "pause stops the clock");

  // Keyboard: arrows step, space toggles.
  await page.mouse.click(5, 5);
  await page.keyboard.press("ArrowRight");
  await page.waitForTimeout(100);
  check(Number(await page.inputValue("#scrubber")) > paused, "ArrowRight steps forward");
  await page.keyboard.press("Space");
  await page.waitForTimeout(150);
  check(await page.evaluate(() => window.__observatory.state().playing), "Space starts playback");
  await page.keyboard.press("Space");

  // Jump into the attack: scrub to the last third where the poisoned row reached the agents.
  const dur = await page.evaluate(() => window.__observatory.state().duration);
  await page.evaluate((v) => {
    const s = document.getElementById("scrubber");
    s.value = String(v);
    s.dispatchEvent(new Event("input", { bubbles: true }));
  }, Math.round(dur * 0.45));
  await page.waitForTimeout(200);
  const n = await distinct();
  check(n > 12, `canvas is non-blank (${n} distinct colours)`);
  check((await page.textContent(".caption")).length > 5, "caption describes the current step");
  const dl = await page.getAttribute(".panel a", "download");
  check(!!dl && (await page.getAttribute(".panel a", "href")).startsWith("blob:"), `download link (${dl})`);

  // Click an agent figure -> inspector populated and time frozen.
  await page.locator(".panel canvas").first().scrollIntoViewIfNeeded();
  const pos = (await page.evaluate(() => window.__observatory.hits()))[0].find((h) => h.lane === "analyst");
  await page.mouse.click(pos.x, pos.y);
  await page.waitForSelector("#inspector .step");
  const steps = await page.locator("#inspector .step").count();
  const insp = await page.textContent("#inspector");
  check(steps > 0 && insp.includes("analyst"), `inspector shows ${steps} analyst step(s)`);
  check(insp.includes("trust") || /untrusted|structured|trusted/.test(insp), "inspector shows trust");
  check(!(await page.evaluate(() => window.__observatory.state().playing)), "clicking an agent freezes time");

  // Split view: two panels/canvases.
  await page.click("#split");
  await page.waitForFunction(() => document.querySelectorAll(".panel canvas").length === 2);
  check(await page.evaluate(() => document.querySelectorAll(".panel").length === 2), "split view shows two panels");
  check((await page.getAttribute("#split", "aria-pressed")) === "true", "split toggle is aria-pressed");
  // Moment of the attack: attacked analyst follows the payload while the guard blocks it.
  const scenarioId = await page.inputValue("#scenario");
  const entry = JSON.parse(fs.readFileSync(path.join(replaysDir, "index.json"), "utf8")).scenarios.find((e) => e.id === scenarioId);
  const replay = JSON.parse(fs.readFileSync(path.join(replaysDir, entry.file), "utf8"));
  const hijack = replay.runs.attacked.steps.find((x) => x.action === "tool_call" && x.poisoned);
  check(!!hijack, "sample attacked run contains a poisoned tool_call");
  await page.evaluate((v) => {
    const s = document.getElementById("scrubber");
    s.value = String(v);
    s.dispatchEvent(new Event("input", { bubbles: true }));
  }, (hijack?.t ?? dur * 0.4) + 300);
  await page.waitForTimeout(300);
  await page.locator(".panel canvas").first().scrollIntoViewIfNeeded();
  const hits = await page.evaluate(() => window.__observatory.hits());
  const guard = hits[1].find((h) => h.lane === "guard");
  await page.mouse.click(guard.x, guard.y);
  await page.waitForSelector("#inspector .step");
  check((await page.locator("#inspector mark").count()) > 0, "inspector highlights tainted spans");
  check((await page.textContent("#inspector")).includes("tainted narrative span"), "inspector shows blocked_reason");
  const both = await page.evaluate(() => [...document.querySelectorAll(".panel canvas")].map((c) => c.width > 0 && c.height > 0));
  check(both.every(Boolean), "both canvases are sized");
  await page.screenshot({ path: shotPath, fullPage: true });
  console.log(`screenshot: ${shotPath}`);
  await page.emulateMedia({ colorScheme: "dark", reducedMotion: "reduce" });
  await page.waitForTimeout(300);
  await page.screenshot({ path: shotPath.replace(/\.png$/, "") + "-dark.png", fullPage: true });

  // Scenario picker has every scenario; switching loads another replay without errors.
  const options = await page.locator("#scenario option").count();
  if (options > 1) {
    await page.selectOption("#scenario", { index: 1 });
    await page.waitForTimeout(300);
    check((await page.locator(".panel").count()) >= 1, "switching scenario rebuilds panels");
  }
  check(problems.length === 0, `no console errors / failed requests ${problems.join("; ")}`);
  check(external.length === 0, `no external requests ${external.join(", ")}`);

  // Missing replays: friendly message, no crash.
  const page2 = await ctx.newPage();
  const errs2 = [];
  page2.on("pageerror", (e) => errs2.push(e.message));
  await page2.goto(`${origin}/index.html?replays=does-not-exist/`);
  await page2.waitForSelector("#message:not([hidden])");
  check((await page2.textContent("#message")).includes("No replays"), "missing replays show a friendly message");
  check(errs2.length === 0, "no uncaught exception when replays are missing");
} catch (err) {
  check(false, `exception: ${err.stack || err}`);
} finally {
  await browser.close();
  server.close();
}
process.exit(failures.length ? 1 : 0);
