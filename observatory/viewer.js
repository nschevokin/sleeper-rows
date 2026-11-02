// Agent Observatory: UI wiring. Loads compacted replays and drives the canvas panels.
import { readTheme, render } from "./draw.js";
import {
  LANE_INFO,
  narrate,
  parseScenario,
  verdict,
  describeStep,
  formatTime,
  laneState,
  lastAtOrBefore,
  prepareRun,
  recentSteps,
} from "./model.js";

const $ = (id) => document.getElementById(id);
const el = $("stage");
const ui = {
  scenario: $("scenario"),
  run: $("run"),
  split: $("split"),
  play: $("play"),
  pause: $("pause"),
  back: $("back"),
  fwd: $("fwd"),
  speed: $("speed"),
  scrub: $("scrubber"),
  clock: $("clock"),
  message: $("message"),
  inspector: $("inspector"),
  banner: $("banner"),
  card: $("scenario-card"),
};
const RUN_LABEL = {
  clean: "Clean (no attack)",
  attacked: "Attacked (undefended)",
  defended: "Defended (taint guard on)",
};
const SAFE_FILE = /^[\w.-]+\.json$/;

const state = {
  index: [],
  replay: null,
  lanes: [],
  runKind: "attacked",
  split: false,
  t: 0,
  duration: 0,
  rate: 1,
  playing: false,
  speed: 1,
  panels: [],
  inspect: null, // { panelIdx, lane }
  theme: null,
  reduced: matchMedia("(prefers-reduced-motion: reduce)").matches,
  lastFrame: 0,
  raf: 0,
};

/** `?replays=` must be a plain relative path: never an absolute path or another origin. */
function replaysBase() {
  const raw = new URLSearchParams(location.search).get("replays") || "replays/";
  const ok = /^[\w.-]+(\/[\w.-]+)*\/?$/.test(raw) && !raw.split("/").includes("..");
  const base = ok ? raw : "replays/";
  return base.endsWith("/") ? base : `${base}/`;
}

async function getJSON(url) {
  const res = await fetch(url, { cache: "no-store" });
  if (!res.ok) throw new Error(`${url}: HTTP ${res.status}`);
  return res.json();
}

function showMessage(text) {
  ui.message.textContent = text;
  ui.message.hidden = !text;
}

function setEnabled(on) {
  for (const k of ["scenario", "run", "play", "pause", "back", "fwd", "speed", "scrub"]) {
    ui[k].disabled = !on;
  }
}

// ---------- loading ----------

async function init() {
  state.theme = readTheme();
  const base = replaysBase();
  try {
    const idx = await getJSON(`${base}index.json`);
    state.index = (idx.scenarios || []).filter((s) => SAFE_FILE.test(s.file || ""));
    state.banner = typeof idx.banner === "string" ? idx.banner : "";
  } catch (err) {
    state.index = [];
    console.info("no replays:", err.message);
  }
  if (!state.index.length) {
    showMessage(
      "No replays found. Generate some with: python -m observatory.compact --events <events dir> --out observatory/replays " +
        "(or make observatory), then reload this page.",
    );
    ui.clock.textContent = "no data";
    return;
  }
  const bn = state.banner;
  ui.banner.textContent = bn || "";
  ui.banner.hidden = !bn;
  ui.scenario.replaceChildren(
    ...state.index.map((s, i) => {
      const sc = parseScenario(s.id);
      const label = sc.detail ? `${i + 1}. ${sc.title}` : s.id;
      return new Option(label, s.id);
    }),
  );
  ui.scenario.disabled = false;
  await selectScenario(state.index[0].id, base);
}

async function selectScenario(id, base = replaysBase()) {
  const entry = state.index.find((s) => s.id === id);
  if (!entry) return;
  setPlaying(false);
  try {
    state.replay = await getJSON(`${base}${entry.file}`);
  } catch (err) {
    showMessage(`Could not load replay "${id}": ${err.message}`);
    return;
  }
  const runs = state.replay.runs || {};
  const kinds = Object.keys(runs).filter((k) => (runs[k].steps || []).length);
  if (!kinds.length) {
    showMessage(`Replay "${id}" contains no events.`);
    return;
  }
  showMessage("");
  const sc = parseScenario(state.replay.scenario_id || id);
  $("sc-title").textContent = sc.title;
  $("sc-detail").textContent = sc.detail;
  $("sc-raw").textContent = sc.raw;
  ui.card.hidden = !sc.detail;
  state.lanes = state.replay.lanes;
  state.prepared = Object.fromEntries(kinds.map((k) => [k, prepareRun(runs[k], state.lanes)]));
  state.kinds = kinds;
  ui.run.replaceChildren(...kinds.map((k) => new Option(RUN_LABEL[k] || k, k)));
  state.runKind = kinds.includes("attacked") ? "attacked" : kinds[0];
  ui.run.value = state.runKind;
  const canSplit = kinds.includes("attacked") && kinds.includes("defended");
  if (!canSplit) state.split = false;
  ui.split.disabled = !canSplit;
  ui.split.title = canSplit ? "" : "Needs both an attacked and a defended run";
  setEnabled(true);
  ui.split.disabled = !canSplit;
  state.t = 0;
  buildPanels();
}

function visibleKinds() {
  return state.split ? ["attacked", "defended"] : [state.runKind];
}

// ---------- panels ----------

function buildPanels() {
  for (const p of state.panels) if (p.url) URL.revokeObjectURL(p.url);
  el.replaceChildren();
  el.classList.toggle("split", state.split);
  ui.split.setAttribute("aria-pressed", String(state.split));
  ui.run.disabled = state.split;
  state.inspect = null;
  clearInspector();
  state.panels = visibleKinds().map((kind, i) => makePanel(kind, i));
  state.duration = Math.max(...visibleKinds().map((k) => state.prepared[k].run.duration_ms || 0), 1);
  state.rate = Math.max(1, state.duration / 90000);
  ui.scrub.max = String(state.duration);
  state.t = Math.min(state.t, state.duration);
  state.panels.forEach((p) => p.ro.observe(p.wrap));
  requestDraw();
}

function makePanel(kind, panelIdx) {
  const prepared = state.prepared[kind];
  const section = document.createElement("section");
  section.className = "panel";
  section.dataset.run = kind;
  const head = document.createElement("header");
  const title = document.createElement("h2");
  title.textContent = RUN_LABEL[kind] || kind;
  const link = document.createElement("a");
  link.textContent = "Download trace";
  const blob = new Blob([JSON.stringify({ scenario_id: state.replay.scenario_id, scenario: kind, ...prepared.run }, null, 1)], {
    type: "application/json",
  });
  const url = URL.createObjectURL(blob);
  link.href = url;
  link.download = `${state.replay.scenario_id}.${kind}.trace.json`;
  head.append(title, link);

  const wrap = document.createElement("div");
  wrap.className = "canvas-wrap";
  const canvas = document.createElement("canvas");
  canvas.setAttribute("role", "img");
  canvas.setAttribute(
    "aria-label",
    `${RUN_LABEL[kind] || kind} replay. Lanes left to right: ${state.lanes.join(", ")}. Use the Inspect buttons below for details.`,
  );
  wrap.append(canvas);
  const caption = document.createElement("p");
  caption.className = "caption";
  const actors = document.createElement("div");
  actors.className = "actors";
  for (const lane of state.lanes) {
    const b = document.createElement("button");
    b.type = "button";
    b.textContent = `Inspect ${lane}`;
    b.dataset.lane = lane;
    b.addEventListener("click", () => openInspector(panelIdx, lane));
    actors.append(b);
  }
  const ver = verdict(prepared, kind);
  const verEl = document.createElement("p");
  verEl.className = `verdict ${ver.tone}`;
  verEl.textContent = ver.text;
  const now = document.createElement("p");
  now.className = "nowtext";
  const story = document.createElement("ol");
  story.className = "story";
  const items = prepared.steps.map((st, i) => {
    const [text, tone] = narrate(st);
    const li = document.createElement("li");
    li.className = tone;
    const tm = document.createElement("span");
    tm.className = "tm";
    tm.textContent = formatTime(st.t);
    const tx = document.createElement("span");
    tx.textContent = text;
    li.append(tm, tx);
    li.addEventListener("click", () => {
      setPlaying(false);
      state.t = st.t;
      requestDraw();
    });
    story.append(li);
    return li;
  });
  section.append(head, verEl, wrap, now, story, caption, actors);
  el.append(section);

  const panel = { kind, prepared, canvas, wrap, caption, now, items, url, hits: [], w: 0, h: 0, dpr: 1 };
  panel.ro = new ResizeObserver(() => {
    resizeCanvas(panel);
    requestDraw();
  });
  canvas.addEventListener("click", (ev) => {
    const r = canvas.getBoundingClientRect();
    const x = ev.clientX - r.left;
    const y = ev.clientY - r.top;
    let best = null;
    for (const h of panel.hits) {
      const d = Math.hypot(h.x - x, h.y - y);
      if (d <= h.r && (!best || d < best.d)) best = { d, lane: h.lane };
    }
    if (best) openInspector(panelIdx, best.lane);
  });
  return panel;
}

function resizeCanvas(panel) {
  const dpr = window.devicePixelRatio || 1;
  const w = Math.max(1, Math.round(panel.wrap.clientWidth));
  const h = Math.max(1, Math.round(panel.wrap.clientHeight));
  panel.canvas.width = Math.round(w * dpr);
  panel.canvas.height = Math.round(h * dpr);
  Object.assign(panel, { w, h, dpr });
}

// ---------- drawing and clock ----------

let drawQueued = false;
function requestDraw() {
  if (drawQueued) return;
  drawQueued = true;
  requestAnimationFrame(() => {
    drawQueued = false;
    draw();
  });
}

function draw() {
  const tick = performance.now();
  for (const p of state.panels) {
    if (!p.w) resizeCanvas(p);
    const ctx = p.canvas.getContext("2d");
    ctx.setTransform(p.dpr, 0, 0, p.dpr, 0, 0);
    p.hits = render(ctx, p.w, p.h, p.prepared, state.lanes, state.t, {
      theme: state.theme,
      rate: state.rate,
      reduced: state.reduced,
      tick,
    });
    const last = lastAtOrBefore(p.prepared.steps, state.t);
    p.caption.textContent = describeStep(last < 0 ? null : p.prepared.steps[last]);
    p.now.textContent = last < 0 ? "Press Play to start the story." : narrate(p.prepared.steps[last])[0];
    p.items.forEach((li, i) => {
      li.classList.toggle("now", i === last);
      li.classList.toggle("future", i > last);
    });
    if (last >= 0 && state.playing) {
      const li = p.items[last];
      const box = li.parentElement;
      box.scrollTop = Math.max(0, li.offsetTop - box.clientHeight / 2);
    }
  }
  ui.scrub.value = String(Math.round(state.t));
  ui.clock.textContent = `${formatTime(state.t)} / ${formatTime(state.duration)}`;
  ui.scrub.setAttribute("aria-valuetext", ui.clock.textContent);
  refreshInspector();
}

function frame(now) {
  if (!state.playing) return;
  const dt = Math.min(100, now - state.lastFrame);
  state.lastFrame = now;
  state.t += dt * state.speed * state.rate;
  if (state.t >= state.duration) {
    state.t = state.duration;
    setPlaying(false);
  }
  draw();
  if (state.playing) state.raf = requestAnimationFrame(frame);
}

function setPlaying(on) {
  state.playing = on;
  cancelAnimationFrame(state.raf);
  ui.play.setAttribute("aria-pressed", String(on));
  ui.pause.setAttribute("aria-pressed", String(!on));
  if (on) {
    if (state.t >= state.duration) state.t = 0;
    state.lastFrame = performance.now();
    state.raf = requestAnimationFrame(frame);
  } else {
    requestDraw();
  }
}

function eventTimes() {
  const all = new Set();
  for (const p of state.panels) for (const t of p.prepared.times) all.add(t);
  return [...all].sort((a, b) => a - b);
}

function step(dir) {
  setPlaying(false);
  const times = eventTimes();
  if (dir > 0) state.t = times.find((t) => t > state.t + 0.5) ?? state.duration;
  else state.t = [...times].reverse().find((t) => t < state.t - 0.5) ?? 0;
  requestDraw();
}

// ---------- inspector ----------

function clearInspector() {
  const head = document.createElement("h2");
  head.textContent = "Inspector";
  const hint = document.createElement("p");
  hint.className = "hint";
  hint.textContent =
    "Click an agent figure (or use the Inspect buttons) to freeze time and see its latest steps.";
  ui.inspector.replaceChildren(head, hint);
  ui.inspector.dataset.key = "";
}

function openInspector(panelIdx, lane) {
  setPlaying(false);
  state.inspect = { panelIdx, lane };
  ui.inspector.dataset.key = "";
  refreshInspector();
}

function line(dl, label, content) {
  const dt = document.createElement("dt");
  dt.textContent = label;
  const dd = document.createElement("dd");
  if (typeof content === "string") dd.textContent = content;
  else dd.append(content);
  dl.append(dt, dd);
}

function badge(text, cls) {
  const b = document.createElement("span");
  b.className = `badge ${cls}`;
  b.textContent = text;
  return b;
}

function excerptNode(text, spans) {
  const pre = document.createElement("p");
  pre.className = "excerpt";
  let pos = 0;
  for (const [a, b] of [...(spans || [])].sort((x, y) => x[0] - y[0])) {
    if (a < pos || b > text.length) continue;
    pre.append(text.slice(pos, a));
    const mark = document.createElement("mark");
    mark.textContent = text.slice(a, b);
    mark.title = "tainted span";
    pre.append(mark);
    pos = b;
  }
  pre.append(text.slice(pos));
  return pre;
}

function stepNode(s) {
  const art = document.createElement("article");
  art.className = "step";
  const h = document.createElement("div");
  const strong = document.createElement("strong");
  strong.textContent = `${formatTime(s.t)}  ${s.action}`;
  h.append(strong, badge(s.trust, s.trust));
  if (s.poisoned) h.append(badge("⚠ poisoned input", "poisoned"));
  if (s.action === "blocked") h.append(badge("✖ blocked", "blocked"));
  const dl = document.createElement("dl");
  if (s.inputs?.length) {
    const ul = document.createElement("ul");
    for (const i of s.inputs) {
      const li = document.createElement("li");
      li.textContent = i;
      ul.append(li);
    }
    line(dl, "inputs", ul);
  }
  if (s.tool) line(dl, "tool call", `${s.tool}(${s.args_digest || ""})`);
  if (s.decision) line(dl, "decision", s.decision);
  if (s.blocked_reason) line(dl, "blocked", s.blocked_reason);
  if (s.output_ref) line(dl, "output", s.output_ref);
  if (typeof s.excerpt === "string") line(dl, "excerpt", excerptNode(s.excerpt, s.tainted_spans));
  art.append(h, dl);
  return art;
}

function refreshInspector() {
  if (!state.inspect) return;
  const panel = state.panels[state.inspect.panelIdx];
  if (!panel) return;
  const { lane } = state.inspect;
  const st = laneState(panel.prepared, lane, state.t);
  const key = `${state.inspect.panelIdx}:${lane}:${st ? st.idx : -1}`;
  if (ui.inspector.dataset.key === key) return;
  ui.inspector.dataset.key = key;
  const head = document.createElement("div");
  head.className = "head";
  const h = document.createElement("h2");
  h.textContent = `${lane} — ${RUN_LABEL[panel.kind] || panel.kind} @ ${formatTime(state.t)}`;
  const close = document.createElement("button");
  close.type = "button";
  close.textContent = "Close";
  close.addEventListener("click", () => {
    state.inspect = null;
    clearInspector();
  });
  head.append(h, close);
  const steps = recentSteps(panel.prepared, lane, state.t, 8);
  const body = steps.length
    ? steps.map(stepNode)
    : [Object.assign(document.createElement("p"), { textContent: "This actor has not acted yet." })];
  ui.inspector.replaceChildren(head, ...body);
}

// ---------- wiring ----------

ui.play.addEventListener("click", () => setPlaying(true));
ui.pause.addEventListener("click", () => setPlaying(false));
ui.back.addEventListener("click", () => step(-1));
ui.fwd.addEventListener("click", () => step(1));
ui.speed.addEventListener("change", () => (state.speed = Number(ui.speed.value)));
ui.scrub.addEventListener("input", () => {
  state.t = Number(ui.scrub.value);
  requestDraw();
});
ui.scenario.addEventListener("change", () => selectScenario(ui.scenario.value));
ui.run.addEventListener("change", () => {
  state.runKind = ui.run.value;
  buildPanels();
});
ui.split.addEventListener("click", () => {
  state.split = !state.split;
  buildPanels();
});

document.addEventListener("keydown", (ev) => {
  if (ev.altKey || ev.ctrlKey || ev.metaKey || !state.panels.length) return;
  const tag = ev.target.tagName;
  if (ev.key === " ") {
    if (tag === "BUTTON" || tag === "SELECT" || tag === "A") return; // native behaviour
    ev.preventDefault();
    setPlaying(!state.playing);
  } else if (ev.key === "ArrowRight" || ev.key === "ArrowLeft") {
    if (tag === "INPUT" || tag === "SELECT") return; // native range/select stepping
    ev.preventDefault();
    step(ev.key === "ArrowRight" ? 1 : -1);
  }
});

window.addEventListener("resize", () => {
  for (const p of state.panels) resizeCanvas(p); // also covers devicePixelRatio changes (zoom)
  requestDraw();
});

for (const q of ["(prefers-color-scheme: dark)", "(prefers-reduced-motion: reduce)"]) {
  matchMedia(q).addEventListener("change", () => {
    state.theme = readTheme();
    state.reduced = matchMedia("(prefers-reduced-motion: reduce)").matches;
    requestDraw();
  });
}

// Small read-only hook so the render check can find figures to click.
window.__observatory = {
  hits: () =>
    state.panels.map((p) => {
      const r = p.canvas.getBoundingClientRect();
      return p.hits.map((h) => ({ lane: h.lane, x: r.left + h.x, y: r.top + h.y }));
    }),
  state: () => ({ t: state.t, duration: state.duration, playing: state.playing, split: state.split }),
};

const key = $("lanes-key");
for (const [lane, [name, text]] of Object.entries(LANE_INFO)) {
  const li = document.createElement("li");
  const b = document.createElement("b");
  b.textContent = name;
  li.append(b, text);
  key.append(li);
}

init();
