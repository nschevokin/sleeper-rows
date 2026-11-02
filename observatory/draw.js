// Canvas rendering of one run at one point in time. Pure drawing: no DOM events, no state.
import { AGENTS, isTainted, laneState, lastAtOrBefore, slot, rowKey } from "./model.js";

const HEADER_H = 46;
const TITLE = {
  ingest: "1 Load",
  transform: "2 Clean (SQL)",
  enrich: "3 LLM labeler",
  guard: "4 Guard",
  triage: "5 Triage agent",
  analyst: "6 Analyst agent",
  data_quality: "7 Data-quality agent",
};
const SHORT = { ingest: "Load", transform: "SQL", enrich: "Label", guard: "Guard", triage: "Triage", analyst: "Analyst", data_quality: "DQ" };

export function readTheme() {
  const cs = getComputedStyle(document.documentElement);
  const get = (name) => cs.getPropertyValue(name).trim();
  return {
    laneA: get("--lane-a"),
    laneB: get("--lane-b"),
    ink: get("--ink"),
    muted: get("--muted"),
    line: get("--line"),
    card: get("--card"),
    cardEdge: get("--card-edge"),
    accent: get("--accent"),
    danger: get("--danger"),
    dangerBg: get("--danger-bg"),
  };
}

function rrect(ctx, x, y, w, h, r) {
  ctx.beginPath();
  ctx.moveTo(x + r, y);
  ctx.arcTo(x + w, y, x + w, y + h, r);
  ctx.arcTo(x + w, y + h, x, y + h, r);
  ctx.arcTo(x, y + h, x, y, r);
  ctx.arcTo(x, y, x + w, y, r);
  ctx.closePath();
}

const ease = (p) => (p < 0.5 ? 2 * p * p : 1 - Math.pow(-2 * p + 2, 2) / 2);
const clamp01 = (v) => Math.max(0, Math.min(1, v));

function warnIcon(ctx, x, y, r, th) {
  ctx.save();
  ctx.fillStyle = th.danger;
  ctx.beginPath();
  ctx.moveTo(x, y - r);
  ctx.lineTo(x + r * 1.1, y + r * 0.8);
  ctx.lineTo(x - r * 1.1, y + r * 0.8);
  ctx.closePath();
  ctx.fill();
  ctx.fillStyle = "#fff";
  ctx.font = `bold ${Math.round(r * 1.5)}px system-ui, sans-serif`;
  ctx.textAlign = "center";
  ctx.textBaseline = "middle";
  ctx.fillText("!", x, y + r * 0.2);
  ctx.restore();
}

function stopIcon(ctx, x, y, r, th) {
  ctx.save();
  ctx.fillStyle = th.danger;
  ctx.strokeStyle = "#fff";
  ctx.lineWidth = Math.max(1, r * 0.18);
  ctx.beginPath();
  for (let i = 0; i < 8; i++) {
    const a = Math.PI / 8 + (i * Math.PI) / 4;
    ctx.lineTo(x + Math.cos(a) * r, y + Math.sin(a) * r);
  }
  ctx.closePath();
  ctx.fill();
  ctx.stroke();
  ctx.beginPath();
  ctx.moveTo(x - r * 0.4, y - r * 0.4);
  ctx.lineTo(x + r * 0.4, y + r * 0.4);
  ctx.moveTo(x + r * 0.4, y - r * 0.4);
  ctx.lineTo(x - r * 0.4, y + r * 0.4);
  ctx.stroke();
  ctx.restore();
}

function drawCard(ctx, c, th) {
  const { x, y, w, h, alpha, poisoned, blocked, pulse } = c;
  ctx.save();
  ctx.globalAlpha = alpha;
  if (poisoned) {
    ctx.shadowColor = th.danger;
    ctx.shadowBlur = pulse;
  }
  rrect(ctx, x - w / 2, y - h / 2, w, h, Math.min(5, h / 3));
  ctx.fillStyle = poisoned ? th.dangerBg : th.card;
  ctx.fill();
  ctx.shadowBlur = 0;
  ctx.lineWidth = poisoned ? 2 : 1;
  ctx.strokeStyle = poisoned ? th.danger : th.cardEdge;
  ctx.stroke();
  ctx.fillStyle = poisoned ? th.danger : th.cardEdge;
  for (let i = 0; i < 3; i++) {
    ctx.fillRect(x - w / 2 + w * 0.15, y - h / 2 + h * (0.22 + i * 0.25), w * (i === 2 ? 0.4 : 0.7), 1.5);
  }
  if (poisoned) warnIcon(ctx, x - w / 2, y - h / 2, Math.max(5, h * 0.4), th);
  if (blocked) stopIcon(ctx, x + w / 2, y - h / 2, Math.max(7, h * 0.55), th);
  ctx.restore();
}

function drawFigure(ctx, f, th) {
  const { x, y, s, lane, tainted, active, blocked, idle } = f;
  const color = tainted ? th.danger : AGENTS.has(lane) ? th.accent : th.muted;
  ctx.save();
  ctx.globalAlpha = idle ? 0.45 : 1;
  ctx.strokeStyle = color;
  ctx.fillStyle = color;
  ctx.lineWidth = Math.max(1.5, s * 0.16);
  ctx.lineCap = "round";
  if (active) {
    ctx.beginPath();
    ctx.arc(x, y, s * 1.7, 0, Math.PI * 2);
    ctx.globalAlpha *= 0.25;
    ctx.fill();
    ctx.globalAlpha = idle ? 0.45 : 1;
  }
  if (lane === "guard") {
    ctx.beginPath(); // shield
    ctx.moveTo(x - s * 0.9, y - s * 0.9);
    ctx.lineTo(x + s * 0.9, y - s * 0.9);
    ctx.lineTo(x + s * 0.9, y + s * 0.1);
    ctx.quadraticCurveTo(x + s * 0.9, y + s * 0.9, x, y + s * 1.3);
    ctx.quadraticCurveTo(x - s * 0.9, y + s * 0.9, x - s * 0.9, y + s * 0.1);
    ctx.closePath();
    ctx.fill();
    if (blocked) {
      stopIcon(ctx, x, y + s * 0.1, s * 0.75, th);
    } else {
      ctx.strokeStyle = th.laneA;
      ctx.beginPath();
      ctx.moveTo(x - s * 0.4, y);
      ctx.lineTo(x - s * 0.1, y + s * 0.35);
      ctx.lineTo(x + s * 0.45, y - s * 0.35);
      ctx.stroke();
    }
  } else if (AGENTS.has(lane)) {
    ctx.beginPath(); // head
    ctx.arc(x, y - s * 0.95, s * 0.42, 0, Math.PI * 2);
    ctx.fill();
    rrect(ctx, x - s * 0.5, y - s * 0.4, s, s * 1.0, s * 0.3);
    ctx.fill(); // torso
    ctx.beginPath();
    ctx.moveTo(x - s * 0.5, y - s * 0.2);
    ctx.lineTo(x - s * 0.95, y + s * 0.35);
    ctx.moveTo(x + s * 0.5, y - s * 0.2);
    ctx.lineTo(x + s * 0.95, y + s * 0.35);
    ctx.moveTo(x - s * 0.22, y + s * 0.6);
    ctx.lineTo(x - s * 0.3, y + s * 1.2);
    ctx.moveTo(x + s * 0.22, y + s * 0.6);
    ctx.lineTo(x + s * 0.3, y + s * 1.2);
    ctx.stroke();
  } else {
    rrect(ctx, x - s * 0.9, y - s * 0.8, s * 1.8, s * 1.6, s * 0.3); // pipeline stage
    ctx.fill();
    ctx.fillStyle = th.laneA;
    ctx.font = `bold ${Math.round(s * 1.1)}px system-ui, sans-serif`;
    ctx.textAlign = "center";
    ctx.textBaseline = "middle";
    ctx.fillText(lane[0].toUpperCase(), x, y + s * 0.05);
  }
  ctx.restore();
  if (tainted) warnIcon(ctx, x + s * 1.1, y - s * 1.2, Math.max(5, s * 0.5), th);
}

/**
 * Draw `prepared` (see model.prepareRun) at time `t` (ms).
 * opts: { theme, rate, reduced, tick }. Returns hit targets for click handling.
 */
export function render(ctx, w, h, prepared, lanes, t, opts) {
  const { theme: th, rate, reduced, tick } = opts;
  const colW = w / lanes.length;
  const top = HEADER_H + 26;
  const bottom = h - 30;
  const laneX = (i) => (i + 0.5) * colW;
  const yOf = (key) => top + slot(key || "") * (bottom - top);
  const travel = reduced ? 0 : 450 * rate;
  const cardW = Math.max(24, Math.min(52, colW * 0.4));
  const cardH = cardW * 0.62;
  const cardDx = colW * 0.17;
  const s = Math.max(9, Math.min(18, colW * 0.15));
  const small = colW < 84;

  ctx.clearRect(0, 0, w, h);
  lanes.forEach((lane, i) => {
    ctx.fillStyle = i % 2 ? th.laneB : th.laneA;
    ctx.fillRect(i * colW, 0, colW, h);
  });
  ctx.strokeStyle = th.line;
  ctx.setLineDash([3, 5]);
  ctx.lineWidth = 1;
  lanes.forEach((_, i) => {
    ctx.beginPath();
    ctx.moveTo(laneX(i) - cardDx, HEADER_H);
    ctx.lineTo(laneX(i) - cardDx, h - 8);
    ctx.stroke();
  });
  ctx.setLineDash([]);

  const pulse = reduced ? 10 : 10 + 6 * Math.sin(tick / 220);
  for (const card of prepared.cards) {
    const i = lastAtOrBefore(card.moves, t);
    if (i < 0) continue;
    const m = card.moves[i];
    const age = t - m.t;
    const p = travel > 0 ? ease(clamp01(age / travel)) : 1;
    const from = m.from === m.to && i === 0 ? m.to : m.from;
    const x = laneX(from) + (laneX(m.to) - laneX(from)) * p + cardDx;
    const lift = reduced ? 0 : Math.sin(Math.PI * p) * 8 * (from === m.to ? 0 : 1);
    const y = yOf(card.key) - lift;
    let alpha = 1;
    if (m.blocked) alpha = age > 9000 * rate ? 0.5 : 1;
    else if (!m.poisoned) alpha = 1 - clamp01((age - 2500 * rate) / (1500 * rate));
    else if (age > 12000 * rate) alpha = 0.7;
    if (!reduced && age < travel * 0.3) alpha *= 0.4 + (0.6 * age) / (travel * 0.3);
    if (alpha <= 0.02) continue;
    const showStop = m.blocked && age < 9000 * rate;
    drawCard(ctx, { x, y, w: cardW, h: cardH, alpha, poisoned: m.poisoned, blocked: m.blocked, pulse }, th);
    if (showStop && !small) {
      ctx.save();
      ctx.fillStyle = th.danger;
      ctx.font = "bold 10px system-ui, sans-serif";
      ctx.textAlign = "center";
      ctx.fillText("BLOCKED", x, y + cardH / 2 + 12);
      ctx.restore();
    }
  }

  const hits = [];
  lanes.forEach((lane, i) => {
    const st = laneState(prepared, lane, t);
    const tainted = isTainted(prepared, lane, t);
    const first = st && rowKey((st.step.inputs || [])[0]);
    const prevKey = st && st.prev && rowKey((st.prev.inputs || [])[0]);
    let y = (top + bottom) / 2;
    if (st) {
      const p = travel > 0 ? ease(clamp01((t - st.step.t) / (travel * 0.8))) : 1;
      const y1 = first ? yOf(first) : y;
      const y0 = prevKey ? yOf(prevKey) : y1;
      y = y0 + (y1 - y0) * p;
    }
    if (!reduced && st) y += Math.sin(tick / 400 + i) * 1.5;
    const x = laneX(i) - cardDx;
    const blocked = !!st && st.step.action === "blocked" && t - st.step.t < 9000 * rate;
    const active = !!st && t - st.step.t < 500 * rate;
    drawFigure(ctx, { x, y, s, lane, tainted, active, blocked, idle: !st }, th);
    hits.push({ lane, x, y, r: Math.max(22, s * 1.8) });

    ctx.textAlign = "center";
    ctx.textBaseline = "alphabetic";
    ctx.fillStyle = th.ink;
    ctx.font = `bold ${small ? 11 : 12}px system-ui, sans-serif`;
    ctx.fillText(small ? SHORT[lane] || lane : TITLE[lane] || lane, laneX(i), 20);
    ctx.font = `${small ? 9 : 10}px system-ui, sans-serif`;
    ctx.fillStyle = tainted ? th.danger : th.muted;
    const label = tainted ? "⚠ tainted" : st ? st.step.action : "idle";
    ctx.fillText(label, laneX(i), 34);
    if (st) {
      ctx.fillStyle = blocked ? th.danger : th.muted;
      ctx.fillText(blocked ? "BLOCKED" : st.step.action, x, y + s * 2.2 + 8);
    }
  });
  return hits;
}
