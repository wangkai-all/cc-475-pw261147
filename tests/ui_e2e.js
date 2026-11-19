// DOM-level end-to-end check: loads index.html, runs app.js against the live
// server, and drives the advisory → simulate → apply → undo flow.
// jsdom is a dev-only dependency of this script, not of the app.
let JSDOM;
try {
  ({ JSDOM } = require("jsdom"));
} catch {
  ({ JSDOM } = require("/tmp/pw/node_modules/jsdom"));
}
const fs = require("fs");
const path = require("path");

const BASE = process.env.BASE || "http://127.0.0.1:8765";
const WEB = path.resolve(__dirname, "..", "web");

const html = fs.readFileSync(path.join(WEB, "index.html"), "utf8");
const appjs = fs.readFileSync(path.join(WEB, "app.js"), "utf8");

const dom = new JSDOM(html, {
  url: BASE + "/",
  runScripts: "outside-only",
  pretendToBeVisual: true,
});
const { window } = dom;

// fetch backed by node's fetch, resolving relative URLs against BASE.
window.fetch = (url, opts) => fetch(url.startsWith("http") ? url : BASE + url, opts);
window.confirm = () => true;
const errors = [];
window.addEventListener("error", (e) => errors.push(e.message));
window.console.error = (...a) => errors.push(a.join(" "));

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const $ = (s) => window.document.querySelector(s);
const $$ = (s) => Array.from(window.document.querySelectorAll(s));
const text = (el) => (el ? el.textContent.replace(/\s+/g, " ").trim() : "");

function check(name, cond, extra = "") {
  const ok = !!cond;
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}${ok ? "" : "  " + extra}`);
  if (!ok) process.exitCode = 1;
}

async function waitFor(fn, timeout = 15000) {
  const t0 = Date.now();
  while (Date.now() - t0 < timeout) {
    const v = fn();
    if (v) return v;
    await sleep(120);
  }
  return null;
}

(async () => {
  window.eval(appjs);

  // 1. list renders
  const items = await waitFor(() => ($$(".advisory-item").length ? $$(".advisory-item") : null));
  check("advisory list renders", items && items.length >= 8, `count=${items && items.length}`);
  check("kind filter chips present", $$(".chip").length === 5);
  check("severity tag rendered", /严重|高|中|低/.test(text($(".advisory-item"))));

  // 2. filter interaction
  const smallChip = $$(".chip").find((c) => c.dataset.kind === "small_files");
  smallChip.click();
  await sleep(50);
  const filtered = $$(".advisory-item");
  check("kind filter narrows list", filtered.length >= 1 && filtered.length < items.length,
    `filtered=${filtered.length}`);
  $$(".chip")[0].click();
  await sleep(50);

  // find the partition_miss advisory (has an applyable plan)
  const itemsAll = $$(".advisory-item");
  let target = null;
  for (const it of itemsAll) {
    if (/时间谓词|分区/.test(text(it))) { target = it; break; }
  }
  check("partition advisory present", !!target);

  target.click();
  const detail = await waitFor(() => ($("#btn-simulate") ? $("#advisory-detail") : null));
  check("detail panel renders", !!detail);
  const dtext = text($("#advisory-detail"));
  check("shows trigger rule", /触发规则/.test(dtext));
  check("shows evidence bullets", $$("#advisory-detail .bullets li").length > 0);
  check("shows sample executions table", $$("#advisory-detail table.data tbody tr").length > 0);
  check("shows recommendation action", /建议动作/.test(dtext));
  check("before/apply section present", /应用前后对比/.test(dtext));

  // 3. simulate
  $("#btn-simulate").click();
  const simOk = await waitFor(() => ($("#btn-apply") ? $("#sim-body") : null), 20000);
  check("simulation plan renders", !!simOk);
  const simText = text($("#sim-body"));
  check("simulation warns estimates != benefit", /估算是|估算，不是|不是收益/.test(simText), simText.slice(0, 120));
  check("simulation shows bounds", /区间/.test(simText));
  check("simulation lists steps", $$("#sim-body ol.steps li").length >= 3);
  check("simulation shows assumptions", /模型假设/.test(simText));

  // 4. apply
  $("#btn-apply").click();
  const applied = await waitFor(
    () => ($("#btn-undo") ? $("#apply-body") : null), 60000
  );
  check("apply renders before/after comparison", !!applied);
  const applyText = text($("#apply-body"));
  check("apply shows measured charts", $$("#apply-body .ba-bar").length >= 4,
    `bars=${$$("#apply-body .ba-bar").length}`);
  check("apply labels measurements", /实测/.test(applyText));
  check("apply shows estimate-vs-measured table", /估算区间/.test(applyText));
  check("apply offers undo", !!$("#btn-undo"));

  const beforeAfterTxt = $$("#apply-body .ba-value").map(text);
  check("before/after values differ", beforeAfterTxt.length >= 4 &&
    beforeAfterTxt[0] !== beforeAfterTxt[2], beforeAfterTxt.join(" | "));

  // 5. undo
  $("#btn-undo").click();
  const undone = await waitFor(() => {
    const t = text($("#advisory-detail"));
    return /尚未应用/.test(t) ? t : null;
  }, 60000);
  check("undo restores state and clears apply card", !!undone);

  // 6. history tab
  $$(".tab").find((t) => t.dataset.tab === "history").click();
  const groups = await waitFor(() => ($$(".group-item").length ? $$(".group-item") : null));
  check("history groups render", !!groups && groups.length > 3);
  groups[0].click();
  const plan = await waitFor(() => ($("#btn-replay") ? $("#history-detail") : null));
  check("history detail shows plan", /执行计划|步骤/.test(text($("#history-detail"))));
  check("history shows sample table", $$("#history-detail table.data tbody tr").length > 0);

  // 7. validation tab
  $$(".tab").find((t) => t.dataset.tab === "validation").click();
  const anomaly = await waitFor(() => ($("#anomaly-card table.data") ? $("#anomaly-card") : null), 20000);
  const statsCard = await waitFor(() => ($("#stats-card table.data") ? $("#stats-card") : null), 40000);
  check("validation: anomalies listed", !!anomaly);
  check("validation: stats consistency table", !!statsCard);
  check("validation names stale table", /统计已过期|统计过期/.test(text($("#stats-card"))));

  // 8. ledger tab
  $$(".tab").find((t) => t.dataset.tab === "ledger").click();
  const ledger = await waitFor(() => ($("#ledger-root table.data") ? $("#ledger-root") : null), 20000);
  check("ledger renders", !!ledger);
  const ledgerText = text(ledger);
  check("ledger records undone apply", /已撤销/.test(ledgerText), ledgerText.slice(0, 200));
  check("ledger lists rollback points", /回滚点/.test(ledgerText));

  check("no uncaught page errors", errors.length === 0, errors.join(" | "));

  console.log(process.exitCode ? "\nSOME CHECKS FAILED" : "\nALL UI CHECKS PASSED");
  await sleep(200);
  window.close();
})();
