// Query history analyzer — single-file SPA, no build step.

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

const state = {
  tables: [],
  advisories: [],
  kindFilter: "all",
  selectedAdvisory: null,
  advisoryDetail: null,
  simulation: null,
  groups: [],
  selectedGroup: null,
  anomalies: [],
  staleTables: [],
};

const KIND_LABEL = {
  overscan: "扫描过大",
  partition_miss: "分区未裁剪",
  repeated_aggregation: "重复聚合",
  small_files: "小文件",
};
const SEV_LABEL = { critical: "严重", high: "高", medium: "中", low: "低" };
const CONF_LABEL = { high: "高置信", medium: "中置信", low: "低置信" };
const ACTION_LABEL = {
  add_partition: "调整分区",
  cluster: "排序 / 聚簇",
  materialize: "物化汇总",
  compact: "合并文件",
};

// ---------------------------------------------------------------- utilities
const esc = (s) =>
  String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

const fmtInt = (n) => (n == null || Number.isNaN(n) ? "—" : Number(n).toLocaleString("en-US"));
const fmtBytes = (n) => {
  if (n == null) return "—";
  const u = ["B", "KB", "MB", "GB", "TB"];
  let v = Number(n), i = 0;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return `${v >= 100 || i === 0 ? Math.round(v) : v.toFixed(1)} ${u[i]}`;
};
const fmtMs = (n) => (n == null ? "—" : n >= 1000 ? `${(n / 1000).toFixed(2)} s` : `${n < 10 ? n.toFixed(1) : Math.round(n)} ms`);
const fmtPct = (n) => (n == null ? "—" : `${n > 0 ? "+" : ""}${Number(n).toFixed(1)}%`);
const fmtTime = (ts) => {
  if (!ts) return "—";
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return ts;
  return d.toLocaleString("zh-CN", { month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit" });
};

function toast(msg, isError = false) {
  const el = $("#toast");
  el.textContent = msg;
  el.classList.toggle("is-error", isError);
  el.classList.add("is-visible");
  clearTimeout(toast._t);
  toast._t = setTimeout(() => el.classList.remove("is-visible"), 3200);
}

async function api(path, options = {}) {
  const res = await fetch(path, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  const text = await res.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch { data = { error: text }; }
  if (!res.ok) {
    const err = new Error((data && data.error) || `HTTP ${res.status}`);
    err.status = res.status;
    err.code = data && data.code;
    err.detail = data && data.detail;
    throw err;
  }
  return data;
}

const sevTag = (sev) => `<span class="tag tag-${esc(sev)}"><span class="dot"></span>${SEV_LABEL[sev] || sev}</span>`;
const confTag = (c) => `<span class="tag tag-conf-${esc(c)}"><span class="dot"></span>${CONF_LABEL[c] || c}</span>`;
const kindTag = (k) => `<span class="tag tag-kind">${KIND_LABEL[k] || k}</span>`;

// ---------------------------------------------------------------- charts
/** Labelled before/after bars. Single scale per chart; never dual-axis. */
function beforeAfterChart(before, after, unitFmt, title, note) {
  const max = Math.max(before, after, 1);
  const pct = (v) => Math.max(1.5, (v / max) * 100);
  const bTxt = unitFmt(before);
  const aTxt = unitFmt(after);
  const drop = before > 0 ? ((before - after) / before) * 100 : null;
  return `
    <div class="chart-block">
      <div class="section-title"><h3>${esc(title)}</h3>${
        drop == null
          ? '<span class="delta-none">无可比基线</span>'
          : `<span class="${drop > 0 ? "delta-pos" : "delta-none"}">${drop > 0 ? "减少" : "增加"} ${Math.abs(drop).toFixed(1)}%（实测）</span>`
      }</div>
      <div class="chart-legend">
        <span class="legend-item"><span class="legend-swatch" style="background:var(--series-2)"></span>应用前（实测）</span>
        <span class="legend-item"><span class="legend-swatch" style="background:var(--series-1)"></span>应用后（实测）</span>
      </div>
      <div class="ba-row">
        <span class="ba-label">应用前</span>
        <div class="ba-track"><div class="ba-bar before" style="width:${pct(before)}%"></div></div>
        <span class="ba-value">${bTxt}</span>
      </div>
      <div class="ba-row">
        <span class="ba-label">应用后</span>
        <div class="ba-track"><div class="ba-bar after" style="width:${pct(after)}%"></div></div>
        <span class="ba-value">${aTxt}</span>
      </div>
      ${note ? `<div class="axis-note">${esc(note)}</div>` : ""}
    </div>`;
}

/** Estimate vs measured: separate bars of a different category, clearly marked. */
function estimateCallout(est, actualBefore, actualAfter, estKey = "files_scanned") {
  const e = est && est[estKey];
  if (!e || e.value == null) {
    return `<div class="callout callout-info"><span class="ico">ⓘ</span><div>
      <strong>未提供估算。</strong>${esc((est && est[estKey] && est[estKey].basis) || "该指标无法在不执行的情况下估算，页面只展示实测结果。")}</div></div>`;
  }
  return `<details class="evidence" open>
    <summary>估算区间与实测对照</summary>
    <div class="evidence-body">
      <table class="data">
        <thead><tr><th>指标</th><th class="num">估算</th><th class="num">估算区间</th><th class="num">实测应用后</th><th>是否落在区间</th></tr></thead>
        <tbody>
          <tr>
            <td>扫描文件数</td>
            <td class="num">${fmtInt(Math.round(e.value))}</td>
            <td class="num">${e.bound_low == null ? "—" : `${fmtInt(Math.round(e.bound_low))} – ${fmtInt(Math.round(e.bound_high))}`}</td>
            <td class="num">${actualAfter == null ? "尚未实测" : fmtInt(actualAfter)}</td>
            <td>${actualAfter == null ? '<span class="hint">应用后填写</span>' : (e.bound_low <= actualAfter && actualAfter <= e.bound_high ? '<span class="delta-pos">在区间内</span>' : '<span style="color:var(--critical);font-weight:600">超出区间</span>')}</td>
          </tr>
        </tbody>
      </table>
      <p class="hint mt-8">估算依据：${esc(e.basis)}。估算不是收益，只有“实测应用后”才代表真实结果。</p>
    </div>
  </details>`;
}

// ---------------------------------------------------------------- advisory list
function renderAdvisoryList() {
  const list = state.advisories.filter(
    (a) => state.kindFilter === "all" || a.kind === state.kindFilter
  );
  $("#advisory-count").textContent = `${list.length} 条`;
  const ul = $("#advisory-list");
  if (!list.length) {
    ul.innerHTML = `<li class="empty-state" style="padding:28px 16px">当前过滤条件下没有建议。</li>`;
    return;
  }
  ul.innerHTML = list
    .map(
      (a) => `
    <li class="advisory-item ${state.selectedAdvisory === a.id ? "is-selected" : ""}" data-id="${a.id}" tabindex="0" role="button">
      <div class="advisory-title">${esc(a.title)}</div>
      <div class="advisory-meta">
        ${sevTag(a.severity)}
        ${kindTag(a.kind)}
        <span class="mono">${esc(a.table_name)}</span>
        ${a.history ? `<span>${a.history.runs} 次执行</span>` : ""}
        ${a.status === "resolved" ? '<span class="tag">已应用</span>' : ""}
      </div>
    </li>`
    )
    .join("");
  $$(".advisory-item", ul).forEach((el) => {
    el.addEventListener("click", () => selectAdvisory(Number(el.dataset.id)));
    el.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === " ") { e.preventDefault(); selectAdvisory(Number(el.dataset.id)); }
    });
  });
}

async function selectAdvisory(id) {
  state.selectedAdvisory = id;
  state.simulation = null;
  renderAdvisoryList();
  const root = $("#advisory-detail");
  root.innerHTML = `<div class="card"><div class="card-body"><span class="spinner"></span> 载入建议…</div></div>`;
  try {
    const detail = await api(`/api/advisories/${id}`);
    state.advisoryDetail = detail;
    renderAdvisoryDetail();
  } catch (err) {
    root.innerHTML = `<div class="callout callout-danger"><span class="ico">!</span><div>${esc(err.message)}</div></div>`;
  }
}

// ---------------------------------------------------------------- advisory detail
function sampleTable(samples) {
  if (!samples || !samples.length) return `<p class="hint">没有可引用的执行样本。</p>`;
  return `<div class="table-wrap"><table class="data">
    <thead><tr><th>时间</th><th>来源</th><th class="num">耗时</th><th class="num">扫描字节</th><th class="num">扫描行</th><th class="num">返回行</th><th class="num">文件</th></tr></thead>
    <tbody>${samples
      .map(
        (s) => `<tr>
        <td>${fmtTime(s.ts)}</td>
        <td class="mono">${esc(s.client || "—")}</td>
        <td class="num">${fmtMs(s.duration_ms)}</td>
        <td class="num">${fmtBytes(s.bytes_scanned)}</td>
        <td class="num">${fmtInt(s.rows_scanned)}</td>
        <td class="num">${fmtInt(s.rows_returned)}</td>
        <td class="num">${s.files_scanned}/${s.files_total}</td>
      </tr>`
      )
      .join("")}</tbody>
  </table></div>
  <details class="evidence mt-8">
    <summary>查看样本 SQL</summary>
    <div class="evidence-body"><pre class="sql">${esc(samples[0].query)}</pre></div>
  </details>`;
}

function rationaleBlock(r) {
  const observed = r.observed || {};
  const facts = [];
  const add = (label, value, suffix = "") => facts.push({ label, value: value == null ? "—" : value, suffix });
  if (r.kind === "overscan" || observed.ratio != null) {
    add("扫描字节", fmtBytes(observed.avg_bytes_scanned));
    add("返回字节", fmtBytes(observed.avg_result_bytes));
    add("放大倍数", observed.ratio == null ? null : `${observed.ratio}×`);
  }
  if (observed.avg_rows_scanned != null) add("平均扫描行", fmtInt(observed.avg_rows_scanned));
  if (observed.runs != null) add("样本执行次数", fmtInt(observed.runs));
  if (observed.files_scanned != null) add("读取文件", `${observed.files_scanned}/${observed.files_total}`);
  if (observed.observed_prune_pct != null) add("当前裁剪率", `${observed.observed_prune_pct}%`);
  if (observed.projected_prune_pct != null) add("投影裁剪率", `${observed.projected_prune_pct}%`);
  if (observed.total_ms != null) add("累计耗时", fmtMs(observed.total_ms));
  if (observed.small_files != null) add("小文件数", `${observed.small_files}/${observed.file_count}`);
  if (observed.median_file_bytes != null) add("中位文件", fmtBytes(observed.median_file_bytes));

  return `
    <div class="facts">
      ${facts
        .map(
          (f) => `<div class="fact"><div class="fact-label">${esc(f.label)}</div>
            <div class="fact-value">${esc(f.value)}${f.suffix ? `<small>${esc(f.suffix)}</small>` : ""}</div></div>`
        )
        .join("")}
    </div>
    <div class="section-title mt-16"><h3>触发规则</h3></div>
    <pre class="sql">${esc(r.rule || "—")}</pre>
    <div class="section-title mt-16"><h3>依据</h3></div>
    <ul class="bullets">${(r.evidence || []).map((e) => `<li>${esc(e)}</li>`).join("")}</ul>
    ${
      r.alternative_projection
        ? `<div class="section-title mt-16"><h3>布局改变后的投影</h3></div>
           ${projectionTable(r.alternative_projection)}`
        : ""
    }
    ${
      r.alternatives && r.alternatives.length
        ? `<div class="section-title mt-16"><h3>备选方案（未采用）</h3></div>
           ${r.alternatives.map((alt) => `
             <div class="callout callout-info mt-8"><span class="ico">⇄</span><div>
               <strong>${esc(ACTION_LABEL[alt.action] || alt.action)}：${esc(alt.cluster_by || "")}</strong>
               <p class="mt-8">${esc(alt.tradeoff)}</p>
               ${alt.projected ? `<p class="hint mt-8">投影：扫描约 ${alt.projected.files_scanned} / ${alt.projected.total_files} 个文件（裁剪 ${alt.projected.prune_pct}%）</p>` : ""}
             </div></div>`).join("")}`
        : ""
    }`;
}

function projectionTable(p) {
  return `<div class="table-wrap"><table class="data">
    <thead><tr><th>投影项</th><th class="num">值</th></tr></thead>
    <tbody>
      <tr><td>预计扫描文件</td><td class="num">${p.files_scanned} / ${p.total_files}</td></tr>
      <tr><td>预计裁剪比例</td><td class="num">${p.prune_pct}%</td></tr>
      <tr><td>误差区间（文件）</td><td class="num">${p.bound_low} – ${p.bound_high}</td></tr>
      <tr><td>依据</td><td>${esc(p.basis)}</td></tr>
    </tbody>
  </table></div>
  <p class="hint mt-8">假设：${(p.assumptions || []).map(esc).join("；")}</p>`;
}

function recommendationBlock(r) {
  const rec = r.recommendation;
  if (!rec) {
    return `<div class="callout callout-warn"><span class="ico">⚠</span><div>
      <strong>未给出可应用建议。</strong>该问题不能通过布局调整获得确定的裁剪收益，估算模型已拒绝给出不可信的收益数字。
    </div></div>`;
  }
  const bits = [];
  if (rec.action === "add_partition") {
    bits.push(`按 <span class="mono">${esc((rec.partition_by || []).join(", "))}</span> 重建分区`);
    if (rec.keep_partitions && rec.keep_partitions.length) bits.push(`保留 <span class="mono">${esc(rec.keep_partitions.join(", "))}</span>`);
  } else if (rec.action === "cluster") {
    bits.push(`按 <span class="mono">${esc(rec.cluster_by)}</span> 排序（每文件目标 ${fmtBytes(rec.target_file_bytes)}）`);
  } else if (rec.action === "materialize") {
    bits.push(`物化 <span class="mono">${esc((rec.group_by || []).join(", ") || "全局")}</span> 聚合`);
  } else if (rec.action === "compact") {
    bits.push(`合并至目标 ${fmtBytes(rec.target_file_bytes)}`);
  }
  if (rec.note) bits.push(`<span class="hint">${esc(rec.note)}</span>`);
  return `<div class="callout callout-info"><span class="ico">→</span><div>
    <strong>建议动作：${esc(ACTION_LABEL[rec.action] || rec.action)}</strong>
    <p class="mt-8">${bits.join("；")}</p>
  </div></div>`;
}

function renderAdvisoryDetail() {
  const d = state.advisoryDetail;
  const r = d.rationale || {};
  const root = $("#advisory-detail");
  const resolvedApply = (d.applies || []).find((a) => a.status === "applied");

  root.innerHTML = `
    <div class="card">
      <div class="card-head">
        <div>
          <h2>${esc(d.title)}</h2>
          <p class="card-sub">
            ${kindTag(d.kind)} ${sevTag(d.severity)} ${confTag(d.confidence)}
            <span class="mono" style="margin-left:6px">${esc(d.table_name)}</span>
            <span class="hint" style="margin-left:6px">更新于 ${fmtTime(d.updated_at)}</span>
          </p>
        </div>
        <div class="row-actions">
          ${d.fingerprint ? `<button class="btn btn-sm btn-ghost" id="btn-run-sample" type="button">重放样本查询</button>` : ""}
        </div>
      </div>

      <div class="section">
        <div class="section-title"><h3>影响面</h3>${
          d.history ? `<span class="hint">${d.history.runs} 次执行 · 累计 ${fmtMs(d.history.total_ms)} · 平均扫描 ${fmtBytes(d.history.avg_bytes)}</span>` : ""
        }</div>
        ${rationaleBlock(r)}
      </div>

      <div class="section">
        <div class="section-title"><h3>建议动作</h3></div>
        ${recommendationBlock(r)}
      </div>

      <div class="section">
        <div class="section-title">
          <h3>查询样本</h3>
          <span class="hint">指标由本地重放实测</span>
        </div>
        ${sampleTable(d.sample_executions)}
      </div>

      <div class="section" id="sim-section">
        <div class="section-title">
          <h3>模拟计划</h3>
          ${d.simulations && d.simulations.length ? `<span class="hint">共 ${d.simulations.length} 次模拟，最近 ${fmtTime(d.simulations[0].ts)}</span>` : ""}
        </div>
        <div id="sim-body">${d.simulations && d.simulations.length ? `<button class="btn" id="btn-show-last-sim" type="button">查看最近一次模拟</button>` : ""}</div>
        <div class="row-actions mt-12">
          <button class="btn btn-primary" id="btn-simulate" type="button" ${r.recommendation ? "" : "disabled title='该建议没有可应用动作'"}>
            生成模拟计划
          </button>
          <span class="hint">模拟不执行任何数据变更；应用前会创建回滚点。</span>
        </div>
      </div>

      <div class="section" id="apply-section">
        <div class="section-title"><h3>应用前后对比</h3>${resolvedApply ? `<span class="tag tag-conf-high"><span class="dot"></span>已应用 #${resolvedApply.id}</span>` : ""}</div>
        <div id="apply-body">${resolvedApply ? applyComparison(resolvedApply, d.simulations || []) : `<p class="hint">尚未应用。应用后这里会展示用同一查询实测的前后对比、估算与实际收益的差异，以及撤销入口。</p>`}</div>
      </div>
    </div>`;

  if (d.simulations && d.simulations.length) {
    const btn = $("#btn-show-last-sim");
    if (btn) btn.addEventListener("click", () => showSimulation(d.simulations[0]));
  }
  $("#btn-simulate").addEventListener("click", () => runSimulation(d.id));
  $("#btn-run-sample")?.addEventListener("click", () => replaySample(d));
  if (state.simulation) showSimulation(state.simulation);
  if (resolvedApply) bindUndo(resolvedApply);
}

function replaySample(d) {
  const sample = (d.sample_executions || [])[0];
  if (!sample) return;
  api("/api/executions", { method: "POST", body: JSON.stringify({ query: sample.query, client: "ui-replay" }) })
    .then((res) => {
      toast(`重放完成：${fmtMs(res.metrics.duration_ms)}，扫描 ${res.metrics.files_scanned}/${res.metrics.files_total} 文件`);
      selectAdvisory(d.id);
    })
    .catch((e) => toast(e.message, true));
}

async function runSimulation(id) {
  const body = $("#sim-body");
  body.innerHTML = `<span class="spinner"></span> 正在根据目录统计计算计划…`;
  try {
    const res = await api(`/api/advisories/${id}/simulate`, { method: "POST", body: "{}" });
    state.simulation = res.simulation;
    showSimulation(res.simulation, res.explanation);
    // refresh detail's simulation list
    const detail = await api(`/api/advisories/${id}`);
    state.advisoryDetail = detail;
  } catch (err) {
    body.innerHTML = `<div class="callout callout-danger"><span class="ico">!</span><div>${esc(err.message)}</div></div>`;
  }
}

function showSimulation(sim, explanation) {
  const body = $("#sim-body");
  const plan = sim.plan || sim;
  const estimates = plan.estimates || sim.estimates || {};
  const steps = plan.steps || [];
  const measurement = plan.measurement || {};
  body.innerHTML = `
    <div class="callout callout-warn">
      <span class="ico">⚠</span>
      <div><strong>以下数字是估算，不是收益。</strong>它们来自目录统计与区间模型；只有应用后实测到的数值才能作为收益依据。</div>
    </div>
    <div class="facts mt-12">
      <div class="fact"><div class="fact-label">动作</div><div class="fact-value" style="font-size:14px">${esc(ACTION_LABEL[plan.action] || plan.action)}</div></div>
      <div class="fact"><div class="fact-label">目标表</div><div class="fact-value mono" style="font-size:14px">${esc(plan.table)}</div></div>
      <div class="fact"><div class="fact-label">状态指纹</div><div class="fact-value mono" style="font-size:12px">${esc(plan.state_fingerprint)}</div></div>
      <div class="fact"><div class="fact-label">目标文件大小</div><div class="fact-value" style="font-size:14px">${plan.target && plan.target.target_file_bytes ? fmtBytes(plan.target.target_file_bytes) : "保持现状"}</div></div>
    </div>

    <div class="section-title mt-16"><h3>执行计划</h3></div>
    <ol class="steps">${steps.map((s) => `<li>${esc(stepText(s))}</li>`).join("")}</ol>

    <div class="section-title mt-16"><h3>估算（含区间）</h3></div>
    <div class="table-wrap"><table class="data">
      <thead><tr><th>指标</th><th class="num">估算值</th><th class="num">区间</th><th>依据</th></tr></thead>
      <tbody>
        ${Object.entries(estimates)
          .filter(([, v]) => v && typeof v === "object")
          .map(([k, v]) => `<tr>
            <td>${esc(metricLabel(k))}</td>
            <td class="num">${v.value == null ? "不估算" : fmtInt(k.includes("bytes") ? v.value : Math.round(v.value * 10) / 10)}</td>
            <td class="num">${v.bound_low == null ? "—" : `${fmtInt(Math.round(v.bound_low))} – ${fmtInt(Math.round(v.bound_high))}`}</td>
            <td class="hint">${esc(v.basis || "")}</td>
          </tr>`)
          .join("")}
      </tbody>
    </table></div>

    <div class="section-title mt-16"><h3>测量口径</h3></div>
    <p class="hint">应用前后都会用 <strong>同一条查询</strong> 重新执行并记录实测值：</p>
    <pre class="sql mt-8">${esc(measurement.query || "—")}</pre>
    <p class="hint mt-8">来源：${esc(measurement.source || "—")}${measurement.execution_id ? ` · 执行样本 #${measurement.execution_id}` : ""}</p>

    <div class="section-title mt-16"><h3>模型假设</h3></div>
    <ul class="bullets">${(plan.assumptions || []).map((a) => `<li>${esc(a)}</li>`).join("")}</ul>

    ${explanation ? `<details class="evidence mt-12"><summary>可解释性说明</summary><div class="evidence-body"><ul class="bullets">${explanation.map((l) => `<li>${esc(l.replace(/`/g, ""))}</li>`).join("")}</ul></div></details>` : ""}

    <div class="row-actions mt-16">
      <button class="btn btn-primary" id="btn-apply" type="button">应用变更（先创建回滚点）</button>
      <span class="hint">应用前会校验目录状态指纹；若期间数据变化，将拒绝应用并要求重新模拟。</span>
    </div>`;
  $("#btn-apply").addEventListener("click", () => applySimulation(sim.id || sim.simulation_id));
}

function stepText(s) {
  const map = {
    read_all_rows: () => `读取 ${s.rows != null ? fmtInt(s.rows) + " 行" : "全表"}`,
    repartition: () => `按 ${(s.by || []).join(", ")} 重新分区`,
    rewrite_files: () => `重写文件（目标 ${fmtBytes(s.target_file_bytes)}）`,
    recompute_zone_maps: () => "重算每个文件的 zone map（min/max/空值）",
    swap_catalog: () => "原子替换目录清单",
    sort: () => `按 ${(s.keys || []).join(", ")} 排序`,
    aggregate_once: () => `执行一次聚合（按 ${(s.group_by || []).join(", ") || "全局"}）`,
    create_table: () => `创建汇总表 ${s.name}`,
    point_query_at_summary: () => "把查询指向汇总表",
    group_small_files: () => `收集 ${s.input_files} 个小文件`,
    merge_and_rewrite: () => `合并并重写（目标 ${fmtBytes(s.target_file_bytes)}）`,
  };
  const f = map[s.op];
  return f ? f() : s.op;
}
function metricLabel(k) {
  return {
    files_scanned: "扫描文件数",
    total_files_after: "变更后总文件数",
    bytes_scanned: "扫描字节",
    duration_ms: "耗时",
    group_cardinality: "分组基数",
    partition_dirs: "分区目录数",
  }[k] || k;
}

async function applySimulation(simId) {
  if (!confirm("将按计划重写该表文件。会先创建可撤销的回滚点，再执行变更。继续？")) return;
  try {
    toast("正在创建回滚点并应用…");
    const res = await api(`/api/simulations/${simId}/apply`, { method: "POST", body: "{}" });
    toast(`应用完成：扫描文件 ${res.before.files_scanned} → ${res.after.files_scanned}`);
    state.simulation = null;
    const detail = await api(`/api/advisories/${state.selectedAdvisory}`);
    state.advisoryDetail = detail;
    renderAdvisoryDetail();
    await loadAdvisories(false);
  } catch (err) {
    toast(err.message, true);
    if (err.code === "state_changed") {
      const body = $("#sim-body");
      if (body) body.insertAdjacentHTML("afterbegin",
        `<div class="callout callout-danger"><span class="ico">!</span><div>
          <strong>目录状态已变化，估算失效。</strong>请重新生成模拟计划后再应用。
        </div></div>`);
    }
  }
}

function applyComparison(apply, sims) {
  const before = apply.before || {};
  const after = apply.after || {};
  const sim = sims.find((s) => s.id === apply.simulation_id) || {};
  const plan = sim.plan || {};
  const est = plan.estimates || {};
  const cmp = est.files_scanned && est.files_scanned.value != null && after.files_scanned != null
    ? {
        delta: after.files_scanned - est.files_scanned.value,
        within: est.files_scanned.bound_low != null &&
          after.files_scanned >= est.files_scanned.bound_low &&
          after.files_scanned <= est.files_scanned.bound_high,
      }
    : null;

  const byteDrop = before.bytes_scanned ? ((before.bytes_scanned - after.bytes_scanned) / before.bytes_scanned) * 100 : null;
  const timeDrop = before.duration_ms ? ((before.duration_ms - after.duration_ms) / before.duration_ms) * 100 : null;

  return `
    <div class="grid-2">
      <div>
        ${beforeAfterChart(before.files_scanned ?? 0, after.files_scanned ?? 0, (v) => `${fmtInt(v)} 个文件`, "扫描文件数", `文件总数：前 ${before.files_total} → 后 ${after.files_total}`)}
      </div>
      <div>
        ${beforeAfterChart(before.bytes_scanned ?? 0, after.bytes_scanned ?? 0, fmtBytes, "扫描字节", "同一查询、同一目录状态下的重放结果")}
      </div>
    </div>
    <div class="grid-2 mt-16">
      <div>
        ${beforeAfterChart(before.duration_ms ?? 0, after.duration_ms ?? 0, fmtMs, "执行耗时", "本地重放耗时，受机器负载影响")}
      </div>
      <div>
        <div class="section-title"><h3>实测收益</h3></div>
        <div class="stat-row"><span class="k">扫描字节省略</span><span class="v">${byteDrop == null ? "—" : `<span class="${byteDrop > 0 ? "delta-pos" : "delta-none"}">${byteDrop.toFixed(1)}%</span>`}</span></div>
        <div class="stat-row"><span class="k">扫描文件省略</span><span class="v">${before.files_scanned ? (((before.files_scanned - after.files_scanned) / before.files_scanned) * 100).toFixed(1) + "%" : "—"}</span></div>
        <div class="stat-row"><span class="k">耗时缩短</span><span class="v">${timeDrop == null ? "—" : `<span class="${timeDrop > 0 ? "delta-pos" : "delta-none"}">${timeDrop.toFixed(1)}%</span>`}</span></div>
        <div class="stat-row"><span class="k">执行样本</span><span class="v">#${esc(apply.id)} · ${fmtTime(apply.ts)}</span></div>
        <div class="stat-row"><span class="k">回滚点</span><span class="v">#${esc(apply.rollback_point_id)}</span></div>
      </div>
    </div>

    <div class="mt-16">
      ${estimateCallout(est, before.files_scanned, after.files_scanned)}
    </div>
    ${cmp && !cmp.within ? `<div class="callout callout-warn mt-12"><span class="ico">⚠</span><div>
        <strong>实测超出估算区间 ${fmtInt(Math.abs(cmp.delta))} 个文件。</strong>估算模型低估了变更效果；页面以实测为准，并保留此次偏差供校准。
      </div></div>` : ""}

    <div class="details mt-16">
      <div class="section-title"><h3>测量查询</h3>${after.rewritten ? '<span class="tag">已改写为读汇总表</span>' : ""}</div>
      <pre class="sql">${esc(after.query || plan.measurement?.query || "")}</pre>
    </div>

    <div class="row-actions mt-16">
      <button class="btn btn-danger" id="btn-undo" type="button">撤销此次应用（从回滚点恢复）</button>
      <span class="hint">撤销会恢复文件与目录清单，并用恢复后的布局重新实测。</span>
    </div>`;
}

function bindUndo(apply) {
  const btn = $("#btn-undo");
  if (!btn) return;
  btn.addEventListener("click", async () => {
    if (!confirm(`将撤销应用 #${apply.id} 并恢复回滚点 #${apply.rollback_point_id}。继续？`)) return;
    try {
      toast("正在恢复回滚点…");
      const res = await api(`/api/applies/${apply.id}/undo`, { method: "POST", body: "{}" });
      toast(`已撤销：恢复 ${res.restored.restored_files} 个文件`);
      const detail = await api(`/api/advisories/${state.selectedAdvisory}`);
      state.advisoryDetail = detail;
      renderAdvisoryDetail();
      await loadAdvisories(false);
    } catch (err) {
      toast(err.message, true);
    }
  });
}

// ---------------------------------------------------------------- advisories tab
async function loadAdvisories(doAnalyze = true) {
  const btn = $("#btn-analyze");
  btn.disabled = true;
  try {
    if (doAnalyze) await api("/api/analyze", { method: "POST", body: "{}" });
    const data = await api("/api/advisories");
    state.advisories = data.advisories;
    renderAdvisoryList();
    const open = state.advisories.filter((a) => a.status === "open").length;
    $("#advisory-count").textContent = `${state.advisories.length} 条 · ${open} 待处理`;
    if (state.selectedAdvisory && state.advisories.some((a) => a.id === state.selectedAdvisory)) {
      await selectAdvisory(state.selectedAdvisory);
    }
  } catch (err) {
    toast(err.message, true);
  } finally {
    btn.disabled = false;
  }
}

// ---------------------------------------------------------------- history tab
async function loadGroups() {
  const root = $("#group-list");
  root.innerHTML = `<li class="hint" style="padding:8px">载入中…</li>`;
  try {
    const data = await api("/api/history/groups");
    state.groups = data.groups;
    state.anomalies = data.abnormal;
    $("#group-count").textContent = `${data.groups.length} 个形状`;
    root.innerHTML = data.groups
      .map(
        (g) => `<li class="group-item ${state.selectedGroup === g.fingerprint ? "is-selected" : ""}" data-fp="${esc(g.fingerprint)}" tabindex="0" role="button">
          <div class="advisory-title mono" style="font-size:11.5px">${esc(g.fingerprint)}</div>
          <div class="advisory-meta">
            <span class="mono">${esc(g.table)}</span>
            <span>${g.runs} 次</span>
            <span>累计 ${fmtMs(g.total_ms)}</span>
            ${g.is_aggregation ? '<span class="tag tag-kind">聚合</span>' : ""}
          </div>
          <div class="hint mt-8" style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(g.sample_query)}</div>
        </li>`
      )
      .join("");
    $$(".group-item", root).forEach((el) => {
      el.addEventListener("click", () => selectGroup(el.dataset.fp));
      el.addEventListener("keydown", (e) => {
        if (e.key === "Enter") selectGroup(el.dataset.fp);
      });
    });
  } catch (err) {
    root.innerHTML = `<li class="hint">${esc(err.message)}</li>`;
  }
}

async function selectGroup(fp) {
  state.selectedGroup = fp;
  $$(".group-item").forEach((el) => el.classList.toggle("is-selected", el.dataset.fp === fp));
  const g = state.groups.find((x) => x.fingerprint === fp);
  const root = $("#history-detail");
  if (!g) return;
  root.innerHTML = `<div class="card"><div class="card-body"><span class="spinner"></span> 载入执行样本…</div></div>`;
  const data = await api(`/api/history?fingerprint=${encodeURIComponent(fp)}&limit=50`);
  const items = data.items;
  const total = items.reduce((a, x) => a + x.bytes_scanned, 0);
  const last = items[0];
  root.innerHTML = `
    <div class="card">
      <div class="card-head">
        <div>
          <h2>执行样本 · <span class="mono" style="font-size:13px">${esc(fp)}</span></h2>
          <p class="card-sub"><span class="mono">${esc(g.table)}</span> · ${data.total} 次执行 · 累计 ${fmtMs(g.total_ms)}</p>
        </div>
      </div>
      <div class="section">
        <div class="section-title"><h3>规范化查询</h3><span class="hint">字面量已归一，用于识别同一查询形状</span></div>
        <pre class="sql">${esc(g.sample_query)}</pre>
      </div>
      <div class="section">
        <div class="section-title"><h3>最新一次的执行计划</h3></div>
        ${planView(last.plan, last)}
      </div>
      <div class="section">
        <div class="section-title"><h3>样本明细</h3><span class="hint">按时间倒序</span></div>
        ${sampleTable(items)}
      </div>
      <div class="section">
        <div class="section-title"><h3>重放</h3><span class="hint">在本地数据湖上真实执行并写入历史</span></div>
        <div class="row-actions">
          <button class="btn" id="btn-replay" type="button">重放此查询</button>
          <span class="hint">重放会把新的执行记录追加到历史，可用于验证统计是否过期。</span>
        </div>
        <div id="replay-out" class="mt-12"></div>
      </div>
    </div>`;
  $("#btn-replay").addEventListener("click", async () => {
    const out = $("#replay-out");
    out.innerHTML = `<span class="spinner"></span> 正在执行…`;
    try {
      const res = await api("/api/executions", { method: "POST", body: JSON.stringify({ query: g.sample_query, client: "ui-replay" }) });
      out.innerHTML = `<div class="callout callout-good"><span class="ico">✓</span><div>
        <strong>重放完成。</strong>耗时 ${fmtMs(res.metrics.duration_ms)}，扫描 ${fmtBytes(res.metrics.bytes_scanned)}（${res.metrics.files_scanned}/${res.metrics.files_total} 文件），返回 ${fmtInt(res.metrics.rows_returned)} 行。
        <p class="hint mt-8">对比历史样本：累计 ${data.total} 次，平均耗时 ${fmtMs(g.avg_ms)}。若实测与历史差异显著，可能存在统计过期。</p>
      </div></div>`;
    } catch (err) {
      out.innerHTML = `<div class="callout callout-danger"><span class="ico">!</span><div>${esc(err.message)}</div></div>`;
    }
  });
}

function planView(plan, exec) {
  if (!plan || !plan.steps) return `<p class="hint">该执行未记录计划。</p>`;
  return `
    <div class="facts">
      <div class="fact"><div class="fact-label">候选文件</div><div class="fact-value">${fmtInt(plan.files_total)}</div></div>
      <div class="fact"><div class="fact-label">实际扫描</div><div class="fact-value">${fmtInt(plan.files_scanned)}</div></div>
      <div class="fact"><div class="fact-label">裁剪文件</div><div class="fact-value">${fmtInt(plan.files_pruned)}</div></div>
      ${plan.prune_reasons ? `<div class="fact"><div class="fact-label">分区裁剪</div><div class="fact-value">${fmtInt(plan.prune_reasons.partition || 0)}</div></div>` : ""}
      ${plan.prune_reasons ? `<div class="fact"><div class="fact-label">zone map 裁剪</div><div class="fact-value">${fmtInt(plan.prune_reasons.zone_map || 0)}</div></div>` : ""}
      <div class="fact"><div class="fact-label">耗时</div><div class="fact-value">${fmtMs(exec.duration_ms)}</div></div>
    </div>
    <div class="section-title mt-12"><h3>步骤</h3></div>
    <table class="data">
      <thead><tr><th>阶段</th><th>说明</th></tr></thead>
      <tbody>${(plan.steps || []).map((s) => `<tr><td class="mono">${esc(s.step)}</td><td>${esc(s.detail)}</td></tr>`).join("")}</tbody>
    </table>`;
}

// ---------------------------------------------------------------- validation tab
async function loadValidation() {
  const root = $("#validation-root");
  root.innerHTML = `
    <div class="card"><div class="card-body">
      <div class="section-title"><h3>验证统计过期与异常查询</h3><span class="hint">读取目录统计与执行历史进行核对</span></div>
      <div class="row-actions">
        <button class="btn" id="btn-check-anomalies" type="button">重算异常查询</button>
        <button class="btn" id="btn-check-stats" type="button">核对表的 zone map 统计</button>
        <button class="btn btn-ghost" id="btn-refresh-all" type="button">刷新全部统计</button>
      </div>
      <p class="hint mt-8">“统计过期”：目录记录的最后数据变更时间晚于统计更新时间。此时所有裁剪与收益投影都不可信，应先刷新统计。</p>
    </div></div>`;
  $("#btn-check-anomalies").addEventListener("click", runAnomalies);
  $("#btn-check-stats").addEventListener("click", () => runStatsCheck(null));
  $("#btn-refresh-all").addEventListener("click", refreshAllStats);
  await Promise.all([runStatsCheck(null), runAnomalies()]);
}

async function runStatsCheck(_) {
  const host = $("#validation-root");
  let existing = $("#stats-card", host);
  if (!existing) {
    host.insertAdjacentHTML("beforeend", `<div class="card" id="stats-card"><div class="card-body"><span class="spinner"></span> 核对统计…</div></div>`);
    existing = $("#stats-card", host);
  } else {
    existing.innerHTML = `<div class="card-body"><span class="spinner"></span> 核对统计…</div>`;
  }
  try {
    const list = await api("/api/validations/stats");
    const checks = await Promise.all(
      list.tables_all.map((t) => api(`/api/validations/stats/${encodeURIComponent(t.table)}`).catch(() => null))
    );
    existing.innerHTML = `
      <div class="card-head">
        <div><h2>统计一致性</h2><p class="card-sub">逐表核对：目录统计是否落后于数据变更，以及 zone map 是否与真实文件一致</p></div>
      </div>
      <div class="card-body">
        ${list.tables.length ? `<div class="callout callout-warn"><span class="ico">⚠</span><div>
          <strong>${list.tables.length} 张表的统计已过期：</strong>
          ${list.tables.map((t) => `<span class="mono">${esc(t.table)}</span>`).join("、")}。
          这些表的裁剪决策与收益投影可能偏离实际，请先刷新统计。
        </div></div>` : `<div class="callout callout-good"><span class="ico">✓</span><div>所有表的统计时间均不早于最后数据变更。</div></div>`}
        <div class="table-wrap mt-12"><table class="data">
          <thead><tr><th>表</th><th>统计时间</th><th>最后数据变更</th><th>zone map 漂移</th><th>核对文件</th><th>结论</th><th></th></tr></thead>
          <tbody>${checks.filter(Boolean).map((c) => `
            <tr>
              <td class="mono">${esc(c.table)}</td>
              <td>${fmtTime(c.stats_updated_at)}</td>
              <td>${fmtTime(c.last_data_change_at)}</td>
              <td class="num">${fmtInt(c.drift_count)}</td>
              <td class="num">${fmtInt(c.checked_files)}</td>
              <td>${c.verdict === "ok"
                ? '<span class="tag tag-conf-high"><span class="dot"></span>一致</span>'
                : '<span class="tag tag-high"><span class="dot"></span>需要刷新</span>'}</td>
              <td>${c.verdict === "ok" ? "" : `<button class="btn btn-sm" data-refresh="${esc(c.table)}" type="button">刷新</button>`}</td>
            </tr>`).join("")}</tbody>
        </table></div>
        ${checks.filter(Boolean).some((c) => c.drift_samples?.length)
          ? `<details class="evidence mt-12"><summary>zone map 漂移明细（预览）</summary><div class="evidence-body">
              <table class="data"><thead><tr><th>文件</th><th>列</th><th>字段</th><th>目录值</th><th>实际值</th></tr></thead><tbody>
              ${checks.filter(Boolean).flatMap((c) => (c.drift_samples || []).map((d) => `<tr><td class="mono">${esc(d.file)}</td><td class="mono">${esc(d.column)}</td><td>${esc(d.field)}</td><td>${esc(d.catalog)}</td><td>${esc(d.actual)}</td></tr>`)).slice(0, 20).join("")}
              </tbody></table></div></details>` : ""}
      </div>`;
    $$("[data-refresh]", existing).forEach((btn) =>
      btn.addEventListener("click", async () => {
        btn.disabled = true;
        try {
          await api(`/api/validations/stats/${encodeURIComponent(btn.dataset.refresh)}/refresh`, { method: "POST", body: "{}" });
          toast(`已刷新 ${btn.dataset.refresh} 的统计`);
          await runStatsCheck();
        } catch (e) {
          toast(e.message, true);
          btn.disabled = false;
        }
      })
    );
  } catch (err) {
    existing.innerHTML = `<div class="card-body"><div class="callout callout-danger"><span class="ico">!</span><div>${esc(err.message)}</div></div></div>`;
  }
}

async function refreshAllStats() {
  try {
    const list = await api("/api/validations/stats");
    for (const t of list.tables) {
      await api(`/api/validations/stats/${encodeURIComponent(t.table)}/refresh`, { method: "POST", body: "{}" });
    }
    toast("统计已刷新");
    await runStatsCheck();
  } catch (err) {
    toast(err.message, true);
  }
}

async function runAnomalies() {
  const host = $("#validation-root");
  let card = $("#anomaly-card", host);
  if (!card) {
    host.insertAdjacentHTML("beforeend", `<div class="card" id="anomaly-card"><div class="card-body"><span class="spinner"></span> 扫描执行历史…</div></div>`);
    card = $("#anomaly-card", host);
  } else {
    card.innerHTML = `<div class="card-body"><span class="spinner"></span> 扫描执行历史…</div>`;
  }
  try {
    const data = await api("/api/validations/anomalies");
    const items = data.anomalies || [];
    card.innerHTML = `
      <div class="card-head">
        <div><h2>异常查询</h2><p class="card-sub">错误执行、慢于同形状中位数 4 倍的离群、扫描量突增、无过滤全表扫描 · 共扫描 ${fmtInt(data.scanned)} 条执行</p></div>
        <span class="count-pill">${items.length} 条</span>
      </div>
      <div class="card-body">
        ${items.length === 0 ? `<div class="callout callout-good"><span class="ico">✓</span><div>未发现异常执行。</div></div>` : `
        <div class="table-wrap"><table class="data">
          <thead><tr><th>时间</th><th>表</th><th>原因</th><th>查询</th></tr></thead>
          <tbody>${items.map((a) => `<tr>
            <td>${fmtTime(a.ts)}</td>
            <td class="mono">${esc(a.table)}</td>
            <td>${a.reasons.map((r) => `<div><span class="tag tag-${r.kind === "error" ? "critical" : "medium"}"><span class="dot"></span>${esc(reasonLabel(r.kind))}</span> <span class="hint">${esc(r.detail)}</span></div>`).join("")}</td>
            <td class="mono" style="max-width:360px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(a.query)}">${esc(a.query)}</td>
          </tr>`).join("")}</tbody>
        </table></div>`}
      </div>`;
  } catch (err) {
    card.innerHTML = `<div class="card-body"><div class="callout callout-danger"><span class="ico">!</span><div>${esc(err.message)}</div></div></div>`;
  }
}
const reasonLabel = (k) => ({
  error: "执行失败",
  slow_outlier: "慢查询离群",
  scan_spike: "扫描量突增",
  unfiltered_full_scan: "无过滤全表扫描",
}[k] || k);

// ---------------------------------------------------------------- ledger tab
async function loadLedger() {
  const root = $("#ledger-root");
  root.innerHTML = `<div class="card"><div class="card-body"><span class="spinner"></span> 载入应用与撤销记录…</div></div>`;
  try {
    const [ledger, rps] = await Promise.all([api("/api/undo-log"), api("/api/rollback-points")]);
    root.innerHTML = `
      <div class="card">
        <div class="card-head">
          <div><h2>应用记录</h2><p class="card-sub">每次应用都记录实测前后值、回滚点与撤销状态</p></div>
          <span class="count-pill">${ledger.applies.length} 条</span>
        </div>
        <div class="card-body">
          ${ledger.applies.length === 0 ? `<div class="empty-state" style="padding:32px">还没有应用记录。在“建议”页生成模拟计划并应用后，记录会出现在这里。</div>` :
            `<div class="table-wrap"><table class="data">
              <thead><tr><th>#</th><th>时间</th><th>来源建议</th><th>状态</th><th class="num">扫描文件 前→后</th><th class="num">耗时 前→后</th><th>回滚点</th><th></th></tr></thead>
              <tbody>${ledger.applies.map((a) => `<tr>
                <td class="num">${a.id}</td>
                <td>${fmtTime(a.ts)}</td>
                <td>${esc(a.advisory_kind ? KIND_LABEL[a.advisory_kind] || a.advisory_kind : "—")}<div class="hint">${esc(a.advisory_title || "")}</div></td>
                <td>${statusTag(a.status)}</td>
                <td class="num">${a.before?.files_scanned ?? "—"} → ${a.after?.files_scanned ?? "—"}</td>
                <td class="num">${a.before?.duration_ms != null ? fmtMs(a.before.duration_ms) : "—"} → ${a.after?.duration_ms != null ? fmtMs(a.after.duration_ms) : "—"}</td>
                <td class="mono">#${a.rollback_point_id ?? "—"}</td>
                <td>${a.status === "applied" ? `<button class="btn btn-sm btn-danger" data-undo="${a.id}" type="button">撤销</button>` : ""}</td>
              </tr>`).join("")}</tbody>
            </table></div>`}
        </div>
      </div>

      <div class="card">
        <div class="card-head">
          <div><h2>回滚点</h2><p class="card-sub">应用前对目录清单与文件字节的快照</p></div>
          <span class="count-pill">${rps.rollback_points.length} 个</span>
        </div>
        <div class="card-body">
          ${rps.rollback_points.length === 0 ? `<p class="hint">暂无回滚点。</p>` :
            `<div class="table-wrap"><table class="data">
              <thead><tr><th>#</th><th>创建时间</th><th>表</th><th>类型</th><th class="num">文件数</th><th class="num">快照字节</th><th>状态</th></tr></thead>
              <tbody>${rps.rollback_points.map((r) => `<tr>
                <td class="num">${r.id}</td><td>${fmtTime(r.ts)}</td>
                <td class="mono">${esc(r.table || "—")}</td><td class="hint">${esc(r.kind)}</td>
                <td class="num">${fmtInt(r.files)}</td><td class="num">${fmtBytes(r.snapshot_bytes)}</td>
                <td>${rpStateTag(r.state)}</td>
              </tr>`).join("")}</tbody>
            </table></div>`}
        </div>
      </div>

      <div class="card">
        <div class="card-head">
          <div><h2>撤销记录</h2><p class="card-sub">应用与撤销的追加式审计日志</p></div>
          <span class="count-pill">${ledger.undo_log.length} 条</span>
        </div>
        <div class="card-body">
          ${ledger.undo_log.length === 0 ? `<p class="hint">暂无日志。</p>` :
            `<ul class="bullets" style="list-style:none;padding:0">${ledger.undo_log.map((l) => `
              <li style="padding:8px 0;border-bottom:1px solid var(--border)">
                <span class="tag ${l.action === "undo" ? "tag-high" : "tag-conf-high"}"><span class="dot"></span>${l.action === "undo" ? "撤销" : l.action === "analyze" ? "刷新统计" : "应用"}</span>
                <span class="hint" style="margin-left:8px">${fmtTime(l.ts)}${l.apply_id ? ` · 应用 #${l.apply_id}` : ""}</span>
                <div class="hint mono mt-8" style="word-break:break-all">${esc(JSON.stringify(l.detail).slice(0, 300))}${JSON.stringify(l.detail).length > 300 ? "…" : ""}</div>
              </li>`).join("")}</ul>`}
        </div>
      </div>`;

    $$("[data-undo]", root).forEach((btn) =>
      btn.addEventListener("click", async () => {
        if (!confirm(`撤销应用 #${btn.dataset.undo}？将从回滚点恢复表布局。`)) return;
        btn.disabled = true;
        try {
          await api(`/api/applies/${btn.dataset.undo}/undo`, { method: "POST", body: "{}" });
          toast("已撤销并恢复");
          await loadLedger();
          await loadAdvisories(false);
        } catch (e) {
          toast(e.message, true);
          btn.disabled = false;
        }
      })
    );
  } catch (err) {
    root.innerHTML = `<div class="callout callout-danger"><span class="ico">!</span><div>${esc(err.message)}</div></div>`;
  }
}

const statusTag = (s) => ({
  applied: '<span class="tag tag-conf-high"><span class="dot"></span>已应用</span>',
  undone: '<span class="tag tag-conf-medium"><span class="dot"></span>已撤销</span>',
  failed: '<span class="tag tag-critical"><span class="dot"></span>失败</span>',
  applying: '<span class="tag tag-medium"><span class="dot"></span>进行中</span>',
}[s] || `<span class="tag">${esc(s)}</span>`);

const rpStateTag = (s) => ({
  available: '<span class="tag tag-conf-high"><span class="dot"></span>可用</span>',
  used: '<span class="tag tag-conf-medium"><span class="dot"></span>已使用</span>',
  preparing: '<span class="tag tag-medium"><span class="dot"></span>准备中</span>',
}[s] || `<span class="tag">${esc(s)}</span>`);

// ---------------------------------------------------------------- bootstrap
function wireTabs() {
  $$(".tab").forEach((tab) => {
    tab.addEventListener("click", () => {
      $$(".tab").forEach((t) => {
        t.classList.toggle("is-active", t === tab);
        t.setAttribute("aria-selected", t === tab ? "true" : "false");
      });
      $$(".panel").forEach((p) => p.classList.toggle("is-active", p.id === `panel-${tab.dataset.tab}`));
      if (tab.dataset.tab === "history") loadGroups();
      if (tab.dataset.tab === "validation") loadValidation();
      if (tab.dataset.tab === "ledger") loadLedger();
    });
  });
  $$(".chip").forEach((chip) => {
    chip.addEventListener("click", () => {
      $$(".chip").forEach((c) => c.classList.toggle("is-active", c === chip));
      state.kindFilter = chip.dataset.kind;
      renderAdvisoryList();
    });
  });
  $("#btn-analyze").addEventListener("click", async () => {
    toast("正在重新分析…");
    await loadAdvisories(true);
    toast("分析完成");
  });
}

async function boot() {
  wireTabs();
  try {
    const health = await api("/api/health");
    $("#data-badge").textContent = health.db.includes(".data") ? "本地数据湖" : "数据目录";
    $("#data-badge").title = health.db;
  } catch (e) {
    /* ignore */
  }
  await loadAdvisories(false);
}

boot();
