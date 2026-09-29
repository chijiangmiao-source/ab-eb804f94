/* 前端逻辑：动态规则表单 + 真实 API 调用 + 裁决/见证渲染。 */
"use strict";

const MAX_RULES = 18;

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "className") node.className = v;
    else if (k === "textContent") node.textContent = v;
    else node.setAttribute(k, v);
  }
  for (const child of children) {
    if (typeof child === "string") node.appendChild(document.createTextNode(child));
    else if (child) node.appendChild(child);
  }
  return node;
}

function alertBox(where, kind, text) {
  where.replaceChildren();
  where.appendChild(el("div", { className: `alert ${kind}`, textContent: text }));
}

function renumber() {
  document.querySelectorAll("#ruleList .rule-card").forEach((card, i) => {
    card.querySelector(".idx").textContent = `优先级 #${i + 1}`;
  });
  const n = document.querySelectorAll("#ruleList .rule-card").length;
  document.getElementById("ruleCount").textContent = `${n} / ${MAX_RULES}`;
}

function ruleCard(index) {
  const card = el("div", { className: "rule-card" });

  const head = el("div", { className: "head" });
  head.appendChild(el("span", { className: "idx", textContent: `优先级 #${index + 1}` }));
  const del = el("button", { className: "danger", type: "button", textContent: "移除" });
  del.addEventListener("click", () => { card.remove(); renumber(); });
  head.appendChild(del);
  card.appendChild(head);

  card.appendChild(el("label", {}, "规则标识 rule_id"));
  card.appendChild(el("input", { className: "f-rid", placeholder: "例如 R1", value: `R${index + 1}` }));

  const grid = el("div", { className: "row" });
  const protoWrap = el("div");
  protoWrap.appendChild(el("label", {}, "协议"));
  const proto = el("select", { className: "f-proto" });
  for (const p of ["BOTH", "TCP", "UDP"]) {
    proto.appendChild(el("option", { value: p, textContent: p }));
  }
  protoWrap.appendChild(proto);
  grid.appendChild(protoWrap);
  card.appendChild(grid);

  card.appendChild(el("label", {}, "源 CIDR（网络位对齐，如 10.0.0.0/24）"));
  card.appendChild(el("input", { className: "f-src", value: "0.0.0.0/0" }));
  card.appendChild(el("label", {}, "目的 CIDR（网络位对齐，如 192.168.1.0/24）"));
  card.appendChild(el("input", { className: "f-dst", value: "0.0.0.0/0" }));

  const ports = el("div", { className: "row" });
  for (const [cls, lab] of [["f-sport", "源端口闭区间 [起, 止]"], ["f-dport", "目的端口闭区间 [起, 止]"]]) {
    const w = el("div");
    w.appendChild(el("label", {}, lab));
    const box = el("div", { style: "display:flex;gap:6px" });
    box.appendChild(el("input", { className: `${cls} f-port-lo`, type: "number", min: "0", max: "65535", value: "0" }));
    box.appendChild(el("input", { className: `${cls} f-port-hi`, type: "number", min: "0", max: "65535", value: "65535" }));
    w.appendChild(box);
    ports.appendChild(w);
  }
  card.appendChild(ports);
  return card;
}

function collectPayload() {
  const rules = [];
  for (const card of document.querySelectorAll("#ruleList .rule-card")) {
    rules.push({
      rule_id: card.querySelector(".f-rid").value.trim(),
      protocol: card.querySelector(".f-proto").value,
      src_cidr: card.querySelector(".f-src").value.trim(),
      dst_cidr: card.querySelector(".f-dst").value.trim(),
      src_port: [
        Number(card.querySelector(".f-sport.f-port-lo").value),
        Number(card.querySelector(".f-sport.f-port-hi").value),
      ],
      dst_port: [
        Number(card.querySelector(".f-dport.f-port-lo").value),
        Number(card.querySelector(".f-dport.f-port-hi").value),
      ],
    });
  }
  return {
    audit_id: document.getElementById("auditId").value.trim(),
    rules,
  };
}

async function httpJson(url, options = {}) {
  const resp = await fetch(url, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  let body = null;
  try { body = await resp.json(); } catch { /* 非 JSON 响应 */ }
  return { status: resp.status, body };
}

function renderWitness(w) {
  return el("div", { className: "witness-box" },
    el("div", { className: "muted", textContent: "最小报文见证（协议, 源地址, 目的地址, 源端口, 目的端口）" }),
    el("div", {}, `${w.protocol}  ${w.src_addr} → ${w.dst_addr}  :${w.src_port} → :${w.dst_port}`),
  );
}

function renderDecision(d) {
  const tr = el("tr");
  tr.appendChild(el("td", { className: "mono", textContent: d.rule_id }));
  if (d.verdict === "FULLY_COVERED") {
    tr.appendChild(el("td", {}, el("span", { className: "tag full", textContent: "完全遮蔽" })));
    tr.appendChild(el("td", { className: "muted", textContent: "—" }));
    tr.appendChild(el("td", { className: "covered-list" },
      ...d.covered_by.map((id) => el("div", { className: "mono", textContent: id }))));
  } else {
    tr.appendChild(el("td", {}, el("span", { className: "tag partial", textContent: "仍可命中" })));
    tr.appendChild(el("td", {}, renderWitness(d.witness)));
    tr.appendChild(el("td", { className: "muted", textContent: "—" }));
  }
  return tr;
}

function renderRecord(record) {
  const box = document.getElementById("result");
  box.replaceChildren();

  const meta = el("div", { className: "muted", style: "margin-bottom:10px;font-size:12px" });
  meta.appendChild(el("span", { className: "mono", textContent: record.audit_id }));
  meta.appendChild(document.createTextNode(` · ${record.rules.length} 条规则 · 已冻结`));
  if (record.fingerprint) {
    meta.appendChild(el("div", { className: "mono", style: "color:#5f708f",
      textContent: `sha256 ${record.fingerprint.slice(0, 16)}…` }));
  }
  box.appendChild(meta);

  const table = el("table");
  const hr = el("tr");
  for (const h of ["规则标识", "裁决", "最小报文见证", "覆盖它的更早规则"]) {
    hr.appendChild(el("th", { textContent: h }));
  }
  table.appendChild(el("thead", {}, hr));
  const tbody = el("tbody");
  for (const d of record.decisions) tbody.appendChild(renderDecision(d));
  table.appendChild(tbody);
  box.appendChild(table);
}

async function onSubmit() {
  const where = document.getElementById("formAlert");
  where.replaceChildren();
  const payload = collectPayload();
  if (!payload.audit_id) { alertBox(where, "err", "审计标识不能为空"); return; }
  if (!payload.rules.length) { alertBox(where, "err", "至少添加一条规则"); return; }
  if (payload.rules.length > MAX_RULES) { alertBox(where, "err", `至多 ${MAX_RULES} 条规则`); return; }

  const { status, body } = await httpJson("/api/audits", {
    method: "POST",
    body: JSON.stringify(payload),
  });
  if (status === 201 || status === 200) {
    alertBox(where, "ok",
      status === 200 ? "与已冻结载荷完全一致的幂等重传，返回既有结论。" : "提交成功，裁决已冻结。");
    document.getElementById("lookupId").value = payload.audit_id;
    document.getElementById("lookupAlert").replaceChildren();
    renderRecord(body);
  } else {
    alertBox(where, "err", body?.error || `提交失败（HTTP ${status}）`);
  }
}

async function onLookup() {
  const auditId = document.getElementById("lookupId").value.trim();
  const where = document.getElementById("lookupAlert");
  where.replaceChildren();
  if (!auditId) { alertBox(where, "err", "请输入审计标识"); return; }
  const { status, body } = await httpJson(`/api/audits/${encodeURIComponent(auditId)}`);
  if (status === 200) {
    renderRecord(body);
  } else {
    document.getElementById("result").replaceChildren();
    alertBox(where, "err", body?.error || `查询失败（HTTP ${status}）`);
  }
}

document.getElementById("addRule").addEventListener("click", () => {
  const list = document.getElementById("ruleList");
  if (list.children.length >= MAX_RULES) return;
  list.appendChild(ruleCard(list.children.length));
  renumber();
});
document.getElementById("submitBtn").addEventListener("click", onSubmit);
document.getElementById("lookupBtn").addEventListener("click", onLookup);
document.getElementById("lookupId").addEventListener("keydown", (e) => {
  if (e.key === "Enter") onLookup();
});

// 初始两条规则，方便直接录入
document.getElementById("ruleList").appendChild(ruleCard(0));
document.getElementById("ruleList").appendChild(ruleCard(1));
renumber();
