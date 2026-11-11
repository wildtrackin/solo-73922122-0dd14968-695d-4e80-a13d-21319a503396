/* 设备授权演示页：左侧模拟无浏览器终端，右侧人工审批控制台。 */

const state = {
  deviceCode: null,
  userCode: null,
  clientId: null,
  accessToken: null,
  autoTimer: null,
  currentApproval: null,
  approver: null,
};

const $ = (id) => document.getElementById(id);

async function api(url, body) {
  const opts = { method: "GET", headers: { "Content-Type": "application/json" } };
  if (body !== undefined) {
    opts.method = "POST";
    opts.body = JSON.stringify(body);
  }
  const resp = await fetch(url, opts);
  const data = await resp.json().catch(() => ({}));
  if (!resp.ok) {
    const err = new Error(data.message || data.error || `HTTP ${resp.status}`);
    err.code = data.error;
    err.status = resp.status;
    throw err;
  }
  return data;
}

function fmtTime(ts) {
  return new Date(ts * 1000).toLocaleString("zh-CN", { hour12: false });
}

function log(target, message, payload) {
  const time = new Date().toLocaleTimeString("zh-CN", { hour12: false });
  let line = `[${time}] ${message}`;
  if (payload !== undefined) line += "\n" + JSON.stringify(payload, null, 2);
  target.textContent += line + "\n";
  target.scrollTop = target.scrollHeight;
}

const termLog = () => $("terminalLog");
const adminLog = () => $("adminLog");

// ---------------------------------------------------------------------------
// 演示身份切换
// ---------------------------------------------------------------------------

async function loadIdentities() {
  const data = await api("/api/admin/identities");
  const sel = $("identitySelect");
  sel.innerHTML = "";
  for (const name of data.identities) {
    const opt = document.createElement("option");
    opt.value = name;
    opt.textContent = name;
    sel.appendChild(opt);
  }
  state.approver = sel.value;
  sel.addEventListener("change", () => {
    state.approver = sel.value;
    log(adminLog(), `已切换本地演示身份：${sel.value}`);
  });
}

// ---------------------------------------------------------------------------
// 终端侧
// ---------------------------------------------------------------------------

$("btnAuthorize").addEventListener("click", async () => {
  const clientId = $("clientId").value.trim();
  const deviceName = $("deviceName").value.trim();
  if (!clientId || !deviceName) return alert("请填写客户端 ID 与设备名");
  try {
    const data = await api("/api/device/authorize", { client_id: clientId, device_name: deviceName });
    state.deviceCode = data.device_code;
    state.userCode = data.user_code;
    state.clientId = clientId;
    state.accessToken = null;
    $("authResult").hidden = false;
    $("outDeviceCode").textContent = data.device_code;
    $("outUserCode").textContent = data.user_code;
    $("outExpiresAt").textContent = `${fmtTime(data.expires_at)}（${data.expires_in} 秒）`;
    $("btnClaim").disabled = true;
    $("btnCallIdentity").disabled = true;
    $("inputUserCode").value = data.user_code;
    log(termLog(), "POST /api/device/authorize → 取得设备码与人工短码", data);
    refreshRecords();
  } catch (e) {
    log(termLog(), `发起失败：${e.message}`);
  }
});

$("btnPoll").addEventListener("click", () => pollOnce());

async function pollOnce() {
  if (!state.deviceCode) return;
  try {
    const data = await api("/api/device/poll", {
      client_id: state.clientId,
      device_code: state.deviceCode,
    });
    log(termLog(), "POST /api/device/poll", data);
    if (data.status === "approved") {
      $("btnClaim").disabled = false;
      stopAutoPoll();
    }
    if (data.status === "denied" || data.status === "expired") stopAutoPoll();
    return data.status;
  } catch (e) {
    log(termLog(), `轮询失败：${e.message}（${e.code || e.status}）`);
    stopAutoPoll();
  }
}

$("btnAutoPoll").addEventListener("click", () => {
  if (state.autoTimer) {
    stopAutoPoll();
    return;
  }
  log(termLog(), "开始自动轮询，每 5 秒一次……");
  $("btnAutoPoll").textContent = "停止自动轮询";
  state.autoTimer = setInterval(pollOnce, 5000);
});

function stopAutoPoll() {
  if (state.autoTimer) {
    clearInterval(state.autoTimer);
    state.autoTimer = null;
    $("btnAutoPoll").textContent = "自动轮询（每 5 秒）";
  }
}

$("btnClaim").addEventListener("click", async () => {
  try {
    const data = await api("/api/device/token", {
      client_id: state.clientId,
      device_code: state.deviceCode,
    });
    state.accessToken = data.access_token;
    $("btnClaim").disabled = true;
    $("btnCallIdentity").disabled = false;
    log(termLog(), "POST /api/device/token → 领取令牌成功（明文仅本次返回，服务端只存哈希）", {
      ...data,
      access_token: data.access_token.slice(0, 10) + "…（仅演示截断显示）",
    });
    refreshRecords();
  } catch (e) {
    log(termLog(), `领取令牌失败：${e.message}（${e.code || e.status}）`);
  }
});

$("btnCallIdentity").addEventListener("click", async () => {
  try {
    const resp = await fetch("/api/identity", {
      headers: { Authorization: `Bearer ${state.accessToken}` },
    });
    const data = await resp.json();
    if (!resp.ok) throw new Error(data.message || `HTTP ${resp.status}`);
    log(termLog(), "GET /api/identity（Bearer 令牌）→ 身份信息", data);
  } catch (e) {
    log(termLog(), `身份接口调用失败：${e.message}`);
  }
});

// ---------------------------------------------------------------------------
// 审批侧
// ---------------------------------------------------------------------------

$("btnFind").addEventListener("click", async () => {
  const code = $("inputUserCode").value.trim().toUpperCase();
  if (!code) return;
  try {
    const data = await api("/api/admin/find", { user_code: code });
    state.currentApproval = data;
    renderApproval(data);
    log(adminLog(), `查询短码 ${code}`, data);
  } catch (e) {
    $("approvalBox").hidden = true;
    log(adminLog(), `查询失败：${e.message}`);
  }
});

function renderApproval(item) {
  $("approvalBox").hidden = false;
  const detail = $("approvalDetail");
  detail.innerHTML = "";
  const rows = [
    ["授权编号", item.id],
    ["客户端 ID", item.client_id],
    ["设备名", item.device_name],
    ["当前状态", item.status],
    ["创建时间", fmtTime(item.created_at)],
    ["有效期至", fmtTime(item.expires_at)],
    ["批准者", item.decided_by || "—"],
  ];
  for (const [k, v] of rows) {
    const dt = document.createElement("dt");
    dt.textContent = k;
    const dd = document.createElement("dd");
    dd.textContent = v;
    detail.append(dt, dd);
  }
  const now = Math.floor(Date.now() / 1000);
  const operable = item.status === "pending" && now < item.expires_at;
  $("btnApprove").disabled = !operable;
  $("btnDeny").disabled = !operable;
}

async function decide(decision) {
  const code = $("inputUserCode").value.trim().toUpperCase();
  if (!code || !state.approver) return;
  try {
    const data = await api("/api/admin/decide", {
      user_code: code,
      approver: state.approver,
      decision,
    });
    log(adminLog(), `${state.approver} 对授权 #${data.id} 执行「${decision === "approve" ? "批准" : "拒绝"}」`, data);
    renderApproval(data);
    refreshRecords();
  } catch (e) {
    log(adminLog(), `操作失败：${e.message}（${e.code || e.status}）`);
    $("btnFind").click();
  }
}

$("btnApprove").addEventListener("click", () => decide("approve"));
$("btnDeny").addEventListener("click", () => decide("deny"));

$("btnRefresh").addEventListener("click", refreshRecords);

async function refreshRecords() {
  try {
    const data = await api("/api/admin/authorizations");
    const tbody = $("recordsBody");
    tbody.innerHTML = "";
    for (const it of data.items) {
      const tr = document.createElement("tr");
      const cells = [
        it.id,
        it.client_id,
        it.device_name,
        it.user_code_masked,
        it.status,
        it.decided_by || "—",
        fmtTime(it.expires_at),
      ];
      for (let i = 0; i < cells.length; i++) {
        const td = document.createElement("td");
        td.textContent = cells[i];
        if (i === 4) td.className = `status-${it.status}`;
        tr.appendChild(td);
      }
      tbody.appendChild(tr);
    }
  } catch (e) {
    log(adminLog(), `刷新列表失败：${e.message}`);
  }
}

// 初始化
(async function init() {
  try {
    await loadIdentities();
    log(adminLog(), "页面就绪，可切换演示身份并处理待确认授权");
    log(termLog(), "终端就绪：填写客户端 ID 与设备名后发起授权");
    refreshRecords();
    setInterval(refreshRecords, 10000);
    // 若已打开某个授权，每分钟刷新其可操作状态（过期自动禁用按钮）
    setInterval(() => {
      if (state.currentApproval && !$("approvalBox").hidden) $("btnFind").click();
    }, 30000);
  } catch (e) {
    alert("初始化失败：" + e.message);
  }
})();
