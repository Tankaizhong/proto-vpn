// lab-client.js
// 与 lab/server.py 后端通信，实现"开始 / 停止 / 下载 pcap"。
// 依赖 composer.js 暴露的全局 buildConfig(state) 与 state。

(function () {
  const API = "";  // 同源，由 lab/server.py 静态托管
  const $ = (id) => document.getElementById(id);

  let currentRunId = null;
  let pollTimer = null;

  // ---------- UI helpers ----------
  function setRunningUI(running) {
    $("run").disabled = running;
    $("stop").disabled = !running;
    if (!running) {
      $("run-status").textContent = "";
    }
  }

  function appendLog(msg) {
    const el = $("run-log");
    el.hidden = false;
    el.textContent += msg + "\n";
    el.scrollTop = el.scrollHeight;
  }

  function clearLog() {
    const el = $("run-log");
    el.textContent = "";
    el.hidden = true;
  }

  function showDownload(pcapUrl) {
    const a = $("download");
    a.href = pcapUrl;
    a.hidden = false;
  }

  function hideDownload() {
    const a = $("download");
    a.hidden = true;
    a.removeAttribute("href");
  }

  // ---------- API calls ----------
  async function postJSON(url, body) {
    const res = await fetch(API + url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      throw new Error(data.detail || res.statusText);
    }
    return data;
  }

  async function getJSON(url) {
    const res = await fetch(API + url);
    if (!res.ok) throw new Error(res.statusText);
    return res.json();
  }

  // ---------- run lifecycle ----------
  async function startRun() {
    if (typeof window.buildConfig !== "function" || !window.state) {
      alert("composer.js 未加载，刷新页面重试");
      return;
    }
    const s = window.state;
    if (!s.protocol || !s.transport || !s.tls) {
      alert("请先完成必选项（协议 / 传输 / TLS）");
      return;
    }
    const inbound = window.buildConfig(s);

    clearLog();
    hideDownload();
    setRunningUI(true);
    appendLog(`▶ 提交 inbound: ${inbound.tag || inbound.type}`);

    try {
      const data = await postJSON("/run", { inbound, duration: 30 });
      currentRunId = data.run_id;
      appendLog(`✓ run_id=${data.run_id}, duration=${data.duration}s`);
      appendLog(`  pcap 将落到 ${data.pcap_url}`);
      startPolling();
    } catch (e) {
      appendLog(`✗ 启动失败: ${e.message}`);
      setRunningUI(false);
    }
  }

  async function stopRun() {
    if (!currentRunId) return;
    stopPolling();
    try {
      const data = await postJSON(`/stop/${currentRunId}`, {});
      appendLog(`■ 已停止 (${data.reason}, 用时 ${data.elapsed_sec}s, pcap ${data.pcap_size_bytes} bytes)`);
      showDownload(data.pcap_url);
    } catch (e) {
      appendLog(`✗ 停止失败: ${e.message}`);
    } finally {
      currentRunId = null;
      setRunningUI(false);
    }
  }

  // ---------- polling ----------
  function startPolling() {
    stopPolling();
    pollTimer = setInterval(async () => {
      try {
        const s = await getJSON("/status");
        const me = s.active_runs.find((r) => r.run_id === currentRunId);
        if (me) {
          $("run-status").textContent =
            `运行中 ${me.elapsed_sec.toFixed(0)}s / ${me.duration}s`;
        } else {
          appendLog("◷ 后端达到时长上限，已自动停止");
          showDownload(`/runs/${currentRunId}/pcap`);
          currentRunId = null;
          setRunningUI(false);
          stopPolling();
        }
      } catch (e) {
        // 静默：偶发网络抖动
      }
    }, 1000);
  }

  function stopPolling() {
    if (pollTimer) {
      clearInterval(pollTimer);
      pollTimer = null;
    }
  }

  // ---------- bind ----------
  function init() {
    const runBtn = $("run");
    const stopBtn = $("stop");
    if (!runBtn || !stopBtn) return;
    runBtn.addEventListener("click", startRun);
    stopBtn.addEventListener("click", stopRun);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
