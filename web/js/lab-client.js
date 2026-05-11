// lab-client.js — Alpine 组件: 后端 fetch + run/stop/poll
//
// HTML 用 <article x-data="lab"> 引入。
// 通过 Alpine.store('composer').buildConfig() 取 inbound 配置。

document.addEventListener("alpine:init", () => {

  async function postJSON(url, body) {
    const res = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.detail || res.statusText);
    return data;
  }

  async function getJSON(url) {
    const res = await fetch(url);
    if (!res.ok) throw new Error(res.statusText);
    return res.json();
  }

  Alpine.data("lab", () => ({
    runId: null,
    running: false,
    statusText: "",
    logText: "",
    pcapUrl: null,
    _pollTimer: null,

    _log(msg) {
      this.logText += msg + "\n";
    },

    async start() {
      const composer = Alpine.store("composer");
      if (!composer.isReady) {
        alert("请先完成必选项并解决冲突");
        return;
      }
      const inbound = composer.buildConfig();

      this.logText = "";
      this.pcapUrl = null;
      this.running = true;
      this._log(`▶ 提交 inbound: ${inbound.tag || inbound.type}`);

      try {
        const data = await postJSON("/run", { inbound, duration: 30 });
        this.runId = data.run_id;
        this._log(`✓ run_id=${data.run_id}, duration=${data.duration}s`);
        this._log(`  pcap → ${data.pcap_url}`);
        this._startPolling();
      } catch (e) {
        this._log(`✗ 启动失败: ${e.message}`);
        this.running = false;
      }
    },

    async stop() {
      if (!this.runId) return;
      this._stopPolling();
      try {
        const data = await postJSON(`/stop/${this.runId}`, {});
        this._log(`■ 已停止 (${data.reason}, 用时 ${data.elapsed_sec}s, pcap ${data.pcap_size_bytes} bytes)`);
        this.pcapUrl = data.pcap_url;
      } catch (e) {
        this._log(`✗ 停止失败: ${e.message}`);
      } finally {
        this.runId = null;
        this.running = false;
        this.statusText = "";
      }
    },

    _startPolling() {
      this._stopPolling();
      this._pollTimer = setInterval(async () => {
        try {
          const s = await getJSON("/status");
          const me = s.active_runs.find((r) => r.run_id === this.runId);
          if (me) {
            this.statusText = `运行中 ${me.elapsed_sec.toFixed(0)}s / ${me.duration}s`;
          } else {
            this._log("◷ 后端达到时长上限，已自动停止");
            this.pcapUrl = `/runs/${this.runId}/pcap`;
            this.runId = null;
            this.running = false;
            this.statusText = "";
            this._stopPolling();
          }
        } catch (_) {
          // 静默：偶发网络抖动
        }
      }, 1000);
    },

    _stopPolling() {
      if (this._pollTimer) {
        clearInterval(this._pollTimer);
        this._pollTimer = null;
      }
    },
  }));
});
