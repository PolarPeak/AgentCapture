(() => {
  const script = document.currentScript;
  if (!script) return;

  const collectUrl = script.dataset.collectUrl || "/recon/fingerprint";

  const payload = {
    url: location.href,
    session_id: document.cookie.match(/ach_sid=([^;]+)/)?.[1] || "",
    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
    language: navigator.language,
    platform: navigator.platform,
    cores: navigator.hardwareConcurrency || 0,
    memory_gb: navigator.deviceMemory || 0,
    screen_width: window.screen?.width || 0,
    screen_height: window.screen?.height || 0,
    pixel_ratio: window.devicePixelRatio || 1,
    touch_points: navigator.maxTouchPoints || 0,
    webdriver: Boolean(navigator.webdriver),
    headless_hint: Boolean(
      navigator.webdriver ||
      /HeadlessChrome/i.test(navigator.userAgent) ||
      !window.chrome
    ),
    plugins: [],
    fonts: [],
    webrtc_ips: [],
    canvas_hash: "",
    webgl_vendor: "",
    webgl_renderer: "",
  };

  function collectPlugins() {
    const plugins = [];
    for (let i = 0; i < navigator.plugins.length; i++) {
      const p = navigator.plugins[i];
      if (p && p.name) plugins.push(p.name);
    }
    return plugins.slice(0, 50);
  }

  function collectFonts() {
    const baseFonts = ["monospace", "sans-serif", "serif"];
    const testFonts = [
      "Arial", "Verdana", "Times New Roman", "Courier New",
      "Comic Sans MS", "Impact", "Georgia", "Trebuchet MS",
      "Helvetica", "Lucida Console", "Tahoma", "Consolas",
      "Segoe UI", "Roboto", "Open Sans", "Ubuntu",
      "PT Sans", "Source Code Pro", "Fira Code", "JetBrains Mono",
      "Cascadia Code", "Menlo", "Monaco",
      "SimSun", "Microsoft YaHei", "PingFang SC", "Hiragino Sans GB",
      "Noto Sans CJK SC", "WenQuanYi Micro Hei",
      "Apple Color Emoji", "Segoe UI Emoji", "Noto Color Emoji",
    ];
    const detected = [];
    const canvas = document.createElement("canvas");
    const ctx = canvas.getContext("2d");
    if (!ctx) return detected;
    const testString = "mmmmmmmmmmlli";
    const testSize = "72px";
    for (const baseFont of baseFonts) {
      canvas.width = 200;
      canvas.height = 80;
      ctx.font = `${testSize} ${baseFont}`;
      const baseWidth = ctx.measureText(testString).width;
      for (const font of testFonts) {
        ctx.font = `${testSize} '${font}', ${baseFont}`;
        const width = ctx.measureText(testString).width;
        if (width !== baseWidth) {
          detected.push(font);
        }
      }
    }
    return [...new Set(detected)];
  }

  function collectCanvasHash() {
    try {
      const canvas = document.createElement("canvas");
      canvas.width = 280;
      canvas.height = 60;
      const ctx = canvas.getContext("2d");
      if (!ctx) return "";
      ctx.textBaseline = "top";
      ctx.font = "14px Arial";
      ctx.fillStyle = "#f60";
      ctx.fillRect(10, 5, 30, 20);
      ctx.fillStyle = "#069";
      ctx.fillText("Browser Fingerprint ◈", 5, 35);
      ctx.fillStyle = "rgba(102, 204, 0, 0.7)";
      ctx.beginPath();
      ctx.arc(80, 20, 10, 0, Math.PI * 2, true);
      ctx.fill();
      return canvas.toDataURL().substring(0, 120);
    } catch (_) {
      return "";
    }
  }

  function collectWebGL() {
    try {
      const canvas = document.createElement("canvas");
      const gl = canvas.getContext("webgl") || canvas.getContext("experimental-webgl");
      if (!gl) return { vendor: "", renderer: "" };
      const debugInfo = gl.getExtension("WEBGL_debug_renderer_info");
      return {
        vendor: debugInfo ? gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL) : "",
        renderer: debugInfo ? gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL) : "",
      };
    } catch (_) {
      return { vendor: "", renderer: "" };
    }
  }

  function collectWebRTCIPs(callback) {
    const ips = [];
    let done = false;
    const pc = new RTCPeerConnection({
      iceServers: [{ urls: "stun:stun.l.google.com:19302" }],
    });
    pc.createDataChannel("");
    pc.onicecandidate = (e) => {
      if (!e.candidate) {
        if (!done) {
          done = true;
          callback(ips);
        }
        pc.close();
        return;
      }
      const addr = e.candidate.address || "";
      const candidate = e.candidate.candidate || "";
      const ipMatch = candidate.match(/([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)/);
      if (addr && ips.indexOf(addr) === -1) {
        ips.push(addr);
      } else if (ipMatch && ips.indexOf(ipMatch[1]) === -1) {
        ips.push(ipMatch[1]);
      }
    };
    pc.createOffer().then((offer) => pc.setLocalDescription(offer)).catch(() => {});
    setTimeout(() => {
      if (!done) {
        done = true;
        callback(ips);
        pc.close();
      }
    }, 3000);
  }

  function send(webrtcIPs) {
    payload.plugins = collectPlugins();
    payload.fonts = collectFonts();
    payload.canvas_hash = collectCanvasHash();
    const gl = collectWebGL();
    payload.webgl_vendor = gl.vendor;
    payload.webgl_renderer = gl.renderer;
    payload.webrtc_ips = webrtcIPs || [];

    const body = JSON.stringify(payload);

    try {
      if (navigator.sendBeacon) {
        const blob = new Blob([body], { type: "application/json" });
        navigator.sendBeacon(collectUrl, blob);
        return;
      }
    } catch (_) {}

    fetch(collectUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body,
      credentials: "same-origin",
      keepalive: true,
    }).catch(() => {});
  }

  if (document.readyState === "complete") {
    collectWebRTCIPs(send);
  } else {
    window.addEventListener("load", () => collectWebRTCIPs(send), { once: true });
  }
})();
