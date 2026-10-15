// Empreinte appareil ("ADN du téléphone") : combinaison de caractéristiques matérielles/logicielles + identifiant persistant.
(function () {
  async function sha(s) {
    if (window.crypto && crypto.subtle) {
      const b = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s));
      return [...new Uint8Array(b)].map(x => x.toString(16).padStart(2, '0')).join('');
    }
    let h = [0x811c9dc5, 0x1b873593, 0xdeadbeef, 0x2545f491, 0x9e3779b1, 0x85ebca6b, 0xc2b2ae35, 0x27d4eb2f];
    for (let i = 0; i < s.length; i++) for (let k = 0; k < 8; k++) { h[k] ^= s.charCodeAt(i) + k; h[k] = Math.imul(h[k], 16777619) >>> 0; }
    return h.map(x => x.toString(16).padStart(8, '0')).join('');
  }
  function canvasSig() {
    try {
      const c = document.createElement('canvas'); c.width = 240; c.height = 60; const x = c.getContext('2d');
      x.textBaseline = 'top'; x.font = "16px 'Arial'"; x.fillStyle = '#f60'; x.fillRect(100, 1, 62, 20);
      x.fillStyle = '#069'; x.fillText('VOGT <canvas> 1.0 \u00e9\u00e8\u00fc', 2, 15);
      x.fillStyle = 'rgba(102,204,0,.7)'; x.fillText('VOGT <canvas> 1.0 \u00e9\u00e8\u00fc', 4, 17);
      x.globalCompositeOperation = 'multiply'; x.fillStyle = 'rgb(255,0,255)'; x.beginPath(); x.arc(50, 30, 20, 0, 6.28, true); x.fill();
      return c.toDataURL();
    } catch (e) { return 'nocanvas'; }
  }
  function gl() {
    try {
      const g = document.createElement('canvas').getContext('webgl') || document.createElement('canvas').getContext('experimental-webgl');
      if (!g) return 'nogl';
      const d = g.getExtension('WEBGL_debug_renderer_info');
      return [d ? g.getParameter(d.UNMASKED_VENDOR_WEBGL) : '', d ? g.getParameter(d.UNMASKED_RENDERER_WEBGL) : '', g.getParameter(g.VERSION), g.getParameter(g.MAX_TEXTURE_SIZE), (g.getSupportedExtensions() || []).length].join('|');
    } catch (e) { return 'nogl'; }
  }
  async function audio() {
    try {
      const O = window.OfflineAudioContext || window.webkitOfflineAudioContext; if (!O) return 'noaudio';
      const ctx = new O(1, 4400, 44100), o = ctx.createOscillator(), cp = ctx.createDynamicsCompressor();
      o.type = 'triangle'; o.frequency.value = 10000; o.connect(cp); cp.connect(ctx.destination); o.start(0);
      const buf = await Promise.race([ctx.startRendering(), new Promise(r => setTimeout(() => r(null), 1500))]);
      if (!buf) return 'audiotimeout';
      const d = buf.getChannelData(0); let s = 0; for (let i = 3000; i < 4400; i++) s += Math.abs(d[i]); return String(s);
    } catch (e) { return 'noaudio'; }
  }
  function fonts() {
    const base = ['monospace', 'sans-serif', 'serif'], list = ['Arial', 'Roboto', 'Helvetica Neue', 'SF Pro', 'Segoe UI', 'Noto Sans', 'Samsung Sans', 'Droid Sans', 'Courier New', 'Georgia', 'Times New Roman', 'Verdana', 'Tahoma'];
    const c = document.createElement('canvas').getContext('2d'), t = 'mmmmmmmmmmlli', w = {};
    base.forEach(b => { c.font = '72px ' + b; w[b] = c.measureText(t).width; });
    return list.filter(f => base.some(b => { c.font = `72px '${f}',${b}`; return c.measureText(t).width !== w[b]; })).join(',');
  }
  function deviceId() {
    const re = /(?:^|; )vdev=([^;]+)/;
    let id = null;
    try { id = localStorage.getItem('vdev'); } catch (e) {}
    if (!id) { const m = document.cookie.match(re); if (m) id = m[1]; }
    if (!id) { const a = new Uint8Array(16); crypto.getRandomValues(a); id = [...a].map(x => x.toString(16).padStart(2, '0')).join(''); }
    try { localStorage.setItem('vdev', id); } catch (e) {}
    document.cookie = 'vdev=' + id + '; max-age=63072000; path=/; SameSite=Strict';
    return id;
  }
  window.VogtDevice = async function () {
    const n = navigator, s = screen;
    const parts = [canvasSig(), gl(), await audio(), fonts(), s.width, s.height, s.colorDepth, window.devicePixelRatio, n.hardwareConcurrency, n.deviceMemory, n.maxTouchPoints, n.platform, n.language, (n.languages || []).join(), Intl.DateTimeFormat().resolvedOptions().timeZone, new Date().getTimezoneOffset()];
    return { fp: await sha(parts.join('||')), deviceId: deviceId() };
  };
})();
