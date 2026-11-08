// cmatrix-style rain behind the header. Its density follows the audit event rate: a quiet lab drips,
// a busy sample pours. Stops when the tab is hidden; one static frame with reduced motion.
const GLYPHS = "ｱｲｳｴｵｶｷｸｹｺｻｼｽｾｿﾀﾁﾂﾃﾄﾅﾆﾇﾈﾉﾊﾋﾌﾍﾎﾏﾐﾑﾒﾓﾔﾕﾖﾗﾘﾙﾚﾛﾜﾝ0123456789abcdef<>/{}[]=$#;:|";

export class Rain {
  constructor(canvas) {
    this.c = canvas;
    this.x = canvas.getContext("2d");
    this.fs = 14;
    this.level = 0.25;
    this.enabled = true;
    this.reduced = matchMedia("(prefers-reduced-motion: reduce)").matches;
    this.colors();
    this.size();
    addEventListener("resize", () => this.size());
    document.addEventListener("visibilitychange", () => this.loop());
    this.loop();
  }
  colors() {
    const cs = getComputedStyle(document.documentElement);
    this.head = cs.getPropertyValue("--accent").trim() || "#3FD45A";
    this.tail = cs.getPropertyValue("--accent-dim").trim() || "#1E6B2B";
    this.bg = cs.getPropertyValue("--bg").trim() || "#090B09";
  }
  size() {
    const r = this.c.getBoundingClientRect();
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    this.c.width = Math.max(1, Math.floor(r.width * dpr));
    this.c.height = Math.max(1, Math.floor(r.height * dpr));
    this.x.setTransform(dpr, 0, 0, dpr, 0, 0);
    this.w = r.width;
    this.hgt = r.height;
    const cols = Math.ceil(this.w / this.fs);
    this.drops = Array.from({ length: cols }, () => ({ y: -Math.random() * 20, v: 0.35 + Math.random() * 0.5, on: Math.random() < 0.3 }));
    this.x.fillStyle = this.bg;
    this.x.fillRect(0, 0, this.w, this.hgt);
    if (this.reduced) this.frame(true);
  }
  setLevel(rate) {
    // rate: audit records per minute (null = unknown). Maps roughly 0..3000/min onto 0.12..1.
    this.level = rate == null ? 0.25 : Math.max(0.18, Math.min(1, 0.12 + Math.log10(1 + rate) / 3.6));
  }
  setEnabled(on) {
    this.enabled = on;
    if (!on) { this.x.fillStyle = this.bg; this.x.fillRect(0, 0, this.w, this.hgt); }
    this.loop();
  }
  frame(still = false) {
    const x = this.x;
    x.fillStyle = this.bg + (still ? "" : "26");
    if (!still) x.fillRect(0, 0, this.w, this.hgt);
    x.font = `${this.fs}px "Plex Mono", monospace`;
    const steps = still ? 8 : 1;
    for (let s = 0; s < steps; s++) {
      this.drops.forEach((d, i) => {
        if (!d.on) {
          if (Math.random() < 0.01 + this.level * 0.05) { d.on = true; d.y = 0; }
          return;
        }
        const ch = GLYPHS[(Math.random() * GLYPHS.length) | 0];
        x.fillStyle = Math.random() < 0.18 ? this.head : this.tail;
        x.fillText(ch, i * this.fs, d.y * this.fs);
        d.y += d.v * (0.6 + this.level);
        if (d.y * this.fs > this.hgt + this.fs) d.on = false;
      });
    }
  }
  loop() {
    clearInterval(this.timer);
    this.timer = null;
    if (!this.enabled || document.hidden || this.reduced) return;
    this.timer = setInterval(() => this.frame(), 70);
  }
}
