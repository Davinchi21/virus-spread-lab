/* Интерфейс веб-симулятора. Модель — в engine.js, данные — в data.js. */
(function () {
  "use strict";
  const VL = window.VirusLab;
  const D = VL.data;
  const { S, E, I, R } = VL;
  const $ = (id) => document.getElementById(id);
  const OS_SHORT = { win7: "7", win10: "10", win11: "11", winsrv: "S", linux: "L" };
  const STATE_LABEL = ["уязвим", "инкубация", "заражён", "вылечен/изолирован"];

  let scenario = null; // текущий сценарий (нормализованный)
  let sim = null;
  let layout = null;
  let running = false;
  let speed = 6;
  let acc = 0;
  let lastTs = 0;
  let selected = -1;
  let hover = -1;
  let showTree = true;
  let showEdges = false;
  let colors = {};
  let logCount = 0;
  const pulses = new Map();

  // ------------------------------------------------------------ описание настроек
  const pct = (v) => Math.round(v * 100) + " %";
  const num = (v) => String(+(+v).toFixed(3));
  const FIELDS = [
    {
      title: "Вирус", open: true, fields: [
        { path: "virus.id", label: "Тип вируса", type: "select", reset: true,
          options: () => Object.entries(D.viruses).map(([k, v]) => [k, v.name]) },
        { type: "virusInfo" },
        { path: "virus.beta", label: "β — заражение за один контакт", type: "range", min: 0, max: 1, step: 0.01, fmt: num },
        { path: "virus.contacts", label: "Попыток заражения за шаг", type: "range", min: 1, max: 10, step: 1, fmt: num },
        { path: "virus.av_block", label: "Антивирус блокирует атаку", type: "range", min: 0, max: 1, step: 0.01, fmt: pct },
        { path: "virus.av_detect", label: "Антивирус находит вирус за шаг", type: "range", min: 0, max: 1, step: 0.01, fmt: pct },
        { path: "virus.firewall_bypass", label: "Проходит межсегментный МСЭ", type: "range", min: 0, max: 1, step: 0.01, fmt: pct },
        { path: "virus.sigma", label: "σ — выход из инкубации (SEIR)", type: "range", min: 0.01, max: 1, step: 0.01, fmt: num },
        { path: "virus.p2p_contacts", label: "Торрент: раздач за шаг", type: "range", min: 0, max: 6, step: 1, fmt: num },
        { path: "virus.p2p_beta", label: "Торрент: шанс запуска файла", type: "range", min: 0, max: 1, step: 0.01, fmt: num },
        { path: "virus.external_rate", label: "Торрент: подкачка из интернета", type: "range", min: 0, max: 0.1, step: 0.005, fmt: num },
      ],
    },
    {
      title: "Модель и запуск", open: true, fields: [
        { path: "model", label: "Эпидемическая модель", type: "select", reset: true,
          options: () => Object.entries(D.models).map(([k, v]) => [k, v]) },
        { path: "seed", label: "Seed (зерно генератора)", type: "number", min: 0, max: 2147483647, reset: true },
        { type: "patientZero" },
        { path: "params.initial_infected", label: "Нулевых пациентов", type: "range", min: 1, max: 10, step: 1, fmt: num, reset: true },
        { path: "params.gamma", label: "γ — администратор сам находит ПК", type: "range", min: 0, max: 0.3, step: 0.005, fmt: num },
        { path: "params.max_steps", label: "Предел шагов", type: "number", min: 10, max: 5000, reset: true },
      ],
    },
    {
      title: "Размер сети", open: true, fields: [
        { path: "network.hosts", label: "Число ПК", type: "number", min: 4, max: 1000, reset: true },
        { path: "network.subnets", label: "Число подсетей (отделов)", type: "number", min: 1, max: 40, reset: true, when: ["corporate", "flat", "star"] },
        { type: "sizePresets" },
      ],
    },
    {
      title: "Сеть и защита", open: true, fields: [
        { path: "network.topology", label: "Топология", type: "select", reset: true,
          options: () => Object.entries(D.topologies).map(([k, v]) => [k, v]) },
        { path: "network.patch_coverage", label: "ПК с установленным патчем", type: "range", min: 0, max: 1, step: 0.05, fmt: pct, reset: true },
        { path: "network.av_coverage", label: "ПК с антивирусом", type: "range", min: 0, max: 1, step: 0.05, fmt: pct, reset: true },
        { path: "params.user_awareness", label: "Осведомлённость персонала", type: "range", min: 0, max: 1, step: 0.05, fmt: pct },
        { path: "params.segmentation", label: "Межсегментный МСЭ включён", type: "check" },
        { path: "params.p2p_blocked", label: "Торренты заблокированы на периметре", type: "check" },
        { path: "network.cross_links", label: "Случайных межотдельных связей", type: "range", min: 0, max: 120, step: 1, fmt: num, reset: true, when: ["corporate"] },
        { path: "network.avg_degree", label: "Средняя степень узла", type: "range", min: 2, max: 20, step: 2, fmt: num, reset: true, when: ["ring", "random", "small_world"] },
        { path: "network.rewire_p", label: "Вероятность перезамыкания", type: "range", min: 0, max: 1, step: 0.01, fmt: num, reset: true, when: ["small_world"] },
        { path: "network.ba_m", label: "Связей у нового узла (m)", type: "range", min: 1, max: 6, step: 1, fmt: num, reset: true, when: ["scale_free"] },
      ],
    },
    {
      title: "Торрент и несвязанные ПК", open: false, fields: [
        { path: "network.p2p_share", label: "Доля ПК с торрент-клиентом", type: "range", min: 0, max: 1, step: 0.05, fmt: pct, reset: true },
        { path: "network.offline_share", label: "Доля ПК вне локальной сети", type: "range", min: 0, max: 0.9, step: 0.05, fmt: pct, reset: true },
        { type: "p2pHint" },
      ],
    },
    {
      title: "Реагирование на инцидент", open: false, fields: [
        { path: "params.detect_threshold", label: "Инцидент замечают при заражении", type: "range", min: 0.01, max: 1, step: 0.01, fmt: pct },
        { path: "params.response_delay", label: "Задержка реагирования, шагов", type: "range", min: 0, max: 60, step: 1, fmt: num },
        { path: "params.response_patch_rate", label: "Скорость установки патчей", type: "range", min: 0, max: 1, step: 0.01, fmt: num },
        { path: "params.response_quarantine", label: "Изоляция заражённых ПК за шаг", type: "range", min: 0, max: 1, step: 0.01, fmt: num },
        { path: "params.response_segmentation", label: "Включить сегментацию при реагировании", type: "check" },
        { path: "params.response_p2p_block", label: "Заблокировать торренты при реагировании", type: "check" },
      ],
    },
  ];
  const SIZE_PRESETS = [["Малый офис", 20, 1], ["Средний", 100, 5], ["Крупный", 300, 10], ["Очень крупный", 600, 20]];

  const getPath = (path) => path.split(".").reduce((o, k) => o[k], scenario);
  function setPath(path, value) {
    const parts = path.split(".");
    let o = scenario;
    for (let i = 0; i < parts.length - 1; i++) o = o[parts[i]];
    o[parts[parts.length - 1]] = value;
  }

  // ------------------------------------------------------------ построение панели настроек
  const inputs = [];
  function buildControls() {
    const root = $("controls");
    root.innerHTML = "";
    for (const sec of FIELDS) {
      const det = document.createElement("details");
      det.open = sec.open;
      det.innerHTML = `<summary>${sec.title}</summary>`;
      const box = document.createElement("div");
      box.className = "fields";
      for (const f of sec.fields) {
        const wrap = document.createElement("div");
        wrap.className = "field";
        if (f.type === "virusInfo") {
          wrap.innerHTML = `<p class="hint" id="virusInfo"></p>`;
        } else if (f.type === "sizePresets") {
          wrap.className = "field presets";
          wrap.innerHTML = `<div class="preset-row">` +
            SIZE_PRESETS.map(([name, h, s], k) => `<button class="btn small" data-preset="${k}">${name}<br>${h} ПК</button>`).join("") +
            `</div>`;
        } else if (f.type === "p2pHint") {
          wrap.innerHTML = `<p class="hint">Торрент-вирусы распространяются <em>между</em> торрент-пользователями и могут заразить даже ПК <em>вне локальной сети</em>. ` +
            `ПК «вне ЛВС» не имеют сетевых связей — обычный сетевой червь до них не доберётся.</p>`;
        } else if (f.type === "patientZero") {
          wrap.innerHTML = `<div class="pz"><span>Нулевой пациент: <b id="pzName">случайный</b></span>` +
            `<button class="btn small" id="pzClear" title="Выбирать случайно">случайно</button></div>`;
        } else if (f.type === "check") {
          wrap.classList.add("check");
          wrap.innerHTML = `<label><input type="checkbox">${f.label}</label>`;
        } else {
          wrap.innerHTML = `<label><span>${f.label}</span><b></b></label>`;
          let el;
          if (f.type === "select") {
            el = document.createElement("select");
            for (const [v, text] of f.options()) {
              const o = document.createElement("option");
              o.value = v;
              o.textContent = text;
              el.appendChild(o);
            }
          } else {
            el = document.createElement("input");
            el.type = f.type;
            el.min = f.min;
            el.max = f.max;
            if (f.step) el.step = f.step;
          }
          wrap.appendChild(el);
        }
        box.appendChild(wrap);
        if (f.path) {
          const el = wrap.querySelector("input, select");
          const out = wrap.querySelector("label b");
          inputs.push({ f, el, out, wrap });
          el.addEventListener("input", () => onFieldInput(f, el, out));
          el.addEventListener("change", () => onFieldChange(f, el));
        }
      }
      det.appendChild(box);
      root.appendChild(det);
    }
    $("pzClear").addEventListener("click", () => {
      scenario.params.patient_zero = -1;
      resetSim();
    });
    root.querySelectorAll("[data-preset]").forEach((b) => b.addEventListener("click", () => {
      const [, h, s] = SIZE_PRESETS[+b.getAttribute("data-preset")];
      scenario.network.hosts = h;
      scenario.network.subnets = s;
      scenario.params.patient_zero = -1;
      $("scenario").value = "custom";
      resetSim();
    }));
  }

  function readField(f, el) {
    if (f.type === "check") return el.checked;
    if (f.type === "select") return el.value;
    const v = parseFloat(el.value);
    return Number.isFinite(v) ? v : getPath(f.path);
  }

  function onFieldInput(f, el, out) {
    if (f.type !== "range") return;
    const v = readField(f, el);
    if (out) out.textContent = f.fmt ? f.fmt(v) : v;
    if (!f.reset) applyLive(f, v);
  }

  function onFieldChange(f, el) {
    let v = readField(f, el);
    if (f.type === "number") {
      v = Math.round(Math.min(f.max, Math.max(f.min, v)));
      el.value = v;
    }
    if (f.path === "virus.id") {
      scenario.virus = VL.getVirus(v);
    } else if (f.reset) {
      setPath(f.path, v);
      // Держим число ПК и подсетей согласованными (в подсеть /24 влезает до 240 ПК).
      if (f.path === "network.hosts") {
        let sub = Math.min(scenario.network.subnets, Math.floor(v / 2));
        sub = Math.max(sub, Math.ceil(v / 240), 1);
        scenario.network.subnets = sub;
        scenario.params.patient_zero = -1;
      } else if (f.path === "network.subnets") {
        scenario.network.hosts = Math.max(scenario.network.hosts, v * 2);
      }
    } else {
      applyLive(f, v);
      return;
    }
    $("scenario").value = "custom";
    resetSim();
  }

  // Параметры без пометки reset применяются к идущему моделированию со следующего шага.
  function applyLive(f, v) {
    setPath(f.path, v);
    const [sec, key] = f.path.split(".");
    if (sec === "virus") sim.virus[key] = v;
    if (sec === "params") sim.params[key] = v;
    if (f.path === "params.segmentation") {
      sim.segActive = v || (sim.responseActive && sim.params.response_segmentation);
      addLogLine({ t: sim.t, kind: "info", text: v ? "Межсегментный МСЭ включён вручную" : "Межсегментный МСЭ выключен вручную" });
    }
    $("scenario").value = "custom";
    renderHost();
  }

  function syncControls() {
    const topo = scenario.network.topology;
    for (const { f, el, out, wrap } of inputs) {
      const v = f.path === "virus.id" ? scenario.virus.id : getPath(f.path);
      if (f.type === "check") el.checked = !!v;
      else el.value = v;
      if (out) out.textContent = f.type === "range" && f.fmt ? f.fmt(v) : "";
      wrap.style.display = f.when && !f.when.includes(topo) ? "none" : "";
    }
    const v = scenario.virus;
    const os = v.targets.map((x) => OS_SHORT[x] === "S" ? "Win Server" : x === "linux" ? "Linux" : "Win " + OS_SHORT[x]).join(", ");
    $("virusInfo").innerHTML = `${v.vector || ""}.<br>Поражает: <em>${os}</em>. ` +
      `${v.needs_vuln ? "Нужна уязвимость (патч защищает)." : "Патч не защищает."} ` +
      `${v.user_action ? "Нужно действие пользователя." : ""}` +
      (v.analogs ? `<br>Исторические аналоги: ${v.analogs}.` : "");
  }

  // ------------------------------------------------------------ сценарии
  function buildScenarioSelect() {
    const sel = $("scenario");
    D.scenarios.forEach((sc, i) => {
      const o = document.createElement("option");
      o.value = String(i);
      o.textContent = sc.name;
      sel.appendChild(o);
    });
    const o = document.createElement("option");
    o.value = "custom";
    o.textContent = "Свои настройки";
    sel.appendChild(o);
    sel.addEventListener("change", () => {
      if (sel.value === "custom") return;
      loadScenario(+sel.value);
    });
  }

  function loadScenario(i) {
    scenario = VL.normalize(D.scenarios[i]);
    $("scenario").value = String(i);
    selected = -1;
    resetSim();
    $("status").title = scenario.description || "";
  }

  // ------------------------------------------------------------ моделирование
  function resetSim() {
    running = false;
    acc = 0;
    pulses.clear();
    try {
      sim = VL.makeSimulation(scenario);
    } catch (err) {
      alert("Ошибка: " + err.message);
      return;
    }
    if (typeof scenario.params.patient_zero === "string") scenario.params.patient_zero = sim.params.patient_zero;
    layout = computeLayout(sim.net);
    if (selected >= sim.n) selected = -1;
    syncControls();
    $("log").innerHTML = "";
    logCount = 0;
    for (const ev of sim.events) addLogLine(ev);
    const pz = scenario.params.patient_zero;
    $("pzName").textContent = Number.isInteger(pz) && pz >= 0 && pz < sim.n ? sim.hosts[pz].hostname : "случайный";
    resizeCanvases();
    updateAll();
  }

  function doStep() {
    if (!sim || sim.finished) return;
    const from = sim.events.length;
    sim.step();
    const now = performance.now();
    for (let k = from; k < sim.events.length; k++) {
      const ev = sim.events[k];
      if (ev.kind === "infect" && ev.host !== undefined) pulses.set(ev.host, now);
      addLogLine(ev);
    }
    if (sim.finished) running = false;
  }

  // ------------------------------------------------------------ раскладка узлов
  function forceLayout(net) {
    const n = net.size;
    const p = Array.from({ length: n }, (_, i) => ({
      x: 0.5 + 0.35 * Math.cos((2 * Math.PI * i) / n), y: 0.5 + 0.35 * Math.sin((2 * Math.PI * i) / n),
    }));
    const k = Math.sqrt(1 / n);
    let temp = 0.08;
    const iters = n > 400 ? 120 : n > 200 ? 180 : 260; // крупные сети раскладываем быстрее
    for (let it = 0; it < iters; it++) {
      const d = p.map(() => ({ x: 0, y: 0 }));
      for (let i = 0; i < n; i++) {
        for (let j = i + 1; j < n; j++) {
          const dx = p[i].x - p[j].x, dy = p[i].y - p[j].y;
          const dist = Math.max(1e-4, Math.hypot(dx, dy));
          const f = (k * k) / dist;
          d[i].x += (dx / dist) * f; d[i].y += (dy / dist) * f;
          d[j].x -= (dx / dist) * f; d[j].y -= (dy / dist) * f;
        }
      }
      for (let i = 0; i < n; i++) {
        for (const j of net.neighbors[i]) {
          if (j <= i) continue;
          const dx = p[i].x - p[j].x, dy = p[i].y - p[j].y;
          const dist = Math.max(1e-4, Math.hypot(dx, dy));
          const f = (dist * dist) / k;
          d[i].x -= (dx / dist) * f; d[i].y -= (dy / dist) * f;
          d[j].x += (dx / dist) * f; d[j].y += (dy / dist) * f;
        }
        d[i].x += (0.5 - p[i].x) * 0.6; d[i].y += (0.5 - p[i].y) * 0.6;
      }
      for (let i = 0; i < n; i++) {
        const len = Math.max(1e-6, Math.hypot(d[i].x, d[i].y));
        const step = Math.min(len, temp);
        p[i].x += (d[i].x / len) * step;
        p[i].y += (d[i].y / len) * step;
      }
      temp *= 0.985;
    }
    let minX = Infinity, maxX = -Infinity, minY = Infinity, maxY = -Infinity;
    for (const q of p) { minX = Math.min(minX, q.x); maxX = Math.max(maxX, q.x); minY = Math.min(minY, q.y); maxY = Math.max(maxY, q.y); }
    return p.map((q) => ({ x: (q.x - minX) / (maxX - minX || 1), y: (q.y - minY) / (maxY - minY || 1) }));
  }

  function computeLayout(net) {
    const topo = net.topology;
    const n = net.size;
    const out = { topo, boxes: [], unit: null, kind: "" };
    if (topo === "corporate" || topo === "flat") {
      out.kind = "boxes";
      out.groups = [];
      for (let s = 0; s < net.subnets; s++) out.groups.push(net.hosts.filter((h) => h.subnet === s).map((h) => h.id));
    } else if (topo === "grid") {
      out.kind = "unit";
      const side = Math.ceil(Math.sqrt(n));
      out.unit = net.hosts.map((h) => ({ x: (h.id % side) / (side - 1), y: Math.floor(h.id / side) / (side - 1) }));
    } else if (topo === "star") {
      out.kind = "unit";
      const hub = net.hosts.find((h) => h.subnet === net.subnets - 1).id;
      const others = net.hosts.filter((h) => h.id !== hub);
      out.unit = new Array(n);
      out.unit[hub] = { x: 0.5, y: 0.5 };
      others.forEach((h, k) => {
        const a = (2 * Math.PI * k) / others.length - Math.PI / 2;
        out.unit[h.id] = { x: 0.5 + 0.5 * Math.cos(a), y: 0.5 + 0.5 * Math.sin(a) };
      });
    } else if (topo === "random" || topo === "scale_free") {
      out.kind = "unit";
      out.unit = forceLayout(net);
    } else {
      out.kind = "unit";
      out.unit = net.hosts.map((h) => {
        const a = (2 * Math.PI * h.id) / n - Math.PI / 2;
        return { x: 0.5 + 0.5 * Math.cos(a), y: 0.5 + 0.5 * Math.sin(a) };
      });
    }
    return out;
  }

  // Перевод раскладки в пиксели под текущую ширину холста.
  function place(W) {
    const L = layout;
    const n = sim.n;
    L.pos = new Array(n);
    L.boxes = [];
    if (L.kind === "boxes") {
      const k = L.groups.length;
      const gap = 10;
      const maxPerRow = Math.max(1, Math.min(k, Math.floor((W + gap) / 150)));
      const perRow = Math.ceil(k / Math.ceil(k / maxPerRow)); // ровные ряды: 5 подсетей → 3 + 2
      const boxW = (W - gap * (perRow - 1)) / perRow;
      const maxSize = Math.max(...L.groups.map((g) => g.length));
      const cols = Math.max(3, Math.min(6, Math.floor(boxW / 34)));
      const cell = boxW / cols;
      const rows = Math.ceil(maxSize / cols);
      const head = 34;
      const boxH = head + rows * cell + 6;
      L.groups.forEach((g, s) => {
        const bx = (s % perRow) * (boxW + gap);
        const by = Math.floor(s / perRow) * (boxH + gap);
        L.boxes.push({ x: bx, y: by, w: boxW, h: boxH, name: sim.net.subnetNames[s], cidr: `10.0.${s + 1}.0/24` });
        g.forEach((id, m) => {
          L.pos[id] = { x: bx + cell * ((m % cols) + 0.5), y: by + head + cell * (Math.floor(m / cols) + 0.5) };
        });
      });
      L.r = Math.max(5, Math.min(13, cell * 0.34));
      L.H = Math.ceil(k / perRow) * (boxH + gap) - gap;
    } else {
      const size = Math.min(W, 620);
      const pad = 18;
      const ox = (W - size) / 2;
      L.r = Math.max(4.5, Math.min(11, size / (Math.sqrt(n) * 4.2)));
      sim.hosts.forEach((h, i) => {
        L.pos[i] = { x: ox + pad + L.unit[i].x * (size - 2 * pad), y: pad + L.unit[i].y * (size - 2 * pad) };
      });
      L.H = size;
    }
  }

  // ------------------------------------------------------------ рисование
  function readColors() {
    const cs = getComputedStyle(document.documentElement);
    for (const k of ["s", "e", "i", "r", "av", "prot", "ink", "muted", "line", "box", "edge", "panel", "accent"]) {
      colors[k] = cs.getPropertyValue("--" + k).trim();
    }
  }

  function setupCanvas(cv, cssW, cssH) {
    const dpr = window.devicePixelRatio || 1;
    cv.style.height = cssH + "px";
    cv.width = Math.round(cssW * dpr);
    cv.height = Math.round(cssH * dpr);
    const ctx = cv.getContext("2d");
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    return ctx;
  }

  let netCtx = null, chartCtx = null, netW = 0, chartW = 0;
  function resizeCanvases() {
    if (!sim) return;
    netW = $("netWrap").clientWidth;
    place(netW);
    netCtx = setupCanvas($("net"), netW, layout.H);
    chartW = $("chart").parentElement.clientWidth - 24;
    chartW = $("chart").clientWidth || chartW;
    chartCtx = setupCanvas($("chart"), chartW, 210);
    drawChart();
  }

  function stateColor(i) {
    const st = sim.state[i];
    if (st === S) return sim.isProtected(i) ? null : colors.s;
    return [colors.s, colors.e, colors.i, colors.r][st];
  }

  function drawNet(now) {
    const ctx = netCtx;
    const L = layout;
    if (!ctx) return;
    ctx.clearRect(0, 0, netW, L.H);
    ctx.textBaseline = "middle";

    for (const b of L.boxes) {
      ctx.fillStyle = colors.box;
      ctx.strokeStyle = colors.line;
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.roundRect(b.x + 0.5, b.y + 0.5, b.w - 1, b.h - 1, 8);
      ctx.fill();
      ctx.stroke();
      ctx.fillStyle = colors.ink;
      ctx.font = "600 12.5px system-ui, sans-serif";
      ctx.textAlign = "left";
      ctx.fillText(b.name, b.x + 10, b.y + 13, b.w - 20);
      ctx.fillStyle = colors.muted;
      ctx.font = "11px ui-monospace, Consolas, monospace";
      ctx.fillText(b.cidr, b.x + 10, b.y + 26, b.w - 20);
    }

    if (showEdges) {
      ctx.strokeStyle = colors.edge;
      ctx.globalAlpha = L.kind === "boxes" ? 0.08 : 0.28;
      ctx.lineWidth = 1;
      ctx.beginPath();
      sim.net.neighbors.forEach((nb, i) => {
        for (const j of nb) {
          if (j <= i) continue;
          ctx.moveTo(L.pos[i].x, L.pos[i].y);
          ctx.lineTo(L.pos[j].x, L.pos[j].y);
        }
      });
      ctx.stroke();
      ctx.globalAlpha = 1;
    }

    if (showTree) {
      ctx.lineWidth = 1.6;
      for (let j = 0; j < sim.n; j++) {
        const src = sim.infectedBy[j];
        if (src < 0 || !sim.wasInfected[j]) continue;
        const active = sim.state[j] === E || sim.state[j] === I;
        // Красный — распространение по ЛВС, бирюзовый пунктир — через торрент.
        const p2p = sim.infectedVia[j] === "p2p";
        const col = p2p ? colors.av : colors.i;
        ctx.strokeStyle = col;
        ctx.globalAlpha = active ? 0.8 : 0.22;
        ctx.setLineDash(p2p ? [4, 3] : []);
        const a = L.pos[src], b = L.pos[j];
        ctx.beginPath();
        ctx.moveTo(a.x, a.y);
        ctx.lineTo(b.x, b.y);
        ctx.stroke();
        ctx.setLineDash([]);
        const ang = Math.atan2(b.y - a.y, b.x - a.x);
        const tx = b.x - Math.cos(ang) * (L.r + 2), ty = b.y - Math.sin(ang) * (L.r + 2);
        ctx.fillStyle = col;
        ctx.beginPath();
        ctx.moveTo(tx, ty);
        ctx.lineTo(tx - Math.cos(ang - 0.45) * 6, ty - Math.sin(ang - 0.45) * 6);
        ctx.lineTo(tx - Math.cos(ang + 0.45) * 6, ty - Math.sin(ang + 0.45) * 6);
        ctx.fill();
      }
      ctx.globalAlpha = 1;
    }

    const r = L.r;
    for (let i = 0; i < sim.n; i++) {
      const h = sim.hosts[i];
      const { x, y } = L.pos[i];
      const fill = stateColor(i);

      const t0 = pulses.get(i);
      if (t0 !== undefined) {
        const age = (now - t0) / 900;
        if (age >= 1) pulses.delete(i);
        else {
          ctx.strokeStyle = colors.i;
          ctx.globalAlpha = 1 - age;
          ctx.lineWidth = 2;
          ctx.beginPath();
          ctx.arc(x, y, r + 2 + age * 14, 0, Math.PI * 2);
          ctx.stroke();
          ctx.globalAlpha = 1;
        }
      }

      ctx.beginPath();
      if (h.role === "server") ctx.roundRect(x - r, y - r, r * 2, r * 2, 3);
      else ctx.arc(x, y, r, 0, Math.PI * 2);
      if (fill) {
        ctx.fillStyle = fill;
        ctx.fill();
      } else {
        ctx.fillStyle = colors.panel;
        ctx.fill();
        ctx.strokeStyle = colors.prot;
        ctx.lineWidth = 2;
        ctx.stroke();
      }
      if (r >= 7) {
        ctx.fillStyle = fill ? "#fff" : colors.muted;
        ctx.font = `600 ${Math.round(r * 0.85)}px system-ui, sans-serif`;
        ctx.textAlign = "center";
        ctx.fillText(OS_SHORT[h.os], x, y + 0.5);
      }
      if (h.offline) {
        // ПК вне ЛВС — серое пунктирное кольцо (связей нет, только торрент)
        ctx.beginPath();
        ctx.arc(x, y, r + 2.5, 0, Math.PI * 2);
        ctx.strokeStyle = colors.muted;
        ctx.setLineDash([2, 2]);
        ctx.lineWidth = 1.3;
        ctx.stroke();
        ctx.setLineDash([]);
      }
      if (h.p2p) {
        // торрент-пользователь — маленький фиолетовый ромбик снизу
        const my = y + r * 0.8;
        ctx.beginPath();
        ctx.moveTo(x - r * 0.72, my);
        ctx.lineTo(x, my - r * 0.34);
        ctx.lineTo(x + r * 0.72, my);
        ctx.lineTo(x, my + r * 0.34);
        ctx.closePath();
        ctx.fillStyle = "#9a6cff";
        ctx.fill();
      }
      if (h.av) {
        ctx.beginPath();
        ctx.arc(x + r * 0.78, y - r * 0.78, Math.max(2.5, r * 0.3), 0, Math.PI * 2);
        ctx.fillStyle = colors.av;
        ctx.fill();
        ctx.strokeStyle = colors.panel;
        ctx.lineWidth = 1.5;
        ctx.stroke();
      }
      if (i === selected || i === hover) {
        ctx.beginPath();
        ctx.arc(x, y, r + 4, 0, Math.PI * 2);
        ctx.strokeStyle = i === selected ? colors.ink : colors.muted;
        ctx.lineWidth = i === selected ? 2 : 1.5;
        ctx.stroke();
      }
    }
  }

  function drawChart() {
    const ctx = chartCtx;
    if (!ctx || !sim) return;
    const W = chartW, H = 210;
    const padL = 34, padR = 10, padT = 10, padB = 24;
    const pw = W - padL - padR, ph = H - padT - padB;
    const hist = sim.history;
    const tMax = Math.max(30, sim.t);
    const X = (t) => padL + (t / tMax) * pw;
    const Y = (v) => padT + ph - (v / sim.n) * ph;
    ctx.clearRect(0, 0, W, H);
    ctx.font = "11px system-ui, sans-serif";
    ctx.textBaseline = "middle";
    ctx.textAlign = "right";
    ctx.lineWidth = 1;
    for (let q = 0; q <= 4; q++) {
      const v = (sim.n * q) / 4;
      ctx.strokeStyle = colors.line;
      ctx.beginPath();
      ctx.moveTo(padL, Math.round(Y(v)) + 0.5);
      ctx.lineTo(W - padR, Math.round(Y(v)) + 0.5);
      ctx.stroke();
      ctx.fillStyle = colors.muted;
      ctx.fillText(String(Math.round(v)), padL - 6, Y(v));
    }
    ctx.textAlign = "center";
    ctx.textBaseline = "top";
    const stepX = Math.max(5, Math.ceil(tMax / 8 / 5) * 5);
    for (let t = 0; t <= tMax; t += stepX) ctx.fillText(String(t), X(t), H - padB + 6);

    for (const [label, at] of [["обнаружение", sim.detectedAt], ["реагирование", sim.responseAt]]) {
      if (at === null || at > tMax) continue;
      ctx.strokeStyle = colors.accent;
      ctx.setLineDash([4, 4]);
      ctx.beginPath();
      ctx.moveTo(Math.round(X(at)) + 0.5, padT);
      ctx.lineTo(Math.round(X(at)) + 0.5, padT + ph);
      ctx.stroke();
      ctx.setLineDash([]);
      ctx.fillStyle = colors.accent;
      ctx.textAlign = "left";
      ctx.fillText(label, X(at) + 4, padT + (label === "реагирование" ? 14 : 0));
    }

    const series = [["S", colors.s], ["E", colors.e], ["I", colors.i], ["R", colors.r]];
    for (const [key, color] of series) {
      if (!hist.some((h) => h[key] > 0)) continue;
      ctx.strokeStyle = color;
      ctx.lineWidth = 2;
      ctx.lineJoin = "round";
      ctx.beginPath();
      hist.forEach((h, k) => (k ? ctx.lineTo(X(h.t), Y(h[key])) : ctx.moveTo(X(h.t), Y(h[key]))));
      ctx.stroke();
      const last = hist[hist.length - 1];
      ctx.fillStyle = color;
      ctx.font = "600 11px system-ui, sans-serif";
      ctx.textAlign = "left";
      ctx.textBaseline = "middle";
      if (X(last.t) < W - padR - 14) ctx.fillText(key, X(last.t) + 5, Y(last[key]));
    }
    // накопленное число заражений — пунктир
    ctx.strokeStyle = colors.muted;
    ctx.setLineDash([3, 3]);
    ctx.lineWidth = 1.2;
    ctx.beginPath();
    hist.forEach((h, k) => (k ? ctx.lineTo(X(h.t), Y(h.ever)) : ctx.moveTo(X(h.t), Y(h.ever))));
    ctx.stroke();
    ctx.setLineDash([]);
  }

  // ------------------------------------------------------------ панели
  function tile(k, v, extra, hot) {
    return `<div class="tile${hot ? " hot" : ""}"><div class="k">${k}</div><div class="v">${v}${extra ? `<small>${extra}</small>` : ""}</div></div>`;
  }

  function updateTiles() {
    const s = sim.summary();
    const last = sim.history[sim.history.length - 1];
    const vulnerable = sim.hosts.filter((h, i) => sim.state[i] === S && !sim.isProtected(i)).length;
    const ch = s.byChannel;
    // Последняя плитка адаптивна: при торрент-угрозе показываем офлайн-ПК, иначе патчи.
    const torrentActive = ch.p2p > 0 || ch.ext > 0 || sim.virus.p2p_contacts > 0 || sim.virus.external_rate > 0;
    const lastTile = (torrentActive && s.offlineHosts)
      ? tile("Заражено вне ЛВС", s.offlineInfected, "из " + s.offlineHosts + " автономных", s.offlineInfected > 0)
      : tile("ПК с патчем", last.patched, "из " + sim.n);
    $("tiles").innerHTML =
      tile("Шаг", sim.t) +
      tile("Заражено сейчас", last.E + last.I, "ПК", last.E + last.I > 0) +
      tile("Пик", s.peak, "на шаге " + s.peakT) +
      tile("Заражались всего", s.ever, Math.round(s.everFraction * 100) + " %") +
      tile("R₀ нулевых пациентов", s.r0.toFixed(2)) +
      tile("Осталось уязвимых", vulnerable, "ПК") +
      tile(torrentActive ? "По ЛВС / торрент" : "Атак отбито защитой",
           torrentActive ? `${ch.lan}/${ch.p2p}` : s.blocked, torrentActive ? "заражений" : "") +
      lastTile;
    const st = $("status");
    if (sim.finished) {
      st.textContent = "Моделирование завершено: " + sim.endReason.toLowerCase();
      st.className = "status done";
    } else {
      const seg = sim.segActive ? "МСЭ между сегментами включён" : "сегментации нет";
      const resp = sim.responseActive ? "идёт реагирование" : sim.detectedAt !== null ? `реагирование с шага ${sim.responseAt}` : "инцидент не обнаружен";
      st.textContent = `${sim.virus.name} · ${sim.model} · ${sim.net.topology}, ${sim.net.edgeCount} связей · ${seg} · ${resp}`;
      st.className = "status";
    }
    $("play").textContent = running ? "❚❚ Пауза" : sim.finished ? "▶ Заново" : "▶ Пуск";
    $("step").disabled = sim.finished;
  }

  function renderHost() {
    const card = $("hostCard");
    if (selected < 0 || !sim) {
      card.innerHTML = `<h3>Компьютер</h3><p class="host-empty">Щёлкните по ПК на схеме, чтобы увидеть его параметры, ` +
        `заразить, установить патч или изолировать.</p>`;
      return;
    }
    const i = selected;
    const h = sim.hosts[i];
    const st = sim.state[i];
    const prot = st === S && sim.isProtected(i);
    const color = ["var(--s)", "var(--e)", "var(--i)", "var(--r)"][st];
    const src = sim.infectedBy[i];
    const p = sim.infectionProb(i);
    const lanP = sim.lanProb(i), p2pP = sim.p2pProb(i) * (sim.p2pOpen(i) ? 1 : 0);
    const reason = !sim.targeted[i] ? "ОС не поражается этим вирусом"
      : (lanP <= 0 && p2pP <= 0) ? (sim.virus.needs_vuln && sim.patched[i] ? "установлен патч" : "нет вектора заражения") : "";
    const risk = reason ? "0 — " + reason
      : [lanP > 0 ? `ЛВС ${(lanP * 100).toFixed(0)} %` : "", p2pP > 0 ? `торрент ${(p2pP * 100).toFixed(0)} %` : ""].filter(Boolean).join(", ");
    const via = sim.infectedVia[i];
    const viaText = { seed: "нулевой пациент", lan: "по ЛВС", p2p: "через торрент", ext: "скачан из торрента" };
    card.innerHTML = `<h3>Компьютер</h3>
      <div class="host-title"><b>${h.hostname}</b><span class="badge" style="background:${prot ? "var(--muted)" : color}">${prot ? "защищён" : STATE_LABEL[st]}</span></div>
      <dl class="kv">
        <dt>IP-адрес</dt><dd class="mono">${h.offline ? "— (вне ЛВС)" : h.ip}</dd>
        <dt>Подсеть</dt><dd>${h.subnetName}</dd>
        <dt>Роль</dt><dd>${h.roleName}</dd>
        <dt>ОС</dt><dd>${D.osNames[h.os]}</dd>
        <dt>Патч</dt><dd>${sim.patched[i] ? "установлен" : h.legacy ? "невозможен (ОС устарела)" : "нет"}</dd>
        <dt>Антивирус</dt><dd>${h.av ? "есть" : "нет"}</dd>
        <dt>Торрент-клиент</dt><dd>${h.p2p ? "есть" : "нет"}</dd>
        <dt>Подключён к ЛВС</dt><dd>${h.offline ? "нет (автономный)" : "да, связей: " + sim.net.neighbors[i].length}</dd>
        <dt>Риск за попытку</dt><dd>${risk}</dd>
        ${sim.wasInfected[i] ? `<dt>Заражён</dt><dd>на шаге ${sim.infectedAt[i]} (${viaText[via] || via})${src >= 0 ? ` от <span class="mono">${sim.hosts[src].hostname}</span>` : ""}</dd>
        <dt>Заразил сам</dt><dd>${sim.offspring[i]} ПК</dd>` : ""}
      </dl>
      <div class="host-actions">
        <button class="btn small" data-act="infect" ${st === E || st === I || !sim.targeted[i] ? "disabled" : ""}>Заразить</button>
        <button class="btn small" data-act="patch" ${sim.patched[i] || h.legacy ? "disabled" : ""}>Установить патч</button>
        <button class="btn small" data-act="isolate" ${st === E || st === I ? "" : "disabled"}>Изолировать</button>
        <button class="btn small" data-act="zero" ${!sim.targeted[i] ? "disabled" : ""} title="Начать заново с этим нулевым пациентом">Нулевой пациент</button>
      </div>`;
  }

  function addLogLine(ev) {
    const li = document.createElement("li");
    li.className = ev.kind;
    li.innerHTML = `<span class="t">${String(ev.t).padStart(3, " ")}</span>`;
    li.appendChild(document.createTextNode(ev.text));
    const log = $("log");
    log.insertBefore(li, log.firstChild);
    logCount++;
    while (logCount > 400) {
      log.removeChild(log.lastChild);
      logCount--;
    }
  }

  function updateAll() {
    updateTiles();
    renderHost();
    drawChart();
  }

  // ------------------------------------------------------------ события
  function hitTest(ev) {
    const rect = $("net").getBoundingClientRect();
    const x = ev.clientX - rect.left, y = ev.clientY - rect.top;
    let best = -1, bestD = Infinity;
    for (let i = 0; i < sim.n; i++) {
      const d = Math.hypot(layout.pos[i].x - x, layout.pos[i].y - y);
      if (d < bestD) { bestD = d; best = i; }
    }
    return bestD <= layout.r + 5 ? best : -1;
  }

  function download(name, text, type) {
    const blob = new Blob([text], { type });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = name;
    document.body.appendChild(a);
    a.click();
    setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 500);
  }

  function bindEvents() {
    $("play").addEventListener("click", () => {
      if (sim.finished) { resetSim(); running = true; }
      else running = !running;
      updateTiles();
    });
    $("step").addEventListener("click", () => {
      running = false;
      doStep();
      updateAll();
    });
    $("reset").addEventListener("click", resetSim);
    $("speed").addEventListener("input", (e) => {
      speed = +e.target.value;
      $("speedVal").textContent = speed;
    });
    $("showTree").addEventListener("change", (e) => (showTree = e.target.checked));
    $("showEdges").addEventListener("change", (e) => (showEdges = e.target.checked));
    $("clearLog").addEventListener("click", () => { $("log").innerHTML = ""; logCount = 0; });
    $("theme").addEventListener("click", () => {
      const root = document.documentElement;
      const dark = getComputedStyle(root).getPropertyValue("color-scheme").trim() === "dark";
      root.setAttribute("data-theme", dark ? "light" : "dark");
      try { localStorage.setItem("virus-lab-theme", root.getAttribute("data-theme")); } catch (e) { /* нет хранилища */ }
      readColors();
      drawChart();
    });

    const cv = $("net");
    const tip = $("tip");
    cv.addEventListener("mousemove", (ev) => {
      const i = hitTest(ev);
      hover = i;
      if (i < 0) { tip.style.display = "none"; return; }
      const h = sim.hosts[i];
      const st = sim.state[i] === S && sim.isProtected(i) ? "защищён" : STATE_LABEL[sim.state[i]];
      tip.innerHTML = `${h.hostname} <span>${h.ip}</span> · ${st}`;
      tip.style.display = "block";
      const p = layout.pos[i];
      const left = Math.min(Math.max(0, p.x - tip.offsetWidth / 2), netW - tip.offsetWidth);
      tip.style.left = left + "px";
      tip.style.top = Math.max(0, p.y - layout.r - 34) + "px";
    });
    cv.addEventListener("mouseleave", () => { hover = -1; tip.style.display = "none"; });
    cv.addEventListener("click", (ev) => {
      selected = hitTest(ev);
      renderHost();
    });

    $("hostCard").addEventListener("click", (ev) => {
      const act = ev.target.getAttribute && ev.target.getAttribute("data-act");
      if (!act || selected < 0) return;
      if (act === "infect") {
        if (sim.manualInfect(selected)) {
          pulses.set(selected, performance.now());
          addLogLine(sim.events[sim.events.length - 1]);
        }
      } else if (act === "patch") {
        if (sim.manualPatch(selected)) addLogLine(sim.events[sim.events.length - 1]);
      } else if (act === "isolate") {
        if (sim.manualIsolate(selected)) addLogLine(sim.events[sim.events.length - 1]);
      } else if (act === "zero") {
        scenario.params.patient_zero = selected;
        scenario.params.initial_infected = Math.max(1, scenario.params.initial_infected);
        $("scenario").value = "custom";
        resetSim();
        return;
      }
      updateAll();
    });

    $("csv").addEventListener("click", () => {
      const keys = ["t", "S", "E", "I", "R", "ever", "new", "attempts", "blocked", "patched"];
      const lines = [keys.join(";")].concat(sim.history.map((h) => keys.map((k) => h[k]).join(";")));
      download("dinamika.csv", "﻿" + lines.join("\r\n"), "text/csv;charset=utf-8");
    });
    $("json").addEventListener("click", () => {
      const sc = JSON.parse(JSON.stringify(scenario));
      sc.name = sc.name || "Сценарий из веб-симулятора";
      download("scenario.json", JSON.stringify(sc, null, 2), "application/json");
    });

    document.addEventListener("keydown", (ev) => {
      const tag = (ev.target.tagName || "").toLowerCase();
      if (tag === "input" || tag === "select" || tag === "textarea") return;
      if (ev.code === "Space") {
        ev.preventDefault();
        $("play").click();
      } else if (ev.code === "ArrowRight") {
        ev.preventDefault();
        $("step").click();
      }
    });

    new ResizeObserver(() => resizeCanvases()).observe($("netWrap"));
    if (window.matchMedia) {
      window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", () => { readColors(); drawChart(); });
    }
  }

  function loop(ts) {
    const dt = lastTs ? Math.min(250, ts - lastTs) : 0;
    lastTs = ts;
    if (running && sim && !sim.finished) {
      acc += (dt * speed) / 1000;
      let steps = 0;
      while (acc >= 1 && steps < 8) {
        doStep();
        acc -= 1;
        steps++;
      }
      if (steps) updateAll();
      if (!running) updateTiles();
    }
    drawNet(ts);
    requestAnimationFrame(loop);
  }

  // ------------------------------------------------------------ запуск
  try {
    const saved = localStorage.getItem("virus-lab-theme");
    if (saved) document.documentElement.setAttribute("data-theme", saved);
  } catch (e) { /* нет хранилища */ }
  readColors();
  buildControls();
  buildScenarioSelect();
  bindEvents();
  loadScenario(0);
  requestAnimationFrame(loop);
})();
