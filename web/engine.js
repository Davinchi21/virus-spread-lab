/*
 * Движок лаборатории — порт пакета virus_lab (Python) на JavaScript.
 * Порядок обращений к генератору случайных чисел совпадает с Python-версией,
 * поэтому при одинаковом seed результаты одинаковые (проверка: web/test.html).
 * Справочные данные (вирусы, профили подсетей, сценарии) — в data.js.
 *
 * Два канала распространения: ЛВС (рёбра графа) и торрент/P2P (между торрент-
 * пользователями, в т.ч. ПК вне ЛВС, плюс подкачка из интернета).
 */
(function (global) {
  "use strict";
  const D = global.VIRUS_LAB_DATA;
  const S = 0, E = 1, I = 2, R = 3;
  const STATE_KEYS = ["S", "E", "I", "R"];
  const SIM_SEED_SALT = 0x9E3779B9;
  const MAX_HOSTS = 1000, MAX_PER_SUBNET = 240;
  const VIA_TEXT = { seed: "нулевой пациент", lan: "по ЛВС", p2p: "через торрент", ext: "из интернета (торрент)" };

  // ------------------------------------------------------------ ГСЧ mulberry32
  function Rng(seed) {
    this.a = seed | 0;
  }
  Rng.prototype.random = function () {
    const a = (this.a = (this.a + 0x6D2B79F5) | 0);
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
  Rng.prototype.randint = function (n) {
    return Math.floor(this.random() * n);
  };
  Rng.prototype.chance = function (p) {
    return this.random() < p;
  };

  // ------------------------------------------------------------ сеть
  function subnetProfile(s, k) {
    if (s === k - 1) {
      const p = D.serverSubnetProfile;
      return [p, p.name, p.prefix];
    }
    const L = D.subnetProfiles.length;
    const p = D.subnetProfiles[s % L];
    const round = Math.floor(s / L);
    if (round === 0) return [p, p.name, p.prefix];
    return [p, p.name + " " + (round + 1), p.prefix + (round + 1)];
  }

  function pickOs(profile, r) {
    let acc = 0;
    for (const [name, weight] of profile.os) {
      acc += weight;
      if (r < acc) return name;
    }
    return profile.os[profile.os.length - 1][0];
  }

  function buildNetwork(config, seed) {
    const cfg = Object.assign({}, D.defaultNetwork, config || {});
    const topo = cfg.topology;
    if (!(topo in D.topologies)) throw new Error("Неизвестная топология: " + topo);
    const n = cfg.hosts | 0;
    const k = cfg.subnets | 0;
    if (n < 4 || n > MAX_HOSTS) throw new Error("Число ПК должно быть от 4 до " + MAX_HOSTS);
    if (k < 1 || k * 2 > n) throw new Error("Число подсетей должно быть от 1 до половины числа ПК");
    if (Math.ceil(n / k) > MAX_PER_SUBNET) throw new Error("В подсети /24 помещается не более " + MAX_PER_SUBNET + " ПК — увеличьте число подсетей");
    const rng = new Rng(seed);

    const hosts = [];
    const counters = new Array(k).fill(0);
    for (let i = 0; i < n; i++) {
      const s = Math.floor((i * k) / n);
      const idx = counters[s]++;
      const [profile, sname, prefix] = subnetProfile(s, k);
      const rOs = rng.random(), rPatch = rng.random(), rAv = rng.random();
      const rP2p = rng.random(), rOff = rng.random();
      let os, role, roleName, hostname;
      if (s === k - 1 && idx < D.serverRoles.length) {
        const srv = D.serverRoles[idx];
        os = srv.os; role = "server"; roleName = srv.name; hostname = "srv-" + srv.role;
      } else {
        os = pickOs(profile, rOs); role = "workstation"; roleName = "Рабочая станция";
        hostname = prefix + "-pc" + String(idx + 1).padStart(2, "0");
      }
      const legacy = os === "win7";
      hosts.push({
        id: i, hostname, ip: `10.0.${s + 1}.${idx + 11}`, subnet: s, subnetName: sname,
        os, role, roleName, legacy,
        patched: !legacy && rPatch < cfg.patch_coverage,
        av: rAv < cfg.av_coverage,
        p2p: role === "workstation" && rP2p < cfg.p2p_share,
        offline: role === "workstation" && rOff < cfg.offline_share,
      });
    }

    const adj = Array.from({ length: n }, () => new Set());
    const link = (a, b) => {
      if (a !== b) { adj[a].add(b); adj[b].add(a); }
    };
    const ringLattice = (kk) => {
      for (let i = 0; i < n; i++) for (let d = 1; d <= kk; d++) link(i, (i + d) % n);
    };
    const serverStart = hosts.find((h) => h.subnet === k - 1).id;

    if (topo === "corporate") {
      for (let s = 0; s < k; s++) {
        const m = hosts.filter((h) => h.subnet === s).map((h) => h.id);
        for (let a = 0; a < m.length; a++) for (let b = a + 1; b < m.length; b++) link(m[a], m[b]);
      }
      const core = hosts.filter((h) => h.role === "server").slice(0, D.coreServers).map((h) => h.id);
      for (const h of hosts) if (h.subnet !== k - 1) for (const c of core) link(h.id, c);
      for (let q = 0; q < (cfg.cross_links | 0); q++) {
        const a = rng.randint(n), b = rng.randint(n);
        if (hosts[a].subnet !== hosts[b].subnet) link(a, b);
      }
    } else if (topo === "flat") {
      for (let a = 0; a < n; a++) for (let b = a + 1; b < n; b++) link(a, b);
    } else if (topo === "star") {
      for (let i = 0; i < n; i++) link(serverStart, i);
    } else if (topo === "ring") {
      ringLattice(Math.max(1, Math.floor((cfg.avg_degree | 0) / 2)));
    } else if (topo === "grid") {
      const side = Math.ceil(Math.sqrt(n));
      for (let i = 0; i < n; i++) {
        if ((i % side) + 1 < side && i + 1 < n) link(i, i + 1);
        if (i + side < n) link(i, i + side);
      }
    } else if (topo === "random") {
      const p = Number(cfg.avg_degree) / (n - 1);
      for (let a = 0; a < n; a++) for (let b = a + 1; b < n; b++) if (rng.chance(p)) link(a, b);
    } else if (topo === "small_world") {
      const kk = Math.max(1, Math.floor((cfg.avg_degree | 0) / 2));
      ringLattice(kk);
      for (let i = 0; i < n; i++) {
        for (let d = 1; d <= kk; d++) {
          const j = (i + d) % n;
          if (rng.chance(cfg.rewire_p)) {
            const c = rng.randint(n);
            if (c !== i && !adj[i].has(c) && adj[i].has(j)) {
              adj[i].delete(j); adj[j].delete(i); link(i, c);
            }
          }
        }
      }
    } else if (topo === "scale_free") {
      const m = Math.max(1, Math.min(cfg.ba_m | 0, n - 1));
      const rep = [];
      for (let a = 0; a <= m; a++) for (let b = a + 1; b <= m; b++) { link(a, b); rep.push(a, b); }
      for (let v = m + 1; v < n; v++) {
        const targets = [];
        while (targets.length < m) {
          const t = rep[rng.randint(rep.length)];
          if (!targets.includes(t)) targets.push(t);
        }
        targets.sort((x, y) => x - y);
        for (const t of targets) { link(v, t); rep.push(t, v); }
      }
    }

    // Автономные ПК не подключены к ЛВС: у них нет сетевых связей.
    for (const h of hosts) {
      if (h.offline) {
        for (const j of adj[h.id]) adj[j].delete(h.id);
        adj[h.id].clear();
      }
    }

    const neighbors = adj.map((set) => Array.from(set).sort((a, b) => a - b));
    const cross = neighbors.map((nb, i) => nb.map((j) => hosts[i].subnet !== hosts[j].subnet));
    const subnetNames = [];
    for (const h of hosts) subnetNames[h.subnet] = h.subnetName;
    return {
      hosts, neighbors, cross, config: cfg, topology: topo, size: n, subnets: k, subnetNames,
      edgeCount: neighbors.reduce((acc, nb) => acc + nb.length, 0) / 2,
      find(key) {
        if (typeof key === "number") return key;
        const text = String(key).trim();
        if (/^-?\d+$/.test(text)) return parseInt(text, 10);
        const h = hosts.find((x) => x.hostname === text || x.ip === text);
        if (!h) throw new Error("Узел не найден: " + text);
        return h.id;
      },
    };
  }

  // ------------------------------------------------------------ вирусы и сценарии
  function clone(x) {
    return JSON.parse(JSON.stringify(x));
  }

  function getVirus(spec) {
    if (typeof spec === "string") {
      if (!(spec in D.viruses)) throw new Error("Неизвестный вирус: " + spec);
      return Object.assign(clone(D.viruses[spec]), { id: spec });
    }
    const baseId = spec.base || spec.id;
    const out = baseId in D.viruses ? getVirus(baseId)
      : Object.assign(getVirus("worm_smb"), { id: "custom", name: "Пользовательский вирус" });
    Object.assign(out, clone(spec));
    delete out.base;
    return out;
  }

  function normalize(sc) {
    const out = Object.assign(
      { name: "Сценарий", description: "", seed: 42, network_seed: null, model: "SIR", virus: "worm_smb", network: {}, params: {} },
      clone(sc || {})
    );
    out.network = Object.assign({}, D.defaultNetwork, out.network || {});
    out.params = Object.assign({}, D.defaultParams, out.params || {});
    out.virus = getVirus(out.virus);
    return out;
  }

  // ------------------------------------------------------------ модель
  class Simulation {
    constructor(network, virus, model, params, seed, keepEvents = true) {
      if (!(model in D.models)) throw new Error("Неизвестная модель: " + model);
      this.net = network;
      this.hosts = network.hosts;
      this.n = this.hosts.length;
      this.virus = virus;
      this.model = model;
      this.params = Object.assign({}, D.defaultParams, params || {});
      this.seed = seed;
      this.rng = new Rng(seed ^ SIM_SEED_SALT);
      this.keepEvents = keepEvents;
      const n = this.n;
      this.state = new Array(n).fill(S);
      this.patched = this.hosts.map((h) => h.patched);
      this.targeted = this.hosts.map((h) => virus.targets.includes(h.os));
      this.p2pUsers = this.hosts.filter((h) => h.p2p).map((h) => h.id);
      this.wasInfected = new Array(n).fill(false);
      this.infectedBy = new Array(n).fill(-1);
      this.infectedAt = new Array(n).fill(-1);
      this.infectedVia = new Array(n).fill("");
      this.generation = new Array(n).fill(-1);
      this.offspring = new Array(n).fill(0);
      this.seeds = [];
      this.firstEpisode = new Array(n).fill(false);
      this.seedOffspring = 0;
      this.byChannel = { seed: 0, lan: 0, p2p: 0, ext: 0 };
      this.t = 0;
      this.ever = 0;
      this.infections = 0;
      this.newLast = 0;
      this.attempts = 0;
      this.blocked = 0;
      this.segActive = !!this.params.segmentation;
      this.p2pBlock = !!this.params.p2p_blocked;
      this.detectedAt = null;
      this.responseAt = null;
      this.responseActive = false;
      this.finished = false;
      this.endReason = "";
      this.events = [];
      this.history = [];
      this.vulnerableAtStart = 0;
      for (let i = 0; i < n; i++) if (!this.isProtected(i)) this.vulnerableAtStart++;
      this._seedInfection();
      this.newLast = this.infections;
      this._record();
      if (this._active() === 0 && !this._influxPossible()) this._finish("Заражённых узлов нет — эпидемия не началась");
    }

    _log(kind, text, extra) {
      if (this.keepEvents) this.events.push(Object.assign({ t: this.t, kind, text }, extra || {}));
    }
    name(i) {
      const h = this.hosts[i];
      return `${h.hostname} (${h.ip})`;
    }
    _active() {
      let c = 0;
      for (const s of this.state) if (s === E || s === I) c++;
      return c;
    }
    _finish(reason) {
      this.finished = true;
      this.endReason = reason;
      this._log("end", reason);
    }
    _infect(j, src, newState, via) {
      this.state[j] = newState;
      this.infectedBy[j] = src;
      this.infectedAt[j] = this.t;
      this.infectedVia[j] = via;
      this.generation[j] = src < 0 ? 0 : this.generation[src] + 1;
      if (src >= 0) {
        this.offspring[src]++;
        if (this.firstEpisode[src]) this.seedOffspring++;
      } else {
        this.seeds.push(j);
        this.firstEpisode[j] = true;
      }
      if (!this.wasInfected[j]) { this.wasInfected[j] = true; this.ever++; }
      this.infections++;
      this.byChannel[via]++;
      if (via === "seed") this._log("infect", `Нулевой пациент: ${this.name(j)}`, { host: j, via });
      else if (via === "ext") this._log("infect", `${this.name(j)} скачал заражённый файл из торрента`, { host: j, via });
      else this._log("infect", `${this.name(src)} заразил ${this.name(j)} ${VIA_TEXT[via]}`, { host: j, src, via });
    }
    _seedInfection() {
      const eligible = [];
      for (let i = 0; i < this.n; i++) if (this.targeted[i]) eligible.push(i);
      if (!eligible.length) {
        this._log("info", "Вирус не может заразить ни один узел: в сети нет подходящих ОС");
        return;
      }
      const k = Math.max(0, Math.min(this.params.initial_infected | 0, eligible.length));
      let count = 0;
      const pz = this.params.patient_zero;
      if (Number.isInteger(pz) && pz >= 0 && pz < this.n && k > 0) {
        if (this.targeted[pz]) { this._infect(pz, -1, I, "seed"); count = 1; }
        else this._log("info", `${this.name(pz)}: ОС не поражается этим вирусом, нулевой пациент выбран случайно`);
      }
      while (count < k) {
        const j = eligible[this.rng.randint(eligible.length)];
        if (this.state[j] === S) { this._infect(j, -1, I, "seed"); count++; }
      }
    }
    _record() {
      const c = [0, 0, 0, 0];
      for (const s of this.state) c[s]++;
      let patched = 0;
      for (const p of this.patched) if (p) patched++;
      this.history.push({
        t: this.t, S: c[S], E: c[E], I: c[I], R: c[R], ever: this.ever, new: this.newLast,
        attempts: this.attempts, blocked: this.blocked, patched,
      });
    }

    lanProb(j) {
      if (!this.targeted[j]) return 0;
      const v = this.virus;
      if (v.needs_vuln && this.patched[j]) return 0;
      let p = v.beta;
      if (v.user_action) p *= 1 - this.params.user_awareness;
      if (this.hosts[j].av) p *= 1 - v.av_block;
      return p;
    }
    infectionProb(j) { return this.lanProb(j); }
    p2pProb(j) {
      if (!this.targeted[j] || !this.hosts[j].p2p) return 0;
      let p = this.virus.p2p_beta * (1 - this.params.user_awareness);
      if (this.hosts[j].av) p *= 1 - this.virus.av_block;
      return p;
    }
    p2pOpen(j) {
      const h = this.hosts[j];
      return h.p2p && !(this.p2pBlock && !h.offline);
    }
    isProtected(j) {
      const v = this.virus;
      const lan = v.contacts > 0 && this.net.neighbors[j].length > 0 && this.lanProb(j) > 0;
      const p2p = (v.p2p_contacts > 0 || v.external_rate > 0) && this.p2pOpen(j) && this.p2pProb(j) > 0;
      return !(lan || p2p);
    }
    _influxPossible() {
      if (this.virus.external_rate <= 0) return false;
      return this.p2pUsers.some((j) => this.state[j] === S && this.p2pOpen(j) && this.p2pProb(j) > 0);
    }

    step() {
      if (this.finished) return false;
      this.t++;
      const p = this.params, v = this.virus, rng = this.rng, n = this.n;

      if (!this.responseActive && this.responseAt !== null && this.t >= this.responseAt) {
        this.responseActive = true;
        if (p.response_segmentation) this.segActive = true;
        if (p.response_p2p_block) this.p2pBlock = true;
        this._log("response", "Начато реагирование на инцидент");
      }

      const start = this.state.slice();
      const before = this.infections;
      const targetState = this.model === "SEIR" ? E : I;

      // 2. ЛВС
      const lanContacts = v.contacts | 0;
      if (lanContacts > 0) {
        for (let i = 0; i < n; i++) {
          if (start[i] !== I) continue;
          const nb = this.net.neighbors[i];
          if (!nb.length) continue;
          const cross = this.net.cross[i];
          for (let c = 0; c < lanContacts; c++) {
            const idx = rng.randint(nb.length);
            const j = nb[idx];
            this.attempts++;
            if (this.state[j] !== S) continue;
            if (cross[idx] && this.segActive && !rng.chance(v.firewall_bypass)) { this.blocked++; continue; }
            const prob = this.lanProb(j);
            if (prob <= 0) continue;
            if (rng.chance(prob)) this._infect(j, i, targetState, "lan");
          }
        }
      }

      // 3. Торрент между ПК
      const p2pContacts = v.p2p_contacts | 0;
      const users = this.p2pUsers;
      if (p2pContacts > 0 && users.length > 1) {
        for (let i = 0; i < n; i++) {
          if (start[i] !== I || !this.hosts[i].p2p) continue;
          if (!this.p2pOpen(i)) { this.attempts += p2pContacts; this.blocked += p2pContacts; continue; }
          for (let c = 0; c < p2pContacts; c++) {
            const j = users[rng.randint(users.length)];
            this.attempts++;
            if (j === i || this.state[j] !== S) continue;
            if (!this.p2pOpen(j)) { this.blocked++; continue; }
            const prob = this.p2pProb(j);
            if (prob <= 0) continue;
            if (rng.chance(prob)) this._infect(j, i, targetState, "p2p");
          }
        }
      }

      // 4. Интернет
      const ext = v.external_rate;
      if (ext > 0) {
        for (const j of users) {
          if (this.state[j] !== S || !this.p2pOpen(j)) continue;
          const prob = this.p2pProb(j);
          if (prob <= 0) continue;
          if (rng.chance(ext * prob)) this._infect(j, -1, targetState, "ext");
        }
      }

      // 5. Инкубация
      if (this.model === "SEIR") {
        for (let i = 0; i < n; i++) if (start[i] === E && rng.chance(v.sigma)) this.state[i] = I;
      }

      // 6. Лечение
      if (this.model !== "SI") {
        const q = this.responseActive ? p.response_quarantine : 0;
        const back = this.model === "SIS" ? S : R;
        for (let i = 0; i < n; i++) {
          if (start[i] !== I) continue;
          const avd = this.hosts[i].av ? v.av_detect : 0;
          const pr = 1 - (1 - p.gamma) * (1 - avd) * (1 - q);
          if (rng.chance(pr)) {
            this.state[i] = back;
            this.firstEpisode[i] = false;
            this._log("recover", `${this.name(i)} вылечен/изолирован`, { host: i });
          }
        }
      }

      // 7. Патчи
      if (this.responseActive && p.response_patch_rate > 0) {
        for (let i = 0; i < n; i++) {
          if (!this.patched[i] && !this.hosts[i].legacy) {
            if (rng.chance(p.response_patch_rate)) this.patched[i] = true;
          }
        }
      }

      // 8. Обнаружение
      if (this.detectedAt === null && this.ever >= p.detect_threshold * n) {
        this.detectedAt = this.t;
        this.responseAt = this.t + (p.response_delay | 0);
        this._log("detect", `Инцидент обнаружен: заражено ${this.ever} ПК. Реагирование начнётся на шаге ${this.responseAt}`);
      }

      this.newLast = this.infections - before;
      this._record();

      if (this._active() === 0 && !this._influxPossible()) this._finish("Эпидемия завершилась: заражённых узлов не осталось");
      else if (this.model === "SI" && !this.state.some((s, i) => s === S && !this.isProtected(i)))
        this._finish("Все доступные для заражения узлы заражены");
      else if (this.t >= (p.max_steps | 0)) this._finish("Достигнут предел числа шагов");
      return !this.finished;
    }

    run() {
      while (this.step()) { /* шагаем до конца */ }
      return this;
    }

    // --- ручные действия из интерфейса (нарушают воспроизводимость прогона) ---
    manualInfect(j) {
      if (this.state[j] === E || this.state[j] === I) return false;
      if (!this.targeted[j]) return false;
      this._infect(j, -1, I, "seed");
      this.history[this.history.length - 1].ever = this.ever;
      if (this.finished) { this.finished = false; this.endReason = ""; }
      return true;
    }
    manualPatch(j) {
      if (this.hosts[j].legacy) return false;
      this.patched[j] = true;
      this._log("info", `Вручную установлен патч: ${this.name(j)}`, { host: j });
      return true;
    }
    manualIsolate(j) {
      if (this.state[j] !== E && this.state[j] !== I) return false;
      this.state[j] = this.model === "SIS" ? S : R;
      this.firstEpisode[j] = false;
      this._log("recover", `Вручную изолирован: ${this.name(j)}`, { host: j });
      return true;
    }

    summary() {
      const h = this.history;
      let peak = -1, peakT = 0;
      for (const r of h) if (r.E + r.I > peak) { peak = r.E + r.I; peakT = r.t; }
      const half = h.find((r) => r.ever * 2 >= this.n);
      const offline = this.hosts.filter((x) => x.offline);
      return {
        steps: this.t, endReason: this.endReason, peak, peakT,
        ever: this.ever, everFraction: this.ever / this.n, infections: this.infections,
        byChannel: Object.assign({}, this.byChannel),
        halfStep: half ? half.t : null,
        r0: this.seeds.length ? this.seedOffspring / this.seeds.length : 0,
        attempts: this.attempts, blocked: this.blocked,
        detectedAt: this.detectedAt, responseAt: this.responseAt,
        offlineHosts: offline.length,
        offlineInfected: offline.filter((x) => this.wasInfected[x.id]).length,
        p2pUsers: this.p2pUsers.length,
      };
    }
  }

  function makeSimulation(scenario, seed, keepEvents = true) {
    const sc = normalize(scenario);
    const s = seed === undefined || seed === null ? sc.seed : seed;
    const net = buildNetwork(sc.network, sc.network_seed === null || sc.network_seed === undefined ? s : sc.network_seed);
    const params = Object.assign({}, sc.params);
    if (typeof params.patient_zero === "string") params.patient_zero = net.find(params.patient_zero);
    return new Simulation(net, sc.virus, sc.model, params, s, keepEvents);
  }

  global.VirusLab = {
    S, E, I, R, STATE_KEYS, Rng, buildNetwork, getVirus, normalize, Simulation, makeSimulation, data: D,
  };
})(typeof window !== "undefined" ? window : globalThis);
