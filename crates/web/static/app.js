/* SkyCipher web console. Vanilla JS, no dependencies, CSP-safe (no eval/inline).
 * Keys/nonces live only in DOM inputs and in-memory variables of this tab; they are
 * never written to localStorage/sessionStorage/cookies. All server text is rendered
 * with textContent (never innerHTML). */
"use strict";

(() => {
  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

  // ---------- Formatting & bytes ----------
  const HEX = Array.from({ length: 256 }, (_, i) => i.toString(16).padStart(2, "0"));
  const toHex = (bytes) => {
    const out = new Array(bytes.length);
    for (let i = 0; i < bytes.length; i++) out[i] = HEX[bytes[i]];
    return out.join("");
  };

  // ---------- In-Browser WebAssembly Verifier & Crypto ----------
  let wasmModuleExports = null;
  let wasmLoadingPromise = null;

  const loadWasmModule = async () => {
    if (wasmModuleExports) return wasmModuleExports;
    if (!wasmLoadingPromise) {
      wasmLoadingPromise = (async () => {
        try {
          let resp = await fetch("/static/wasm/todo_wasm.wasm");
          let module;
          if (typeof WebAssembly.instantiateStreaming === "function") {
            try {
              module = await WebAssembly.instantiateStreaming(resp);
            } catch (_) {
              const buf = await (await fetch("/static/wasm/todo_wasm.wasm")).arrayBuffer();
              module = await WebAssembly.instantiate(buf);
            }
          } else {
            const buf = await resp.arrayBuffer();
            module = await WebAssembly.instantiate(buf);
          }
          wasmModuleExports = module.instance.exports;
          return wasmModuleExports;
        } catch (e) {
          wasmLoadingPromise = null;
          throw e;
        }
      })();
    }
    return wasmLoadingPromise;
  };

  const verifyBlockWithWasm = async (wasm, rawBytes, cidStr) => {
    const encoder = new TextEncoder();
    const cidBytes = encoder.encode(cidStr.trim());
    const dataPtr = wasm.todo_wasm_alloc(rawBytes.length);
    const cidPtr = wasm.todo_wasm_alloc(cidBytes.length);
    try {
      new Uint8Array(wasm.memory.buffer).set(rawBytes, dataPtr);
      new Uint8Array(wasm.memory.buffer).set(cidBytes, cidPtr);
      const res = wasm.todo_wasm_verify_block(dataPtr, rawBytes.length, cidPtr, cidBytes.length);
      return res === 1;
    } finally {
      wasm.todo_wasm_free(dataPtr, rawBytes.length);
      wasm.todo_wasm_free(cidPtr, cidBytes.length);
    }
  };

  const parseManifestWithWasm = (wasm, manifestBytes) => {
    const dataPtr = wasm.todo_wasm_alloc(manifestBytes.length);
    const ptrBuf = wasm.todo_wasm_alloc(8);
    const lenBuf = wasm.todo_wasm_alloc(8);
    try {
      new Uint8Array(wasm.memory.buffer).set(manifestBytes, dataPtr);
      const status = wasm.todo_wasm_parse_manifest(dataPtr, manifestBytes.length, ptrBuf, lenBuf);
      if (status < 0) throw new Error("Invalid DAG-JSON manifest structure");
      const view = new DataView(wasm.memory.buffer);
      const outPtr = view.getUint32(ptrBuf, true);
      const outLen = view.getUint32(lenBuf, true);
      const jsonStr = new TextDecoder().decode(new Uint8Array(wasm.memory.buffer, outPtr, outLen));
      const manifest = JSON.parse(jsonStr);
      wasm.todo_wasm_free(outPtr, outLen);
      return manifest;
    } finally {
      wasm.todo_wasm_free(dataPtr, manifestBytes.length);
      wasm.todo_wasm_free(ptrBuf, 8);
      wasm.todo_wasm_free(lenBuf, 8);
    }
  };

  const decryptDecompressWithWasm = (wasm, ctWithTag, keyHex, nonceHex) => {
    const encoder = new TextEncoder();
    const keyBytes = encoder.encode(keyHex.trim());
    const nonceBytes = encoder.encode(nonceHex.trim());

    const ctPtr = wasm.todo_wasm_alloc(ctWithTag.length);
    const keyPtr = wasm.todo_wasm_alloc(keyBytes.length);
    const noncePtr = wasm.todo_wasm_alloc(nonceBytes.length);
    const ptrBuf = wasm.todo_wasm_alloc(8);
    const lenBuf = wasm.todo_wasm_alloc(8);

    try {
      new Uint8Array(wasm.memory.buffer).set(ctWithTag, ctPtr);
      new Uint8Array(wasm.memory.buffer).set(keyBytes, keyPtr);
      new Uint8Array(wasm.memory.buffer).set(nonceBytes, noncePtr);

      const status = wasm.todo_wasm_decrypt_decompress(
        ctPtr,
        ctWithTag.length,
        keyPtr,
        keyBytes.length,
        noncePtr,
        nonceBytes.length,
        ptrBuf,
        lenBuf
      );
      if (status < 0) {
        throw new Error(`Verifikasi tag AEAD atau dekompresi Zstd gagal (kode: ${status})`);
      }
      const view = new DataView(wasm.memory.buffer);
      const outPtr = view.getUint32(ptrBuf, true);
      const outLen = view.getUint32(lenBuf, true);
      const res = new Uint8Array(new Uint8Array(wasm.memory.buffer, outPtr, outLen));
      wasm.todo_wasm_free(outPtr, outLen);
      return res;
    } finally {
      wasm.todo_wasm_free(ctPtr, ctWithTag.length);
      wasm.todo_wasm_free(keyPtr, keyBytes.length);
      wasm.todo_wasm_free(noncePtr, nonceBytes.length);
      wasm.todo_wasm_free(ptrBuf, 8);
      wasm.todo_wasm_free(lenBuf, 8);
    }
  };

  const initServiceWorker = async () => {
    const swPill = $("#sw-pill");
    if (!("serviceWorker" in navigator)) {
      if (swPill) {
        swPill.dataset.state = "error";
        swPill.querySelector(".pill-text").textContent = "SW: Tak Didukung";
      }
      return;
    }
    try {
      const reg = await navigator.serviceWorker.register("/sw.js", { scope: "/" });
      if (swPill) {
        swPill.dataset.state = "live";
        swPill.querySelector(".pill-text").textContent = "SW: Aktif";
        swPill.title = `Service Worker aktif · scope: ${reg.scope}`;
      }
    } catch (err) {
      console.warn("Service Worker registration failed:", err);
      if (swPill) {
        swPill.dataset.state = "warn";
        swPill.querySelector(".pill-text").textContent = "SW: Standby";
      }
    }
  };
  const randomBytes = (n) => {
    const b = new Uint8Array(n);
    for (let o = 0; o < n; o += 65536) crypto.getRandomValues(b.subarray(o, Math.min(n, o + 65536)));
    return b;
  };
  const fmtBytes = (n) => {
    if (!Number.isFinite(n)) return "—";
    const u = ["B", "KiB", "MiB", "GiB"];
    let v = n, i = 0;
    while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
    return `${i === 0 || Number.isInteger(v) ? v.toFixed(0) : v.toFixed(v < 10 ? 2 : 1)} ${u[i]}`;
  };
  const fmtNum = (n) => new Intl.NumberFormat("id-ID").format(n);
  const fmtMicros = (us) => {
    if (!Number.isFinite(us)) return "—";
    if (us < 1000) return `${us.toFixed(1)} µs`;
    if (us < 1e6) return `${(us / 1000).toFixed(2)} ms`;
    return `${(us / 1e6).toFixed(2)} s`;
  };
  const isHex = (s, bytes) => new RegExp(`^[0-9a-fA-F]{${bytes * 2}}$`).test(s);

  // ---------- DOM helpers ----------
  const h = (tag, attrs = {}, ...children) => {
    const el = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs)) {
      if (k === "class") el.className = v;
      else if (k === "text") el.textContent = v;
      else el.setAttribute(k, v);
    }
    for (const c of children) el.append(c);
    return el;
  };
  const setK = (root, key, value) => {
    for (const el of $$(`[data-k="${key}"]`, root)) el.textContent = value;
  };
  const setBadge = (el, kind, text) => {
    el.className = `badge badge-${kind}`;
    el.textContent = text;
  };
  const setWidth = (el, pct) => {
    requestAnimationFrame(() => { el.style.width = `${Math.max(0, Math.min(100, pct))}%`; });
  };

  // ---------- Toasts ----------
  const toast = (message, kind = "info", ms = 4500) => {
    const region = $("#toasts");
    if (!region) return;
    const t = h("div", { class: `toast ${kind}`, role: kind === "err" ? "alert" : "status" }, h("span", { text: message }));
    region.append(t);
    setTimeout(() => {
      t.classList.add("leaving");
      setTimeout(() => t.remove(), 220);
    }, ms);
  };

  // ---------- API ----------
  class ApiError extends Error {
    constructor(message, status) { super(message); this.status = status; }
  }
  const api = async (path, body) => {
    const init = body === undefined
      ? { method: "GET" }
      : { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) };
    let res;
    try {
      res = await fetch(path, { ...init, cache: "no-store", credentials: "same-origin" });
    } catch (_) {
      throw new ApiError("Server tidak dapat dihubungi.", 0);
    }
    let data = null;
    try { data = await res.json(); } catch (_) { /* non-JSON */ }
    if (!res.ok) throw new ApiError((data && data.error) || `HTTP ${res.status}`, res.status);
    return data;
  };
  const busy = async (btn, fn) => {
    if (!btn || btn.getAttribute("aria-busy") === "true") return undefined;
    btn.setAttribute("aria-busy", "true");
    btn.disabled = true;
    try { return await fn(); } finally { btn.removeAttribute("aria-busy"); btn.disabled = false; }
  };
  // Never surface details of an authentication failure (API_WEB.md: generic errors).
  const AUTH_FAIL_MSG = "Verifikasi gagal: kunci/nonce salah atau data telah dimodifikasi. Tidak ada plaintext yang dirilis.";
  const friendlyError = (e) => {
    if (!(e instanceof ApiError)) return "Terjadi kesalahan tak terduga.";
    if (e.status === 0) return e.message;
    if (e.status === 401 && /login required|not logged in/i.test(e.message)) return "Sesi tidak ada atau telah berakhir: silakan masuk di halaman Akun.";
    if (e.status === 401 && /username or password/i.test(e.message)) return "Nama pengguna atau kata sandi salah.";
    if (e.status === 401) return "Token API salah atau belum diisi.";
    if (e.status === 429 && /failed logins/i.test(e.message)) return "Terlalu banyak percobaan masuk gagal; coba lagi nanti.";
    if (e.status === 404 && /for this account/.test(e.message)) return "Objek tidak ditemukan, atau bukan milik akun Anda.";
    if (e.status === 404) return "Objek tidak ditemukan pada backend penyimpanan.";
    if (e.status === 503 && /metadata store/i.test(e.message)) return "Penyimpanan metadata (PostgreSQL) tidak tersedia.";
    if (e.status === 413) return "Data terlalu besar untuk dikirim.";
    if (/authentication|tag verification/i.test(e.message)) return AUTH_FAIL_MSG;
    if (e.status === 422) return `Objek ditolak: ${e.message}`;
    if (e.status === 429) return "Server sedang sibuk memproses berkas lain; coba lagi sebentar.";
    if (e.status === 503) return "Vault nonaktif: server tidak memiliki kunci.";
    if (e.status === 400) return `Permintaan ditolak: ${e.message}`;
    return `Server galat (HTTP ${e.status}).`;
  };

  // ---------- Shell: navigation, theme, health ----------
  const initShell = () => {
    const sidebar = $("#sidebar"), scrim = $("#scrim"), menu = $("#menu-btn");
    const setMenu = (open) => {
      sidebar.classList.toggle("open", open);
      scrim.hidden = !open;
      menu.setAttribute("aria-expanded", String(open));
    };
    menu?.addEventListener("click", () => setMenu(!sidebar.classList.contains("open")));
    scrim?.addEventListener("click", () => setMenu(false));
    document.addEventListener("keydown", (e) => { if (e.key === "Escape") setMenu(false); });

    $("#theme-btn")?.addEventListener("click", () => {
      const root = document.documentElement;
      const dark = root.dataset.theme
        ? root.dataset.theme === "dark"
        : matchMedia("(prefers-color-scheme: dark)").matches;
      root.dataset.theme = dark ? "light" : "dark";
      try { localStorage.setItem("skycipher-theme", root.dataset.theme); } catch (_) { /* ignore */ }
    });

    const refreshHealth = async () => {
      const pill = $("#health-pill");
      pill.dataset.state = "loading";
      $(".pill-text", pill).textContent = "Memeriksa layanan…";
      try {
        const hres = await api("/api/v1/health");
        pill.dataset.state = "ok";
        $(".pill-text", pill).textContent = `Layanan aktif · v${hres.version}`;
        const box = $("#health-details");
        if (box) for (const [k, v] of Object.entries(hres)) {
          const dd = $(`[data-field="${k}"]`, box);
          if (dd) dd.textContent = String(v);
        }
      } catch (_) {
        pill.dataset.state = "down";
        $(".pill-text", pill).textContent = "Layanan tidak merespons";
      }
    };
    refreshHealth();
    $("#health-refresh")?.addEventListener("click", refreshHealth);
  };

  // ---------- Reusable form widgets ----------
  const initTabs = (root) => {
    for (const list of $$('[role="tablist"]', root)) {
      const tabs = $$('[role="tab"]', list);
      const select = (tab) => {
        for (const t of tabs) {
          const on = t === tab;
          t.setAttribute("aria-selected", String(on));
          t.tabIndex = on ? 0 : -1;
          document.getElementById(t.getAttribute("aria-controls")).hidden = !on;
        }
      };
      tabs.forEach((tab, i) => {
        tab.addEventListener("click", () => select(tab));
        tab.addEventListener("keydown", (e) => {
          const d = e.key === "ArrowRight" ? 1 : e.key === "ArrowLeft" ? -1 : 0;
          if (!d) return;
          const next = tabs[(i + d + tabs.length) % tabs.length];
          select(next);
          next.focus();
        });
      });
    }
  };
  const activeSource = (form) => {
    const tab = $('[role="tab"][aria-selected="true"]', form);
    return tab ? tab.getAttribute("aria-controls").split("-").pop() : "text";
  };

  const initConditional = (form) => {
    const items = $$("[data-show-when]", form);
    const update = () => {
      for (const el of items) {
        const [name, value] = el.dataset.showWhen.split("=");
        el.hidden = form.elements[name]?.value !== value;
      }
    };
    form.addEventListener("change", update);
    update();
  };

  const initRange = (form) => {
    const range = form.elements.compression_level, out = form.elements.level_out;
    if (!range || !out) return;
    const sync = () => { out.value = range.value; };
    range.addEventListener("input", sync);
    sync();
  };

  const initSecrets = (root) => {
    for (const btn of $$("[data-toggle-secret]", root)) {
      btn.addEventListener("click", () => {
        const input = $("input", btn.closest(".input-group"));
        const show = input.type === "password";
        input.type = show ? "text" : "password";
        btn.textContent = show ? "Sembunyikan" : "Lihat";
        btn.setAttribute("aria-label", show ? "Sembunyikan kunci" : "Tampilkan kunci");
      });
    }
  };

  const initKeybox = (form) => {
    const box = $("[data-keybox]", form);
    if (!box) return;
    const bits = $("[data-key-bits]", box), key = $("[data-key-input]", box), nonce = $("[data-nonce-input]", box);
    const regen = () => {
      key.value = toHex(randomBytes(Number(bits.value) / 8));
      nonce.value = toHex(randomBytes(12));
      key.removeAttribute("aria-invalid");
      nonce.removeAttribute("aria-invalid");
    };
    bits.addEventListener("change", regen);
    $("[data-key-regen]", box).addEventListener("click", () => { regen(); toast("Kunci dan nonce baru dibuat di peramban.", "ok", 2500); });
    regen();
  };

  const readKeyNonce = (form) => {
    const key = form.elements.key_hex, nonce = form.elements.nonce_hex;
    const k = key.value.trim(), n = nonce.value.trim();
    const keyOk = isHex(k, 16) || isHex(k, 32), nonceOk = isHex(n, 12);
    key.setAttribute("aria-invalid", String(!keyOk));
    nonce.setAttribute("aria-invalid", String(!nonceOk));
    if (!keyOk) throw new Error("Kunci harus 32 atau 64 digit hex (128/256 bit).");
    if (!nonceOk) throw new Error("Nonce harus tepat 24 digit hex (96 bit).");
    return { key_hex: k.toLowerCase(), nonce_hex: n.toLowerCase() };
  };

  const initDropzone = (form) => {
    const dz = $("[data-dropzone]", form);
    if (!dz) return;
    const input = $('input[type="file"]', dz), meta = $("[data-file-meta]", dz);
    const max = Number(form.dataset.maxInput || Infinity);
    const setFile = (file) => {
      form._file = null;
      if (!file) { meta.textContent = "Belum ada berkas"; return; }
      if (file.size > max) {
        meta.textContent = `${file.name} terlalu besar (${fmtBytes(file.size)} > ${fmtBytes(max)})`;
        toast("Berkas melebihi batas ukuran.", "warn");
        return;
      }
      form._file = file;
      meta.textContent = `${file.name} · ${fmtBytes(file.size)}`;
    };
    input.addEventListener("change", () => setFile(input.files[0]));
    for (const ev of ["dragenter", "dragover"]) dz.addEventListener(ev, (e) => { e.preventDefault(); dz.classList.add("drag"); });
    for (const ev of ["dragleave", "drop"]) dz.addEventListener(ev, () => dz.classList.remove("drag"));
    dz.addEventListener("drop", (e) => { e.preventDefault(); setFile(e.dataTransfer.files[0]); });
  };

  const initCopy = (root) => {
    root.addEventListener("click", async (e) => {
      const btn = e.target.closest("[data-copy]");
      if (!btn) return;
      const scope = btn.closest("[data-result], form, section") || document;
      const src = $(`[data-k="${btn.dataset.copy}"]`, scope);
      const text = src?.textContent?.trim();
      if (!text) return;
      try {
        await navigator.clipboard.writeText(text);
        toast("Disalin ke clipboard.", "ok", 1800);
      } catch (_) {
        toast("Clipboard tidak tersedia di konteks ini.", "warn");
      }
    });
  };

  const showResult = (container) => {
    $("[data-empty]", container)?.setAttribute("hidden", "");
    $("[data-result]", container).hidden = false;
  };

  // ---------- Sample data ----------
  const sampleData = (kind, size) => {
    if (kind === "random") return randomBytes(size);
    const enc = new TextEncoder();
    if (kind === "text") {
      const unit = enc.encode("Langit biru, data terenkripsi, satu tag untuk satu pesan AEAD. ");
      const out = new Uint8Array(size);
      for (let o = 0; o < size; o += unit.length) out.set(unit.subarray(0, Math.min(unit.length, size - o)), o);
      return out;
    }
    const levels = ["INFO", "WARN", "DEBUG", "ERROR"];
    const rnd = randomBytes(4096);
    const parts = [];
    let len = 0, i = 0;
    while (len < size) {
      const r = rnd[i % rnd.length] ^ i;
      const line = `{"ts":${1700000000000 + i * 37},"level":"${levels[r & 3]}","node":"sky-${r % 17}","req":"${toHex(randomBytes(6))}","latency_ms":${r % 250}}\n`;
      parts.push(line);
      len += line.length;
      i++;
    }
    return enc.encode(parts.join("")).subarray(0, size);
  };

  // Returns { data: {data_utf8}|{data_hex}, size }.
  const collectInput = async (form) => {
    const max = Number(form.dataset.maxInput || Infinity);
    const source = activeSource(form);
    let bytes;
    if (source === "text") {
      const text = form.elements.text.value;
      const size = new TextEncoder().encode(text).length;
      if (size > max) throw new Error(`Teks melebihi ${fmtBytes(max)}.`);
      return { data: { data_utf8: text }, size };
    }
    if (source === "file") {
      if (!form._file) throw new Error("Pilih berkas terlebih dahulu.");
      bytes = new Uint8Array(await form._file.arrayBuffer());
    } else {
      bytes = sampleData(form.elements.sample_kind.value, Number(form.elements.sample_size.value));
    }
    if (bytes.length > max) throw new Error(`Data melebihi ${fmtBytes(max)}.`);
    return { data: { data_hex: toHex(bytes) }, size: bytes.length };
  };

  // ---------- Pipeline page ----------
  const FALLBACK = {
    single_thread: "hanya 1 thread Rayon tersedia",
    below_threshold: "data terkompresi di bawah ambang paralel",
    single_segment: "satu segmen menutupi seluruh payload",
    forced: "jalur sekuensial dipaksa",
    not_applicable: "crypto_mode ini tidak memakai POLYVAL",
  };

  const renderPipeline = (root, r) => {
    showResult(root);
    const eq = r.aes_gcm_siv_equivalence;
    const plan = r.encryption_plan;
    const mode = r.crypto_mode || "aes-gcm-siv";
    const identical = eq
      ? eq.is_bit_identical && eq.sequential_tag_hex === eq.parallel_tag_hex
        && (eq.upstream_tag_hex == null || eq.upstream_tag_hex === eq.sequential_tag_hex)
      : r.deterministic_reencryption && (r.tamper_rejected !== false);

    const pb = $("[data-parallel-badge]", root);
    if (r.parallel_path_exercised) setBadge(pb, "ok", `Jalur paralel dijalankan · ${r.num_polyval_segments} segmen`);
    else if (r.stream_parallel_exercised) setBadge(pb, "ok", `STREAM paralel dijalankan · ${r.aead_chunks} chunk`);
    else setBadge(pb, "warn", "parallel_not_exercised");
    const eqBadge = $("[data-equiv-badge]", root);
    if (eq) {
      setBadge(eqBadge, identical ? "ok" : "err",
        identical ? "Tag identik: sekuensial = paralel = upstream" : "Tag BERBEDA — correctness FAIL");
    } else if (!r.authenticated) {
      setBadge(eqBadge, "warn", `${mode}: TANPA autentikasi (baseline)`);
    } else {
      setBadge(eqBadge, identical ? "ok" : "err",
        identical ? `${mode}: deterministik & tamper ditolak` : `${mode}: verifikasi GAGAL`);
    }

    let planText;
    if (r.stream_chunk_size) {
      planText = `crypto_mode ${mode} dengan STREAM: ${r.aead_chunks} chunk AEAD × ${fmtBytes(r.stream_chunk_size)} dienkripsi paralel; indeks chunk dan penanda is_last terikat di nonce dan AAD (format v3).`;
    } else if (plan.execution === "sequential" && plan.reason === "not_applicable") {
      planText = `crypto_mode ${mode} tidak memakai POLYVAL: dienkripsi sebagai satu pesan tanpa segmentasi paralel (bukan pembanding tag AES-GCM-SIV).`;
    } else if (plan.execution === "sequential") {
      planText = `Rencana: sekuensial (${FALLBACK[plan.reason] || plan.reason}). ${fmtBytes(r.compressed_size_bytes)} terkompresi diproses sebagai 1 segmen POLYVAL, sehingga tidak ada klaim speedup paralel.`;
    } else if (!r.parallel_path_exercised) {
      planText = `Rencana: segmen ${fmtBytes(plan.segment_bytes)}, tetapi hanya ${r.num_polyval_segments} segmen dieksekusi, sehingga tidak ada klaim speedup paralel.`;
    } else {
      planText = `Rencana: ${plan.segments} segmen POLYVAL × ${fmtBytes(plan.segment_bytes)}, digabung berurutan menjadi satu tag.`;
    }
    $("[data-plan-text]", root).textContent = planText;

    setK(root, "original", fmtBytes(r.original_size_bytes));
    setK(root, "compressed", fmtBytes(r.compressed_size_bytes));
    setK(root, "ratio", `${r.compression_ratio_percent.toFixed(2)} %`);
    setK(root, "frames", fmtNum(r.zstd_frames));
    setK(root, "segments", fmtNum(r.num_polyval_segments));
    setK(root, "segment-size", r.polyval_segment_size ? `@ ${fmtBytes(r.polyval_segment_size)}` : "jalur sekuensial");
    setK(root, "algorithm", `${eq ? eq.algorithm : mode} · ${r.compression_mode === "single-frame" ? "satu frame" : "frame independen"}`);

    const maxSize = Math.max(r.original_size_bytes, r.compressed_size_bytes, r.single_frame_compressed_size_bytes, 1);
    const sizes = { original: r.original_size_bytes, compressed: r.compressed_size_bytes, single: r.single_frame_compressed_size_bytes };
    for (const [k, v] of Object.entries(sizes)) {
      setWidth($(`[data-bar="${k}"]`, root), (v / maxSize) * 100);
      setK(root, `${k}-b`, fmtBytes(v));
    }

    setK(root, "tag-seq", eq ? eq.sequential_tag_hex : "n/a (bukan AES-GCM-SIV)");
    setK(root, "tag-par", eq ? eq.parallel_tag_hex : "n/a (bukan AES-GCM-SIV)");
    setK(root, "tag-up", eq ? (eq.upstream_tag_hex || "tidak tersedia") : "n/a (bukan AES-GCM-SIV)");

    const firstCheck = eq
      ? ["Tag sekuensial = paralel = upstream aes-gcm-siv (bit-identik)", identical]
      : r.authenticated
        ? [`${mode}: enkripsi ulang deterministik & ciphertext termanipulasi ditolak`, identical]
        : [`${mode}: TANPA tag autentikasi, manipulasi tidak terdeteksi`, false];
    const streamChecks = [];
    if (r.chunk_transposition_rejected != null) streamChecks.push(["STREAM: chunk 0 dan 1 ditukar → ditolak", r.chunk_transposition_rejected]);
    if (r.chunk_truncation_rejected != null) streamChecks.push(["STREAM: chunk terakhir dibuang → ditolak", r.chunk_truncation_rejected]);
    const checks = $("[data-checks]", root);
    checks.replaceChildren(...[
      firstCheck,
      ...streamChecks,
      ["Frame dapat dibaca decoder Zstandard standar", r.standard_zstd_decoder_roundtrip],
      ["Round-trip lossless: verifikasi tag → dekripsi → dekompresi", r.pipeline_roundtrip_verified],
    ].map(([label, ok]) => h("li", { class: ok ? "" : "fail", text: `${label}${ok ? "" : " (GAGAL)"}` })));

    const stages = [
      ["Kompresi", r.compression_time_micros, "fill-a"],
      ["Enkripsi", r.encryption_time_micros, "fill-b"],
      ["Dekripsi", r.decryption_time_micros, "fill-c"],
      ["Dekompresi", r.decompression_time_micros, "fill-d"],
    ];
    const total = stages.reduce((s, [, v]) => s + v, 0) || 1;
    $("[data-stack]", root).replaceChildren(...stages.map(([label, v, cls]) => {
      const seg = h("span", { class: cls, title: `${label}: ${fmtMicros(v)}` });
      setWidth(seg, (v / total) * 100);
      return seg;
    }));
    $("[data-legend]", root).replaceChildren(...stages.map(([label, v, cls]) =>
      h("li", {}, h("span", { class: `sw ${cls}` }), `${label} · ${fmtMicros(v)}`)));
    setK(root, "throughput", `${r.total_pipeline_throughput_mib_s.toFixed(1)} MiB/s`);
  };

  const streamChunk = (form) => {
    const v = Number(form.elements.stream_chunk_size?.value || 0);
    return v > 0 && form.elements.crypto_mode.value !== "aes-gcm-siv" ? v : null;
  };

  const pipelineBody = (form, input, keys) => {
    const body = { ...input.data, ...keys, compression_level: Number(form.elements.compression_level.value) };
    body.compression_mode = form.elements.compression_mode.value;
    body.crypto_mode = form.elements.crypto_mode.value;
    const chunk = streamChunk(form);
    if (chunk) body.stream_chunk_size = chunk;
    if (body.compression_mode === "independent-frames") body.frame_size = Number(form.elements.frame_size.value);
    body.segmentation = form.elements.segmentation.value;
    if (body.segmentation === "fixed") body.polyval_segment_size = Number(form.elements.polyval_segment_size.value);
    return body;
  };

  const runTamper = async (form, results) => {
    const input = await collectInput(form);
    const maxT = Number(form.dataset.maxTamper);
    if (input.size > maxT) throw new Error(`Uji tamper dibatasi ${fmtBytes(maxT)} (sealed stream dikirim balik ke server).`);
    const keys = readKeyNonce(form);
    const card = $("[data-tamper-result]", results);
    const steps = $("[data-tamper-steps]", card);
    const badge = $("[data-tamper-badge]", card);
    card.hidden = false;
    steps.replaceChildren();
    setBadge(badge, "info", "berjalan…");
    const step = (text, ok) => steps.append(h("li", { class: ok ? "ok" : "bad", text }));

    const cryptoMode = form.elements.crypto_mode.value;
    const unauthenticated = cryptoMode === "xchacha20";
    const sealedRes = await api("/api/v1/pipeline/process", {
      ...input.data, ...keys,
      compression_level: Number(form.elements.compression_level.value),
      crypto_mode: cryptoMode,
      ...(streamChunk(form) ? { stream_chunk_size: streamChunk(form) } : {}),
    });
    const sealed = sealedRes.sealed;
    step(`Seal (${cryptoMode}): ${fmtBytes(sealed.ciphertext.length)} ciphertext, ${sealed.segments.length} frame, tag ${sealed.tag.length} B${sealed.tag.length ? ` (${toHex(sealed.tag).slice(0, 16)}…)` : ""}.`, true);

    const tryRecover = async (s, nonceHex) => {
      try {
        const r = await api("/api/v1/pipeline/recover", { sealed: s, key_hex: keys.key_hex, nonce_hex: nonceHex, crypto_mode: cryptoMode });
        return { ok: true, size: r.recovered_size_bytes };
      } catch (e) {
        return { ok: false, status: e.status };
      }
    };
    let allGood = true;
    const orig = await tryRecover(sealed, keys.nonce_hex);
    allGood &&= orig.ok;
    step(orig.ok ? `Pesan asli: tag valid, ${fmtBytes(orig.size)} dipulihkan.` : "Pesan asli gagal dipulihkan (tidak terduga).", orig.ok);

    const clone = () => JSON.parse(JSON.stringify(sealed));
    const cases = [];
    if (sealed.ciphertext.length > 0) {
      const c = clone();
      c.ciphertext[c.ciphertext.length >> 1] ^= 0x01;
      cases.push(["1 bit ciphertext dibalik", c, keys.nonce_hex]);
    }
    if (sealed.tag.length > 0) {
      const t = clone();
      t.tag[t.tag.length - 1] ^= 0x80;
      cases.push(["1 bit tag dibalik", t, keys.nonce_hex]);
    }
    if (sealed.stream_chunk_size) {
      // Full chunk slot = chunk bytes + cascade inner tag + chunk tag.
      const slot = sealed.stream_chunk_size + sealed.tag.length + (cryptoMode.startsWith("cascade") ? 16 : 0);
      if (sealed.ciphertext.length > 2 * slot) {
        const t = clone();
        for (let i = 0; i < slot; i++) {
          [t.ciphertext[i], t.ciphertext[slot + i]] = [t.ciphertext[slot + i], t.ciphertext[i]];
        }
        cases.push(["Chunk STREAM 0 dan 1 ditukar (transposisi)", t, keys.nonce_hex]);
      }
    }
    if (sealed.segments.length > 0) {
      const m = clone();
      m.segments[0].uncompressed_size += 1;
      cases.push(["Metadata frame (AAD) diubah", m, keys.nonce_hex]);
    }
    const n = keys.nonce_hex.slice(0, -2) + HEX[(parseInt(keys.nonce_hex.slice(-2), 16) ^ 1)];
    cases.push(["Nonce berbeda", clone(), n]);

    for (const [label, s, nonceHex] of cases) {
      const r = await tryRecover(s, nonceHex);
      const rejected = !r.ok;
      if (unauthenticated) {
        step(rejected
          ? `${label}: gagal (HTTP ${r.status}) karena dekompresi/struktur, BUKAN karena autentikasi.`
          : `${label}: TIDAK terdeteksi (xchacha20 tanpa autentikasi).`, false);
        continue;
      }
      allGood &&= rejected;
      step(rejected
        ? `${label}: ditolak (HTTP ${r.status}). Tidak ada plaintext yang dirilis.`
        : `${label}: TIDAK ditolak, pelanggaran invarian!`, rejected);
    }
    if (unauthenticated) setBadge(badge, "warn", "xchacha20: tidak ada autentikasi");
    else setBadge(badge, allGood ? "ok" : "err", allGood ? "Semua manipulasi ditolak" : "FAIL");
    card.scrollIntoView({ behavior: "smooth", block: "nearest" });
  };

  const initPipeline = () => {
    const form = $("#pipeline-form"), results = $("#pipeline-results");
    if (!form) return;
    initTabs(form); initConditional(form); initRange(form); initKeybox(form); initDropzone(form); initSecrets(form);
    initCopy(results);
    form.addEventListener("submit", (e) => {
      e.preventDefault();
      const btn = $("[data-run]", form);
      busy(btn, async () => {
        results.setAttribute("aria-busy", "true");
        try {
          const keys = readKeyNonce(form);
          const input = await collectInput(form);
          const r = await api("/api/v1/pipeline/verify", pipelineBody(form, input, keys));
          renderPipeline(results, r);
          toast(r.parallel_path_exercised
            ? `Selesai: ${r.num_polyval_segments} segmen paralel, tag identik.`
            : "Selesai: jalur sekuensial (parallel_not_exercised).", "ok");
        } catch (err) {
          toast(err instanceof ApiError ? friendlyError(err) : err.message, "err", 6000);
        } finally {
          results.setAttribute("aria-busy", "false");
        }
      });
    });
    $("[data-tamper]", form).addEventListener("click", (e) => {
      busy(e.currentTarget, async () => {
        try { await runTamper(form, results); } catch (err) {
          toast(err instanceof ApiError ? friendlyError(err) : err.message, "err", 6000);
        }
      });
    });
  };

  // ---------- Equivalence page ----------
  const initEquivalence = () => {
    const form = $("#equiv-form"), results = $("#equiv-results");
    if (!form) return;
    initConditional(form);
    initCopy(results);
    form.addEventListener("submit", (e) => {
      e.preventDefault();
      busy($("[data-run]", form), async () => {
        try {
          const body = { segment_size: Number(form.elements.segment_size.value) };
          if (form.elements.source.value === "text") body.data_utf8 = form.elements.text.value;
          else body.data_hex = toHex(randomBytes(Number(form.elements.size.value)));
          const r = await api("/api/v1/verify-equivalence", body);
          showResult(results);
          const same = r.is_bit_identical && r.sequential_tag_hex === r.parallel_tag_hex;
          setBadge($("[data-equiv-badge]", results), same ? "ok" : "err", same ? "POLYVAL bit-identik" : "POLYVAL BERBEDA — FAIL");
          const multi = r.num_segments > 1;
          setBadge($("[data-parallel-badge]", results), multi ? "info" : "warn", multi ? `${r.num_segments} segmen digabung` : "parallel_not_exercised");
          setK(results, "size", fmtBytes(r.data_size_bytes));
          setK(results, "segments", fmtNum(r.num_segments));
          setK(results, "segment-size", `@ ${fmtBytes(r.segment_size_bytes)}`);
          setK(results, "threads", String(r.rayon_threads));
          setK(results, "algorithm", r.algorithm);
          setK(results, "seq", r.sequential_tag_hex);
          setK(results, "par", r.parallel_tag_hex);
          const m = Math.max(r.sequential_latency_micros, r.parallel_latency_micros, 1e-9);
          setWidth($('[data-bar="seq"]', results), (r.sequential_latency_micros / m) * 100);
          setWidth($('[data-bar="par"]', results), (r.parallel_latency_micros / m) * 100);
          setK(results, "seq-lat", fmtMicros(r.sequential_latency_micros));
          setK(results, "par-lat", fmtMicros(r.parallel_latency_micros));
          setK(results, "speedup-note", multi
            ? `Rasio indikatif ${r.speedup_ratio.toFixed(2)}× dari satu kali jalan (termasuk overhead penjadwalan). Untuk klaim speedup gunakan Criterion pada build release.`
            : "Hanya 1 segmen: jalur paralel tidak dijalankan, sehingga tidak ada klaim speedup.");
          toast(same ? "POLYVAL sekuensial dan paralel identik." : "Hasil berbeda!", same ? "ok" : "err");
        } catch (err) {
          toast(err instanceof ApiError ? friendlyError(err) : err.message, "err", 6000);
        }
      });
    });
  };

  // ---------- Benchmark page ----------
  const initBenchmark = () => {
    const btn = $("#bench-run"), results = $("#bench-results");
    if (!btn) return;
    let last = null;
    btn.addEventListener("click", () => busy(btn, async () => {
      try {
        toast("Benchmark berjalan, mohon tunggu…", "info", 3000);
        const rows = await api("/api/v1/benchmark");
        last = rows;
        showResult(results);
        const max = Math.max(...rows.flatMap((r) => [r.seq_throughput_mib_s, r.par_throughput_mib_s]), 1e-9);
        // One segment means the parallel path did not run: no speedup claim.
        const single = (r) => Math.ceil(r.payload_size_bytes / r.segment_size_bytes) <= 1;
        const speedup = (r) => (single(r) ? "parallel_not_exercised" : `${r.speedup_ratio.toFixed(2)}×`);
        $("[data-chart]", results).replaceChildren(...rows.map((r) => {
          const bar = (v, cls) => {
            const fill = h("span", { class: `bar-fill ${cls}` });
            setWidth(fill, (v / max) * 100);
            return h("div", { class: "bar" }, fill);
          };
          return h("div", { class: "chart-row" },
            h("div", { class: "chart-label" }, r.payload_size_label, h("small", { text: speedup(r) })),
            h("div", { class: "chart-bars" },
              bar(r.seq_throughput_mib_s, "fill-a"), h("span", { class: "chart-val", text: `seq ${r.seq_throughput_mib_s.toFixed(1)} MiB/s` }),
              bar(r.par_throughput_mib_s, "fill-b"), h("span", { class: "chart-val", text: `par ${r.par_throughput_mib_s.toFixed(1)} MiB/s` })));
        }));
        $("[data-rows]", results).replaceChildren(...rows.map((r) => h("tr", {},
          h("td", { text: r.payload_size_label }),
          h("td", { text: fmtBytes(r.segment_size_bytes) }),
          h("td", { text: String(r.rayon_threads) }),
          h("td", { text: String(r.iterations) }),
          h("td", { class: "num", text: r.seq_throughput_mib_s.toFixed(1) }),
          h("td", { class: "num", text: r.par_throughput_mib_s.toFixed(1) }),
          single(r)
            ? h("td", { class: "num" }, h("span", { class: "badge badge-warn", text: "parallel_not_exercised" }))
            : h("td", { class: "num", text: `${r.speedup_ratio.toFixed(2)}×` }),
          h("td", { class: "num", text: single(r) ? "—" : `${(r.parallel_efficiency * 100).toFixed(0)} %` }),
          h("td", {}, h("span", { class: `badge ${r.tag_equivalence_passed ? "badge-ok" : "badge-err"}`, text: r.tag_equivalence_passed ? "identik" : "FAIL" })))));
        toast("Benchmark selesai.", "ok");
      } catch (err) {
        toast(friendlyError(err), "err", 6000);
      }
    }));
    $("#bench-export")?.addEventListener("click", () => {
      if (!last) return;
      const blob = new Blob([JSON.stringify(last, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = h("a", { href: url, download: `polyval-benchmark-${Date.now()}.json` });
      document.body.append(a);
      a.click();
      a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    });
  };

  // ---------- Storage page ----------
  const initStorage = () => {
    const pub = $("#publish-form"), fetchForm = $("#fetch-form");
    if (!pub) return;
    initTabs(pub); initKeybox(pub); initDropzone(pub); initSecrets(document); initCopy(pub);
    let lastPublished = null; // in-memory only

    pub.addEventListener("submit", (e) => {
      e.preventDefault();
      busy($("[data-run]", pub), async () => {
        try {
          const id = pub.elements.stream_id;
          if (!/^[A-Za-z0-9._-]{1,128}$/.test(id.value)) {
            id.setAttribute("aria-invalid", "true");
            throw new Error("ID objek tidak valid.");
          }
          id.removeAttribute("aria-invalid");
          const keys = readKeyNonce(pub);
          const input = await collectInput(pub);
          const r = await api("/api/v1/ipfs/publish", { stream_id: id.value, ...input.data, ...keys });
          lastPublished = { root: r.root_cid, ...keys };
          const box = $("[data-result]", pub);
          box.hidden = false;
          setK(box, "root", r.root_cid);
          setK(box, "backend", r.backend_label);
          setK(box, "total", fmtBytes(r.manifest.total_size));
          setK(box, "count", fmtNum(r.manifest.blocks.length));
          $("[data-blocks]", box).replaceChildren(...r.manifest.blocks.map((b) =>
            h("li", {}, h("code", { text: b.cid }), ` · ${fmtBytes(b.size)}`)));
          toast(r.backend === "mock" ? "Dipublikasikan ke backend MOCK (bukan jaringan IPFS)." : "Dipublikasikan dan di-pin di node IPFS.", r.backend === "mock" ? "warn" : "ok", 5000);
        } catch (err) {
          toast(err instanceof ApiError ? friendlyError(err) : err.message, "err", 6000);
        }
      });
    });

    $("[data-use-fetch]", pub)?.addEventListener("click", () => {
      if (!lastPublished) return;
      fetchForm.elements.root_cid.value = lastPublished.root;
      fetchForm.elements.key_hex.value = lastPublished.key_hex;
      fetchForm.elements.nonce_hex.value = lastPublished.nonce_hex;
      fetchForm.scrollIntoView({ behavior: "smooth", block: "start" });
      fetchForm.elements.root_cid.focus({ preventScroll: true });
    });

    fetchForm.addEventListener("submit", (e) => {
      e.preventDefault();
      const out = $("[data-result]", fetchForm), errBox = $("[data-error]", fetchForm);
      busy($("[data-run]", fetchForm), async () => {
        out.hidden = true;
        errBox.hidden = true;
        try {
          const root = fetchForm.elements.root_cid.value.trim();
          if (!root) throw new Error("Masukkan root CID.");
          const keys = readKeyNonce(fetchForm);
          const r = await api("/api/v1/ipfs/fetch", { root_cid: root, ...keys });
          out.hidden = false;
          setK(out, "size", fmtBytes(r.recovered_size_bytes));
          const PREVIEW = 4000;
          if (r.recovered_utf8 != null) {
            setK(out, "preview-label", "Pratinjau UTF-8");
            setK(out, "preview", r.recovered_utf8.length > PREVIEW ? `${r.recovered_utf8.slice(0, PREVIEW)}\n…` : r.recovered_utf8);
          } else {
            setK(out, "preview-label", "Pratinjau hex (biner)");
            setK(out, "preview", r.recovered_hex.slice(0, PREVIEW) + (r.recovered_hex.length > PREVIEW ? "…" : ""));
          }
          toast("Blok terverifikasi, tag valid, data dipulihkan.", "ok");
        } catch (err) {
          const msg = err instanceof ApiError ? friendlyError(err) : err.message;
          errBox.textContent = msg;
          errBox.hidden = false;
          toast(msg, "err", 6000);
        }
      });
    });

    // WASM Verified-Fetch & Client-Side Decrypt Console
    const wasmForm = $("#wasm-fetch-form");
    if (wasmForm) {
      const logsBox = $("#wasm-logs-box");
      const logsPre = $("#wasm-verification-logs");
      const resBox = $("#wasm-result-box");
      const errBox = $("#wasm-error-callout");
      const previewText = $("#wasm-preview-text");
      const dlLink = $("#wasm-download-link");
      const gwSelect = $("#wasm-gateway-select");
      const rawBtn = $("#wasm-raw-btn");

      const log = (msg) => {
        logsBox.hidden = false;
        const ts = new Date().toISOString().substring(11, 23);
        logsPre.textContent += `[${ts}] ${msg}\n`;
        logsPre.scrollTop = logsPre.scrollHeight;
      };

      const runWasmFetch = async (isRawOnly = false) => {
        logsBox.hidden = false;
        logsPre.textContent = "";
        resBox.hidden = true;
        errBox.hidden = true;

        const rootCid = wasmForm.elements.wasm_root_cid.value.trim();
        if (!rootCid) throw new Error("Masukkan Root CID.");

        const keyHex = wasmForm.elements.wasm_key_hex.value.trim();
        const nonceHex = wasmForm.elements.wasm_nonce_hex.value.trim();
        const gateway = gwSelect ? gwSelect.value : "http://127.0.0.1:8080/ipfs/";

        log(`Memulai WASM Verified-Fetch untuk Root CID: ${rootCid}`);
        log(`Gateway target: ${gateway}`);

        const wasm = await loadWasmModule();
        log("[WASM] Modul WebAssembly siap (SHA2-256 + AES-GCM-SIV + Zstd).");

        // Step 1: Fetch raw root block
        const rootUrl = `${gateway.replace(/\/+$/, "")}/${rootCid}?format=raw`;
        log(`[Fetch] Mengambil blok root mentah: ${rootUrl}`);
        const resp = await fetch(rootUrl, { headers: { Accept: "application/vnd.ipld.raw" } });
        if (!resp.ok) {
          throw new Error(`Gagal mengambil blok root dari gateway (HTTP ${resp.status})`);
        }
        const rootBuf = await resp.arrayBuffer();
        const rootBytes = new Uint8Array(rootBuf);
        log(`[Fetch] Diterima ${fmtBytes(rootBytes.length)} bytes.`);

        // Step 2: Verify root block multihash
        log(`[WASM] Menghitung SHA2-256 multihash pada blok root...`);
        const isValid = await verifyBlockWithWasm(wasm, rootBytes, rootCid);
        if (!isValid) {
          throw new Error(`[KRITIS] Verifikasi digest SHA2-256 GAGAL untuk root CID ${rootCid}. Data rusak atau dimanipulasi!`);
        }
        log(`[WASM] ✓ Verifikasi integritas Root CID BERHASIL (SHA2-256 cocok).`);

        if (isRawOnly) {
          resBox.hidden = false;
          previewText.textContent = `[Raw Block Verified]\nUkuran: ${fmtBytes(rootBytes.length)}\nCID: ${rootCid}`;
          const blob = new Blob([rootBytes], { type: "application/octet-stream" });
          dlLink.href = URL.createObjectURL(blob);
          dlLink.download = `${rootCid}.bin`;
          toast("Raw block berhasil diverifikasi via WASM.", "ok");
          return;
        }

        // Step 3: Check if root block is DAG-JSON manifest
        let manifest = null;
        try {
          manifest = parseManifestWithWasm(wasm, rootBytes);
          log(`[WASM] Terdeteksi DAG-JSON manifest: ID="${manifest.object_id}", total_size=${fmtBytes(manifest.total_size)}, ${manifest.blocks.length} blok.`);
        } catch (_) {
          log("[WASM] Blok tunggal (bukan DAG-JSON manifest).");
        }

        let combinedPayload = rootBytes;
        if (manifest && manifest.blocks && manifest.blocks.length > 0) {
          const chunkBuffers = [];
          for (let i = 0; i < manifest.blocks.length; i++) {
            const b = manifest.blocks[i];
            log(`[Fetch] Mengambil chunk ${i + 1}/${manifest.blocks.length}: ${b.cid} (${fmtBytes(b.size)})...`);
            const chunkUrl = `${gateway.replace(/\/+$/, "")}/${b.cid}?format=raw`;
            const chunkResp = await fetch(chunkUrl, { headers: { Accept: "application/vnd.ipld.raw" } });
            if (!chunkResp.ok) throw new Error(`Gagal mengambil chunk ${b.cid}`);
            const chunkBytes = new Uint8Array(await chunkResp.arrayBuffer());

            log(`[WASM] Verifikasi multihash chunk ${i + 1}...`);
            const chunkValid = await verifyBlockWithWasm(wasm, chunkBytes, b.cid);
            if (!chunkValid) {
              throw new Error(`[KRITIS] Verifikasi multihash GAGAL pada chunk ${b.cid}`);
            }
            log(`[WASM] ✓ Chunk ${i + 1} valid.`);
            chunkBuffers.push(chunkBytes);
          }

          let totalLen = chunkBuffers.reduce((sum, c) => sum + c.length, 0);
          combinedPayload = new Uint8Array(totalLen);
          let offset = 0;
          for (const buf of chunkBuffers) {
            combinedPayload.set(buf, offset);
            offset += buf.length;
          }
          log(`[WASM] Rekonstruksi ${chunkBuffers.length} blok menjadi payload ${fmtBytes(combinedPayload.length)}.`);
        }

        // Step 4: Client-side Decryption & Decompression if key/nonce provided
        let finalOutput = combinedPayload;
        let isDecrypted = false;
        if (keyHex && nonceHex) {
          log(`[WASM] Menjalankan dekripsi AES-256-GCM-SIV & dekompresi Zstd di peramban...`);
          finalOutput = decryptDecompressWithWasm(wasm, combinedPayload, keyHex, nonceHex);
          isDecrypted = true;
          log(`[WASM] ✓ Tag AEAD valid! Plaintext terotentikasi & terdekompresi (${fmtBytes(finalOutput.length)}).`);
        } else {
          log(`[Info] Kunci/nonce tidak diisi; menampilkan payload ciphertext terverifikasi (${fmtBytes(combinedPayload.length)}).`);
        }

        resBox.hidden = false;
        const blob = new Blob([finalOutput], { type: "application/octet-stream" });
        dlLink.href = URL.createObjectURL(blob);
        dlLink.download = isDecrypted ? (manifest ? manifest.object_id : "decrypted-object.bin") : `${rootCid}.enc`;

        const decoder = new TextDecoder("utf-8", { fatal: false });
        const textSample = decoder.decode(finalOutput.slice(0, 4000));
        previewText.textContent = textSample + (finalOutput.length > 4000 ? "\n… [dipotong]" : "");

        toast(isDecrypted ? "Data IPFS terverifikasi & terdekripsi via WASM!" : "Data IPFS terverifikasi via WASM!", "ok");
      };

      wasmForm.addEventListener("submit", (e) => {
        e.preventDefault();
        busy($("[data-run]", wasmForm), async () => {
          try {
            await runWasmFetch(false);
          } catch (err) {
            errBox.textContent = err.message;
            errBox.hidden = false;
            toast(err.message, "err", 6000);
          }
        });
      });

      rawBtn?.addEventListener("click", () => {
        busy(rawBtn, async () => {
          try {
            await runWasmFetch(true);
          } catch (err) {
            errBox.textContent = err.message;
            errBox.hidden = false;
            toast(err.message, "err", 6000);
          }
        });
      });
    }
  };

  // ---------- Secure Vault page ----------
  // Without a metadata store, CID + nonce are enough to download an object, so the list
  // stays in this tab's memory. With one (data-catalog: logged in + PostgreSQL), the list
  // comes from the server and downloads are owner-checked with the stored nonce.
  const initVault = () => {
    const up = $("#vault-upload"), dl = $("#vault-fetch"), list = $("#vault-list");
    if (!up) return;
    initDropzone(up); initCopy(up);
    const persistent = list.hasAttribute("data-catalog");
    const objects = [];
    // Bearer token (only when the server requires one): DOM input + request headers only.
    const tokenInput = $("#vault-token");
    if (tokenInput) {
      initSecrets($("#vault-auth"));
      const state = $("[data-token-state]");
      tokenInput.addEventListener("input", () => {
        state.textContent = tokenInput.value.trim() ? "Diisi · hanya di memori tab" : "Belum diisi";
      });
    }
    const authHeaders = () => {
      if (!tokenInput) return {};
      const t = tokenInput.value.trim();
      if (!t) {
        tokenInput.setAttribute("aria-invalid", "true");
        tokenInput.focus();
        throw new Error("Isi token API terlebih dahulu.");
      }
      tokenInput.removeAttribute("aria-invalid");
      return { Authorization: `Bearer ${t}` };
    };
    const ID_RE = /^[A-Za-z0-9._-]{1,128}$/;
    const toId = (name) => {
      const id = name.replace(/[^A-Za-z0-9._-]/g, "_").slice(0, 128);
      return ID_RE.test(id) ? id : "upload.bin";
    };
    const planText = (p) => !p ? "—" : p.execution === "parallel"
      ? `paralel · ${fmtNum(p.segments)} segmen × ${fmtBytes(p.segment_bytes)}`
      : `sekuensial (${p.reason ?? "fallback"})`;

    const upload = (file, id, auth, onProgress) => new Promise((resolve, reject) => {
      const x = new XMLHttpRequest();
      x.open("POST", "/api/v1/objects/upload");
      for (const [k, v] of Object.entries(auth)) x.setRequestHeader(k, v);
      x.setRequestHeader("Content-Type", "application/octet-stream");
      x.setRequestHeader("X-Object-Id", id);
      x.responseType = "json";
      x.upload.addEventListener("progress", (e) => { if (e.lengthComputable) onProgress((e.loaded / e.total) * 100); });
      x.addEventListener("load", () => {
        const d = x.response;
        if (x.status >= 200 && x.status < 300 && d) resolve(d);
        else reject(new ApiError((d && d.error) || `HTTP ${x.status}`, x.status));
      });
      x.addEventListener("error", () => reject(new ApiError("Server tidak dapat dihubungi.", 0)));
      x.send(file);
    });

    // The server sends the body only after the tag verified; a non-2xx is a JSON error.
    const download = async (cid, nonce, fallbackName) => {
      const headers = authHeaders();
      let res;
      const query = nonce ? `?nonce=${encodeURIComponent(nonce)}` : "";
      try {
        res = await fetch(`/api/v1/objects/${encodeURIComponent(cid)}${query}`, { headers, cache: "no-store", credentials: "same-origin" });
      } catch (_) {
        throw new ApiError("Server tidak dapat dihubungi.", 0);
      }
      if (!res.ok) {
        let d = null;
        try { d = await res.json(); } catch (_) { /* non-JSON */ }
        throw new ApiError((d && d.error) || `HTTP ${res.status}`, res.status);
      }
      const blob = await res.blob();
      const name = /filename="([A-Za-z0-9._-]{1,128})"/.exec(res.headers.get("Content-Disposition") || "")?.[1] || fallbackName || "object.bin";
      const url = URL.createObjectURL(blob);
      const a = h("a", { href: url, download: name });
      document.body.append(a);
      a.click();
      a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
      return { name, size: blob.size, plan: res.headers.get("X-Encryption-Plan"), timing: res.headers.get("Server-Timing") };
    };

    const toRow = (r) => ({ id: r.object_id, cid: r.ipfs_cid, nonce: r.nonce_hex, size: r.original_size_bytes, plan: planText(r.encryption_plan), backend: r.backend });

    const render = () => {
      $("[data-empty]", list).hidden = objects.length > 0;
      $("[data-table]", list).hidden = objects.length === 0;
      $("[data-rows]", list).replaceChildren(...objects.map((o, i) => h("tr", {},
        h("td", { text: o.backend === "mock" ? `${o.id} (mock)` : o.id }),
        h("td", { class: "num", text: fmtBytes(o.size) }),
        h("td", { text: o.plan }),
        h("td", {}, h("code", { class: "mono", title: o.cid, text: `${o.cid.slice(0, 14)}…${o.cid.slice(-6)}` })),
        h("td", {},
          h("button", { type: "button", class: "btn btn-sm btn-primary", "data-act": "get", "data-i": String(i), text: "Unduh" }), " ",
          h("button", { type: "button", class: "btn btn-sm btn-ghost", "data-act": "tamper", "data-i": String(i), text: "Uji nonce salah" }), " ",
          h("button", { type: "button", class: "btn btn-sm btn-ghost", "data-act": "fill", "data-i": String(i), text: "Isi formulir" })))));
    };

    const fileInput = $('input[type="file"]', up);
    fileInput.addEventListener("change", () => {
      if (fileInput.files[0] && !up.elements.object_id.value) up.elements.object_id.value = toId(fileInput.files[0].name);
    });
    $("[data-dropzone]", up).addEventListener("drop", (e) => {
      const f = e.dataTransfer?.files?.[0];
      if (f && !up.elements.object_id.value) up.elements.object_id.value = toId(f.name);
    });

    up.addEventListener("submit", (e) => {
      e.preventDefault();
      busy($("[data-run]", up), async () => {
        const bar = $("[data-progress]", up), fill = $(".bar-fill", bar);
        try {
          const file = up._file;
          if (!file) throw new Error("Pilih berkas terlebih dahulu.");
          const idEl = up.elements.object_id;
          const id = idEl.value.trim() || toId(file.name);
          if (!ID_RE.test(id)) { idEl.setAttribute("aria-invalid", "true"); throw new Error("ID objek tidak valid."); }
          idEl.removeAttribute("aria-invalid");
          const auth = authHeaders();
          bar.hidden = false;
          setWidth(fill, 0);
          const r = await upload(file, id, auth, (pct) => { setWidth(fill, pct); bar.setAttribute("aria-valuenow", String(Math.round(pct))); });
          const box = $("[data-result]", up);
          box.hidden = false;
          setK(box, "cid", r.ipfs_cid);
          setK(box, "nonce", r.nonce_hex);
          setK(box, "sizes", `${fmtBytes(r.original_size_bytes)} → ${fmtBytes(r.compressed_size_bytes)}`);
          setK(box, "plan", planText(r.encryption_plan));
          setK(box, "timing", `zstd ${r.compression_ms.toFixed(1)} ms · enkripsi ${r.encryption_ms.toFixed(1)} ms · publish ${r.publish_ms.toFixed(1)} ms`);
          setK(box, "backend", `${r.backend_label} · ${fmtNum(r.ipfs_blocks)} blok`);
          objects.unshift(toRow(r));
          render();
          toast(r.backend === "mock" ? "Terenkripsi dan disimpan di backend MOCK (bukan jaringan IPFS)." : "Terenkripsi dan di-pin di node IPFS.", r.backend === "mock" ? "warn" : "ok", 5000);
        } catch (err) {
          toast(err instanceof ApiError ? friendlyError(err) : err.message, "err", 6000);
        } finally {
          setTimeout(() => { bar.hidden = true; }, 800);
        }
      });
    });

    const runDownload = async (cid, nonce, name) => {
      const ok = $("[data-ok]", dl), errBox = $("[data-error]", dl);
      ok.hidden = true;
      errBox.hidden = true;
      try {
        const r = await download(cid, nonce, name);
        ok.textContent = `Tag AEAD valid → ${r.name} (${fmtBytes(r.size)}) diunduh. Rencana: ${r.plan ?? "—"} · ${r.timing ?? ""}`;
        ok.hidden = false;
        toast("Tag terverifikasi; berkas dirilis.", "ok");
      } catch (err) {
        const msg = err instanceof ApiError ? friendlyError(err) : err.message;
        errBox.textContent = `${msg}${err instanceof ApiError && err.status ? ` (HTTP ${err.status})` : ""}`;
        errBox.hidden = false;
        toast(msg, "err", 6000);
      }
    };

    dl.addEventListener("submit", (e) => {
      e.preventDefault();
      const cid = dl.elements.cid.value.trim(), nonce = dl.elements.nonce_hex.value.trim().toLowerCase();
      const nonceOk = isHex(nonce, 12) || (persistent && nonce === "");
      dl.elements.nonce_hex.setAttribute("aria-invalid", String(!nonceOk));
      if (!cid || !nonceOk) { toast(persistent ? "Isi root CID (nonce opsional, 24 digit hex)." : "Isi root CID dan nonce 24 digit hex.", "err"); return; }
      busy($("[data-run]", dl), () => runDownload(cid, nonce));
    });

    list.addEventListener("click", (e) => {
      const btn = e.target.closest("[data-act]");
      const o = btn && objects[Number(btn.dataset.i)];
      if (!o) return;
      if (btn.dataset.act === "fill") {
        dl.elements.cid.value = o.cid;
        dl.elements.nonce_hex.value = o.nonce;
        dl.scrollIntoView({ behavior: "smooth", block: "start" });
        return;
      }
      // Persistent mode: "Unduh" sends no nonce, so the server uses the stored one.
      let nonce = persistent ? "" : o.nonce;
      if (btn.dataset.act === "tamper") nonce = o.nonce.slice(0, -1) + (parseInt(o.nonce.slice(-1), 16) ^ 1).toString(16);
      busy(btn, () => runDownload(o.cid, nonce, o.id));
    });
    render();
    if (persistent) {
      api("/api/v1/vault/objects")
        .then((d) => { objects.push(...d.objects.map(toRow)); render(); })
        .catch((err) => toast(err instanceof ApiError ? friendlyError(err) : err.message, "err", 6000));
    }
  };

  // ---------- Account page (login / profile / logout) ----------
  // The session token lives only in an HttpOnly cookie; JS never sees it.
  const encryptAuthPayload = async (data) => {
    if (!window.crypto || !window.crypto.subtle) return data;
    try {
      const rawKey = window.crypto.getRandomValues(new Uint8Array(32));
      const iv = window.crypto.getRandomValues(new Uint8Array(16));
      const key = await window.crypto.subtle.importKey(
        "raw",
        rawKey,
        { name: "AES-CTR" },
        false,
        ["encrypt"]
      );
      const plain = new TextEncoder().encode(
        JSON.stringify({ ...data, timestamp: Date.now() })
      );
      const encrypted = await window.crypto.subtle.encrypt(
        { name: "AES-CTR", counter: iv, length: 64 },
        key,
        plain
      );
      return {
        encrypted: true,
        key: toHex(rawKey),
        iv: toHex(iv),
        ciphertext: toHex(new Uint8Array(encrypted)),
      };
    } catch (_) {
      return data;
    }
  };

  const initAccount = () => {
    const form = $("#login-form"), profile = $("#account-profile");
    const showErr = (root, e) => {
      const box = $("[data-error]", root);
      box.textContent = friendlyError(e);
      box.hidden = false;
    };
    if (form) {
      initSecrets(form);
      form.addEventListener("submit", (ev) => {
        ev.preventDefault();
        const username = form.elements.username.value.trim();
        const password = form.elements.password.value;
        if (!username || !password) { showErr(form, new ApiError("Isi nama pengguna dan kata sandi.", 0)); return; }
        busy($("[data-run]", form), async () => {
          try {
            const payload = await encryptAuthPayload({ username, password });
            await api("/api/v1/auth/login", payload);
            const next = form.dataset.next || new URLSearchParams(window.location.search).get("next");
            if (next && next.startsWith("/") && !next.startsWith("//")) {
              window.location.href = next;
            } else {
              window.location.href = "/status";
            }
          } catch (e) {
            form.elements.password.value = "";
            showErr(form, e);
          }
        });
      });
    }
    if (profile) {
      const set = (k, v) => { const el = $(`[data-k="${k}"]`, profile); if (el) el.textContent = v; };
      const when = (unix) => unix ? new Date(unix * 1000).toLocaleString("id-ID") : "—";
      api("/api/v1/auth/me").then((d) => {
        set("email", d.email ?? "—");
        set("national_id", d.national_id ?? "—");
        set("created", when(d.created_at_unix));
        set("session", when(d.session_created_unix));
      }).catch((e) => showErr(profile, e));
      const out = $("[data-logout]", profile);
      out?.addEventListener("click", () => busy(out, async () => {
        try {
          await api("/api/v1/auth/logout", {});
          window.location.href = "/login";
        } catch (e) { showErr(profile, e); }
      }));
    }
  };

  // ---------- Settings page ----------
  const initSettings = () => {
    const toggle = $("#settings-theme-toggle");
    if (!toggle) return;
    toggle.addEventListener("click", () => {
      const themeBtn = $("#theme-btn");
      if (themeBtn) {
        themeBtn.click();
        const mode = document.documentElement.dataset.theme === "dark" ? "gelap" : "terang";
        toast(`Tema visual dialihkan ke mode ${mode}.`, "ok", 2000);
      }
    });
  };

  // ---------- RuKubo private supervisor ----------
  const initRukubo = () => {
    const btn = $("#rukubo-start");
    if (!btn) return;
    const message = $("#rukubo-message");
    btn.addEventListener("click", () => busy(btn, async () => {
      try {
        const status = await api("/api/v1/rukubo/start", {});
        $("#rukubo-state")?.replaceChildren(document.createTextNode(status.running ? "RUNNING" : "STOPPED"));
        const pid = $("#rukubo-pid");
        if (pid) pid.textContent = status.managed_pid ?? "—";
        if (message) message.textContent = "Kubo private dijalankan oleh supervisor Rust.";
        btn.disabled = true;
      } catch (e) {
        if (message) message.textContent = e.message || "Kubo private tidak dapat dimulai.";
        throw e;
      }
    }));
  };

  document.addEventListener("DOMContentLoaded", () => {
    initServiceWorker();
    initAccount();
    initShell();
    initSettings();
    initPipeline();
    initEquivalence();
    initBenchmark();
    initStorage();
    initVault();
    initRukubo();
  });
})();
