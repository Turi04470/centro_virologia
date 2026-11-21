(() => {
  "use strict";

  const STORAGE_THEME = "cs_web_theme_v1";
  const STORAGE_CONSULTAS_VIEW = "cs_web_consultas_view_v1";

  const state = {
    action: "encrypt",
    mode: "text",
    algorithms: [],
    consultas: [],
    consultasFilter: "all",
    consultasLayout: localStorage.getItem(STORAGE_CONSULTAS_VIEW) || "table",
    requests: [],
    drawerItem: null,
    lastInspector: {
      algo: "AES-256-GCM",
      cells: Array.from({ length: 16 }, (_, i) => i.toString(16).padStart(2, "0").toUpperCase()),
      steps: ["Esperando operación"]
    },
    fileBase64: null,
    fileName: "",
    fileSize: 0,
    lastResponse: null,
    lsbImageLoaded: false,
    lsbHasOutputImage: false
  };

  const $ = (sel) => document.querySelector(sel);
  const $$ = (sel) => Array.from(document.querySelectorAll(sel));

  async function api(url, options = {}) {
    const resp = await fetch(url, options);
    const contentType = resp.headers.get("content-type") || "";
    const data = contentType.includes("application/json") ? await resp.json() : null;
    if (!resp.ok) {
      throw new Error(data?.error || `HTTP ${resp.status}`);
    }
    return data;
  }

  // --- Theme ---
  function initTheme() {
    const saved = localStorage.getItem(STORAGE_THEME) || "dark";
    applyTheme(saved);
    $("#themeToggle").addEventListener("click", () => {
      const next = document.documentElement.getAttribute("data-theme") === "dark" ? "light" : "dark";
      applyTheme(next);
      localStorage.setItem(STORAGE_THEME, next);
    });
  }

  function applyTheme(theme) {
    document.documentElement.setAttribute("data-theme", theme);
    $("#iconSun").classList.toggle("hidden", theme === "dark");
    $("#iconMoon").classList.toggle("hidden", theme === "light");
  }

  // --- Navigation ---
  function initNav() {
    $$(".nav-tab").forEach((btn) => {
      btn.addEventListener("click", () => {
        $$(".nav-tab").forEach((b) => b.classList.remove("active"));
        btn.classList.add("active");
        const target = btn.dataset.view;
        $$(".view").forEach((v) => v.classList.remove("active"));
        $(`#view-${target}`).classList.add("active");
        if (target === "consultas") refreshConsultas();
        if (target === "solicitudes") refreshRequests();
      });
    });
  }

  // --- Algorithms Config & Sync ---
  async function refreshAlgorithms() {
    state.algorithms = await api("/api/config/algorithms");
    renderSettings($("#settingsSearch")?.value || "");
    syncVisibleAlgorithms();
  }

  function syncVisibleAlgorithms() {
    const visible = state.algorithms.filter((a) => a.isVisible);
    const sel = $("#algoSelect");
    const prev = sel.value;
    sel.innerHTML = "";

    visible.forEach((a) => {
      const opt = document.createElement("option");
      opt.value = a.code;
      opt.textContent = a.name;
      sel.appendChild(opt);
    });

    const hasAny = visible.length > 0;
    $("#noAlgosNotice").classList.toggle("hidden", hasAny);
    $("#operateBody").classList.toggle("hidden", !hasAny);
    $("#operateFooter").classList.toggle("hidden", !hasAny);

    if (hasAny) {
      sel.value = visible.some((a) => a.code === prev) ? prev : visible[0].code;
    }
    syncActionButtons();
  }

  function syncActionButtons() {
    const code = $("#algoSelect").value;
    const algo = state.algorithms.find((a) => a.code === code);
    const isEnc = state.action === "encrypt";
    const btn = $("#submitBtn");
    btn.textContent = isEnc ? "Cifrar" : "Descifrar";
    btn.disabled = !algo || !algo.isVisible || (isEnc ? !algo.canEncrypt : !algo.canDecrypt);
  }

  // --- Settings ---
  function initSettings() {
    $("#settingsSearch").addEventListener("input", (e) => renderSettings(e.target.value));
    $$(".preset-btn").forEach((btn) => {
      btn.addEventListener("click", async () => {
        if (btn.dataset.preset === "hideAll") {
          state.algorithms = await api("/api/config/algorithms/hide-all", { method: "POST" });
          renderSettings($("#settingsSearch").value);
          syncVisibleAlgorithms();
          toast("Algoritmos ocultos");
        }
      });
    });
  }

  function renderSettings(filter = "") {
    const body = $("#settingsBody");
    const q = filter.trim().toLowerCase();
    body.innerHTML = "";

    state.algorithms
      .filter((a) => !q || a.name.toLowerCase().includes(q) || a.category.toLowerCase().includes(q) || a.code.toLowerCase().includes(q))
      .forEach((algo) => {
        const tr = document.createElement("tr");
        tr.innerHTML = `
          <td><strong>${algo.name}</strong> <span class="meta-count" style="margin-left:6px;">${algo.code}</span></td>
          <td><span class="cat-pill">${algo.category}</span></td>
          <td class="td-center">${switchHtml(algo.code, "isVisible", algo.isVisible)}</td>
          <td class="td-center">${switchHtml(algo.code, "canEncrypt", algo.canEncrypt)}</td>
          <td class="td-center">${switchHtml(algo.code, "canDecrypt", algo.canDecrypt)}</td>
        `;
        body.appendChild(tr);
      });

    body.querySelectorAll("input[data-algo]").forEach((chk) => {
      chk.addEventListener("change", async (e) => {
        const { algo: code, field } = e.target.dataset;
        const target = state.algorithms.find((a) => a.code === code);
        if (!target) return;
        target[field] = e.target.checked;
        try {
          const updated = await api(`/api/config/algorithms/${encodeURIComponent(code)}`, {
            method: "PUT",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              isVisible: target.isVisible,
              canEncrypt: target.canEncrypt,
              canDecrypt: target.canDecrypt
            })
          });
          Object.assign(target, updated);
          syncVisibleAlgorithms();
        } catch (err) {
          toast(err.message);
        }
      });
    });
  }

  function switchHtml(code, field, checked) {
    return `
      <label class="switch">
        <input type="checkbox" data-algo="${code}" data-field="${field}" ${checked ? "checked" : ""} />
        <span class="slider"></span>
      </label>
    `;
  }

  // --- Operate ---
  function showInputState() {
    $("#inputState").classList.remove("hidden");
    $("#outputState").classList.add("hidden");
  }

  function showOutputState(originalPreview, resultText) {
    $("#outputOriginalPreview").textContent = `Original: ${originalPreview}`;
    $("#outputBody").textContent = resultText;
    $("#inputState").classList.add("hidden");
    $("#outputState").classList.remove("hidden");
  }

  function initOperate() {
    $$("#actionModeGroup .seg-pill").forEach((btn) => {
      btn.addEventListener("click", () => {
        $$("#actionModeGroup .seg-pill").forEach((b) => b.classList.remove("active"));
        btn.classList.add("active");
        state.action = btn.dataset.action;
        syncActionButtons();
      });
    });

    $$("#inputModeGroup .seg-pill").forEach((btn) => {
      btn.addEventListener("click", () => {
        $$("#inputModeGroup .seg-pill").forEach((b) => b.classList.remove("active"));
        btn.classList.add("active");
        state.mode = btn.dataset.mode;
        $("#textInputPane").classList.toggle("hidden", state.mode !== "text");
        $("#fileInputPane").classList.toggle("hidden", state.mode !== "file");
        $("#lsbInputPane").classList.toggle("hidden", state.mode !== "lsb");
        $("#lsbOutCanvas").classList.toggle("visible", state.mode === "lsb" && state.lsbHasOutputImage);
        showInputState();
        if (state.mode === "lsb" && state.algorithms.some((a) => a.code === "LSBSTEGO" && a.isVisible)) {
          $("#algoSelect").value = "LSBSTEGO";
          syncActionButtons();
        }
        updateInputMeta();
      });
    });

    $("#advToggleBtn").addEventListener("click", () => $("#advancedDrawer").classList.toggle("hidden"));
    $("#editInputBtn").addEventListener("click", showInputState);
    $("#resetBtn").addEventListener("click", clearOperate);
    $("#clearBtn").addEventListener("click", clearOperate);

    $("#algoSelect").addEventListener("change", () => {
      syncActionButtons();
    });

    $("#genKeyBtn").addEventListener("click", () => {
      const code = $("#algoSelect").value;
      if (code === "CAESAR") $("#keyInput").value = String(Math.floor(Math.random() * 24) + 1);
      else if (code === "EUCLIDESAFFINE") {
        const coprimes = [3, 5, 7, 9, 11, 15, 17, 19, 25];
        $("#keyInput").value = `a=${coprimes[Math.floor(Math.random() * coprimes.length)]},b=${Math.floor(Math.random() * 200) + 1}`;
      } else {
        const rnd = new Uint8Array(8);
        crypto.getRandomValues(rnd);
        $("#keyInput").value = Array.from(rnd, (b) => b.toString(16).padStart(2, "0")).join("");
      }
      toast("Clave generada");
    });

    $("#inputText").addEventListener("input", updateInputMeta);

    const drop = $("#fileDropzone");
    drop.addEventListener("dragover", (e) => { e.preventDefault(); drop.classList.add("dragover"); });
    drop.addEventListener("dragleave", () => drop.classList.remove("dragover"));
    drop.addEventListener("drop", (e) => {
      e.preventDefault();
      drop.classList.remove("dragover");
      if (e.dataTransfer.files[0]) loadGenericFile(e.dataTransfer.files[0]);
    });
    $("#fileInput").addEventListener("change", (e) => {
      if (e.target.files[0]) loadGenericFile(e.target.files[0]);
    });
    $("#lsbImageInput").addEventListener("change", (e) => {
      if (e.target.files[0]) loadLsbImage(e.target.files[0]);
    });

    $("#submitBtn").addEventListener("click", () => runOperation(state.action === "encrypt"));
    $("#copyBtn").addEventListener("click", () => {
      const txt = $("#outputBody").textContent;
      if (!txt) return;
      navigator.clipboard?.writeText(txt);
      toast("Copiado");
    });
    $("#downloadBtn").addEventListener("click", downloadOutput);
  }

  function updateInputMeta() {
    if (state.mode === "text") {
      $("#inMeta").textContent = `${new TextEncoder().encode($("#inputText").value).length} B`;
    } else if (state.mode === "file") {
      $("#inMeta").textContent = `${state.fileSize} B`;
    } else {
      $("#inMeta").textContent = state.lsbImageLoaded ? $("#lsbCapacity").textContent : "0 B";
    }
  }

  function loadGenericFile(file) {
    const r = new FileReader();
    r.onload = () => {
      const bytes = new Uint8Array(r.result);
      state.fileBase64 = bytesToBase64(bytes);
      state.fileName = file.name;
      state.fileSize = bytes.length;
      $("#fileName").textContent = file.name;
      $("#fileInfo").textContent = `${bytes.length} bytes`;
      updateInputMeta();
    };
    r.readAsArrayBuffer(file);
  }

  function loadLsbImage(file) {
    const url = URL.createObjectURL(file);
    const img = new Image();
    img.onload = () => {
      const canvas = $("#lsbSourceCanvas");
      canvas.width = img.width;
      canvas.height = img.height;
      canvas.getContext("2d").drawImage(img, 0, 0);
      canvas.classList.add("visible");
      const cap = Math.floor((img.width * img.height * 3) / 8) - 8;
      $("#lsbImageName").textContent = file.name;
      $("#lsbCapacity").textContent = `${Math.max(0, cap)} B cap`;
      state.lsbImageLoaded = true;
      updateInputMeta();
      URL.revokeObjectURL(url);
    };
    img.src = url;
  }

  function clearOperate() {
    $("#inputText").value = "";
    $("#outputBody").textContent = "";
    $("#lsbSecretInput").value = "";
    $("#outHash").textContent = "SHA-256: —";
    state.fileBase64 = null;
    state.fileName = "";
    state.fileSize = 0;
    state.lastResponse = null;
    state.lsbHasOutputImage = false;
    $("#fileName").textContent = "Archivo";
    $("#fileInfo").textContent = "—";
    $("#lsbOutCanvas").classList.remove("visible");
    showInputState();
    updateInputMeta();
  }

  async function runOperation(isEncrypt) {
    const code = $("#algoSelect").value;
    const algo = state.algorithms.find((a) => a.code === code);
    if (!algo || !algo.isVisible) return toast("Algoritmo oculto");
    if (isEncrypt && !algo.canEncrypt) return toast("Cifrado deshabilitado");
    if (!isEncrypt && !algo.canDecrypt) return toast("Descifrado deshabilitado");

    if (state.mode === "lsb" && state.lsbImageLoaded) {
      runCanvasLsb(isEncrypt, algo);
      return;
    }

    const payload = {
      algorithmCode: code,
      isEncrypt,
      inputMode: state.mode === "file" ? "file" : "text",
      text: state.mode === "text" ? $("#inputText").value : null,
      fileBase64: state.mode === "file" ? state.fileBase64 : null,
      fileName: state.mode === "file" ? state.fileName : "mensaje.txt",
      key: $("#keyInput").value.trim(),
      attachCertificate: $("#attachCertToggle").checked
    };

    try {
      const res = await api("/api/crypto/operate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
      });

      state.lastResponse = res;
      state.lsbHasOutputImage = false;
      $("#lsbOutCanvas").classList.remove("visible");
      $("#outHash").textContent = `SHA-256: ${res.sha256.slice(0, 12)}…`;

      const display = state.mode === "file"
        ? `[${res.outputFileName}] (${res.zipFileName || "Sin .ZIP"})`
        : (res.outputText || "");
      const preview = state.mode === "file" ? `${state.fileName} (${state.fileSize} B)` : $("#inputText").value.slice(0, 60);
      showOutputState(preview, display);

      state.lastInspector = { algo: res.algorithmName, cells: res.cells, steps: res.steps };
      renderInspector();
      if (res.consultaId) refreshConsultas();
      toast(isEncrypt ? "Cifrado listo" : "Descifrado listo");
    } catch (err) {
      toast(err.message);
    }
  }

  function runCanvasLsb(isEncrypt, algo) {
    const srcCanvas = $("#lsbSourceCanvas");
    const sCtx = srcCanvas.getContext("2d");
    const imgData = sCtx.getImageData(0, 0, srcCanvas.width, srcCanvas.height);
    const data = imgData.data;

    if (isEncrypt) {
      const secret = $("#lsbSecretInput").value;
      if (!secret) return toast("Ingresa dato oculto");
      const msgBytes = new TextEncoder().encode(secret);
      const payload = new Uint8Array(6 + msgBytes.length);
      payload[0] = 0x43; payload[1] = 0x53;
      payload[2] = (msgBytes.length >>> 24) & 0xff;
      payload[3] = (msgBytes.length >>> 16) & 0xff;
      payload[4] = (msgBytes.length >>> 8) & 0xff;
      payload[5] = msgBytes.length & 0xff;
      payload.set(msgBytes, 6);

      const maxBytes = Math.floor((srcCanvas.width * srcCanvas.height * 3) / 8);
      if (payload.length > maxBytes) return toast("Imagen muy pequeña");

      let bitIdx = 0;
      const beforePx = data[0];
      for (let b = 0; b < payload.length; b++) {
        for (let bit = 7; bit >= 0; bit--) {
          const pxIdx = Math.floor(bitIdx / 3) * 4 + (bitIdx % 3);
          data[pxIdx] = (data[pxIdx] & 0xfe) | ((payload[b] >> bit) & 1);
          bitIdx++;
        }
      }
      const afterPx = data[0];
      const outCanvas = $("#lsbOutCanvas");
      outCanvas.width = srcCanvas.width;
      outCanvas.height = srcCanvas.height;
      outCanvas.getContext("2d").putImageData(imgData, 0, 0);
      outCanvas.classList.add("visible");
      state.lsbHasOutputImage = true;
      state.lastResponse = null;

      $("#outHash").textContent = "LSB PNG";
      showOutputState($("#lsbImageName").textContent, `LSB PNG (${srcCanvas.width}x${srcCanvas.height}) · ${msgBytes.length} B ocultos`);
      state.lastInspector = {
        algo: algo.name,
        cells: Array.from(payload.slice(0, 16), (x) => x.toString(16).padStart(2, "0").toUpperCase()),
        steps: [
          `Capacidad: ${maxBytes} B`,
          `Pixel[0]: ${beforePx} -> ${afterPx}`,
          `Bits incrustados: ${payload.length * 8}`
        ]
      };
      renderInspector();
      toast("Ocultado en LSB");
    } else {
      const readByte = (byteOff) => {
        let val = 0;
        for (let bit = 0; bit < 8; bit++) {
          const bitIdx = byteOff * 8 + bit;
          const pxIdx = Math.floor(bitIdx / 3) * 4 + (bitIdx % 3);
          val = (val << 1) | (data[pxIdx] & 1);
        }
        return val;
      };
      if (readByte(0) !== 0x43 || readByte(1) !== 0x53) return toast("Sin cabecera LSB");
      const len = ((readByte(2) << 24) | (readByte(3) << 16) | (readByte(4) << 8) | readByte(5)) >>> 0;
      if (len <= 0 || len > 500000) return toast("Longitud inválida");
      const out = new Uint8Array(len);
      for (let i = 0; i < len; i++) out[i] = readByte(6 + i);
      const txt = new TextDecoder().decode(out);
      $("#lsbOutCanvas").classList.remove("visible");
      state.lsbHasOutputImage = false;
      showOutputState($("#lsbImageName").textContent, txt);
      state.lastInspector = {
        algo: algo.name,
        cells: Array.from(out.slice(0, 16), (x) => x.toString(16).padStart(2, "0").toUpperCase()),
        steps: ["Cabecera CS detectada", `Longitud: ${len} B`, "Extracción LSB completada"]
      };
      renderInspector();
      toast("Extraído LSB");
    }
  }

  function downloadOutput() {
    if (state.mode === "lsb" && state.lsbHasOutputImage) {
      const link = document.createElement("a");
      link.download = "estego.png";
      link.href = $("#lsbOutCanvas").toDataURL("image/png");
      link.click();
      return;
    }
    if (state.lastResponse?.consultaId) {
      window.location.href = `/api/consultas/${state.lastResponse.consultaId}/zip`;
      return;
    }
    if (state.lastResponse?.outputBase64) {
      const bytes = base64ToBytes(state.lastResponse.outputBase64);
      const blob = new Blob([bytes], { type: "application/octet-stream" });
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = state.lastResponse.outputFileName || "salida.bin";
      a.click();
      setTimeout(() => URL.revokeObjectURL(a.href), 1000);
    }
  }

  // --- Inspector ---
  function initInspector() {
    $$("#inspectorFormatGroup .seg-pill").forEach((btn) => {
      btn.addEventListener("click", () => {
        $$("#inspectorFormatGroup .seg-pill").forEach((b) => b.classList.remove("active"));
        btn.classList.add("active");
        renderInspector();
      });
    });
    renderInspector();
  }

  function renderInspector() {
    $("#inspectorAlgoName").textContent = state.lastInspector.algo;
    const fmt = $("#inspectorFormatGroup .seg-pill.active")?.dataset.fmt || "matrix";
    const vis = $("#inspectorVisual");
    vis.innerHTML = "";
    state.lastInspector.cells.forEach((hex, idx) => {
      const div = document.createElement("div");
      div.className = "matrix-cell" + (idx % 5 === 0 ? " highlight" : "");
      const num = parseInt(hex, 16);
      div.textContent = fmt === "bin" ? num.toString(2).padStart(8, "0") : (fmt === "hex" ? `0x${hex}` : hex);
      vis.appendChild(div);
    });
    const list = $("#inspectorSteps");
    list.innerHTML = "";
    state.lastInspector.steps.forEach((s, idx) => {
      const li = document.createElement("li");
      li.className = "step-item";
      li.innerHTML = `<span class="step-num">${idx + 1}</span><span>${s}</span>`;
      list.appendChild(li);
    });
  }

  // --- Consultas & Lateral Drawer ---
  function initConsultas() {
    $("#consultasSearch").addEventListener("input", renderConsultas);
    $$("#consultasFilterGroup .seg-pill").forEach((btn) => {
      btn.addEventListener("click", () => {
        $$("#consultasFilterGroup .seg-pill").forEach((b) => b.classList.remove("active"));
        btn.classList.add("active");
        state.consultasFilter = btn.dataset.origin;
        renderConsultas();
      });
    });

    $$("#consultasViewModeGroup .seg-pill").forEach((btn) => {
      btn.classList.toggle("active", btn.dataset.layout === state.consultasLayout);
      btn.addEventListener("click", () => {
        $$("#consultasViewModeGroup .seg-pill").forEach((b) => b.classList.remove("active"));
        btn.classList.add("active");
        state.consultasLayout = btn.dataset.layout;
        localStorage.setItem(STORAGE_CONSULTAS_VIEW, state.consultasLayout);
        renderConsultas();
      });
    });

    $("#consultasSaveAllBtn").addEventListener("click", () => {
      if (state.consultas.length === 0) return toast("Sin registros");
      window.location.href = "/api/consultas/export-all";
    });

    $("#consultasClearAllBtn").addEventListener("click", async () => {
      if (state.consultas.length === 0) return toast("Sin registros");
      try {
        await api("/api/consultas", { method: "DELETE" });
        await refreshConsultas();
        toast("Consultas limpiadas");
      } catch (err) {
        toast(err.message);
      }
    });

    $("#drawerCloseBtn").addEventListener("click", closeSendDrawer);
    $("#drawerCancelBtn").addEventListener("click", closeSendDrawer);
    $("#sendDrawerBackdrop").addEventListener("click", closeSendDrawer);
    $("#drawerSendBtn").addEventListener("click", async () => {
      const targetIp = $("#drawerTargetIp").value.trim();
      if (!targetIp || !state.drawerItem) return toast("Ingresa IP:Puerto");
      try {
        $("#drawerSendBtn").disabled = true;
        const res = await api(`/api/consultas/${state.drawerItem.id}/send`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ targetIp })
        });
        closeSendDrawer();
        toast(`Enviado a ${res.targetUrl}`);
      } catch (err) {
        toast(err.message);
      } finally {
        $("#drawerSendBtn").disabled = false;
      }
    });
  }

  async function refreshConsultas() {
    state.consultas = await api("/api/consultas");
    renderConsultas();
  }

  function consultaActionsHtml(item) {
    return `
      <button class="icon-action-btn c-operate" data-id="${item.id}" title="Operar" aria-label="Operar">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <path d="M12 20h9"></path>
          <path d="M16.5 3.5a2.12 2.12 0 0 1 3 3L7 19l-4 1 1-4Z"></path>
        </svg>
      </button>
      <a class="icon-action-btn" href="/api/consultas/${item.id}/zip" title="Descargar .ZIP" aria-label="Descargar .ZIP">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
          <polyline points="7 10 12 15 17 10"></polyline>
          <line x1="12" y1="15" x2="12" y2="3"></line>
        </svg>
      </a>
      <button class="icon-action-solid c-send" data-id="${item.id}" title="Enviar" aria-label="Enviar">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <line x1="22" y1="2" x2="11" y2="13"></line>
          <polygon points="22 2 15 22 11 13 2 9 22 2"></polygon>
        </svg>
      </button>
      <button class="icon-action-btn icon-action-danger c-delete" data-id="${item.id}" title="Eliminar" aria-label="Eliminar">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <polyline points="3 6 5 6 21 6"></polyline>
          <path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"></path>
          <path d="M10 11v6"></path>
          <path d="M14 11v6"></path>
          <path d="M9 6V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2"></path>
        </svg>
      </button>
    `;
  }

  function renderConsultas() {
    const body = $("#consultasBody");
    const grid = $("#consultasCardsGrid");
    const tableWrap = $("#consultasTableWrap");
    const q = ($("#consultasSearch")?.value || "").trim().toLowerCase();
    const isCards = state.consultasLayout === "cards";

    tableWrap.classList.toggle("hidden", isCards);
    grid.classList.toggle("hidden", !isCards);
    body.innerHTML = "";
    grid.innerHTML = "";

    const filtered = state.consultas
      .filter((c) => state.consultasFilter === "all" || c.origin === state.consultasFilter)
      .filter((c) => !q || c.zipFileName.toLowerCase().includes(q) || c.algorithmName.toLowerCase().includes(q));

    filtered.forEach((item) => {
      const originCls = item.origin === "Recibido" ? "badge-pending" : "cat-pill";
      const actions = consultaActionsHtml(item);

      if (isCards) {
        const card = document.createElement("article");
        card.className = "ticket-card";
        card.innerHTML = `
          <div class="ticket-top">
            <span class="${originCls}">${item.origin}</span>
            <span class="meta-count">${item.createdAt}</span>
          </div>
          <div class="ticket-file">${item.zipFileName}</div>
          <div class="ticket-meta">
            <span>${item.algorithmName}</span>
            <span class="meta-count">SHA-256: ${item.encryptedSha256.slice(0, 14)}…</span>
          </div>
          <div class="ticket-actions">${actions}</div>
        `;
        grid.appendChild(card);
      } else {
        const tr = document.createElement("tr");
        tr.innerHTML = `
          <td class="input-mono" style="font-size:12px;">${item.zipFileName}</td>
          <td><span class="${originCls}">${item.origin}</span></td>
          <td>${item.algorithmName}</td>
          <td class="input-mono" style="font-size:12px;">${item.createdAt}</td>
          <td class="input-mono" style="font-size:12px;">${item.encryptedSha256.slice(0, 12)}…</td>
          <td class="td-center">
            <div class="tool-bottom-group" style="justify-content:center; gap:6px;">${actions}</div>
          </td>
        `;
        body.appendChild(tr);
      }
    });

    const container = isCards ? grid : body;
    container.querySelectorAll(".c-operate").forEach((btn) => {
      btn.addEventListener("click", () => loadConsultaIntoOperate(Number(btn.dataset.id)));
    });

    container.querySelectorAll(".c-send").forEach((btn) => {
      btn.addEventListener("click", () => {
        const item = state.consultas.find((c) => c.id === Number(btn.dataset.id));
        if (item) openSendDrawer(item);
      });
    });

    container.querySelectorAll(".c-delete").forEach((btn) => {
      btn.addEventListener("click", async () => {
        try {
          await api(`/api/consultas/${btn.dataset.id}`, { method: "DELETE" });
          await refreshConsultas();
          toast("Eliminado");
        } catch (err) {
          toast(err.message);
        }
      });
    });
  }

  async function loadConsultaIntoOperate(id) {
    try {
      const pkg = await api(`/api/consultas/${id}/unpack`);
      const algo = state.algorithms.find((a) => a.code === pkg.algorithmCode);
      if (!algo || !algo.isVisible) {
        return toast("Algoritmo oculto en Ajustes");
      }

      document.querySelector('.nav-tab[data-view="operar"]')?.click();
      document.querySelector('#actionModeGroup .seg-pill[data-action="decrypt"]')?.click();

      $("#algoSelect").value = pkg.algorithmCode;
      $("#keyInput").value = "";
      syncActionButtons();

      if (pkg.payloadMode === "file") {
        document.querySelector('#inputModeGroup .seg-pill[data-mode="file"]')?.click();
        const byteLen = base64ToBytes(pkg.dataBase64).length;
        state.fileBase64 = pkg.dataBase64;
        state.fileName = pkg.originalFileName.endsWith(".enc") ? pkg.originalFileName : `${pkg.originalFileName}.enc`;
        state.fileSize = byteLen;
        $("#fileName").textContent = state.fileName;
        $("#fileInfo").textContent = `${byteLen} bytes`;
      } else {
        document.querySelector('#inputModeGroup .seg-pill[data-mode="text"]')?.click();
        $("#inputText").value = pkg.dataText;
      }

      showInputState();
      updateInputMeta();
      toast("Cargado en Operar");
    } catch (err) {
      toast(err.message);
    }
  }

  function openSendDrawer(item) {
    state.drawerItem = item;
    $("#drawerFileName").textContent = item.zipFileName;
    $("#drawerAlgo").textContent = item.algorithmName;
    $("#drawerSha").textContent = `${item.encryptedSha256.slice(0, 18)}…`;
    $("#sendDrawerBackdrop").classList.add("open");
    $("#sendDrawer").classList.add("open");
    $("#sendDrawer").setAttribute("aria-hidden", "false");
  }

  function closeSendDrawer() {
    $("#sendDrawerBackdrop").classList.remove("open");
    $("#sendDrawer").classList.remove("open");
    $("#sendDrawer").setAttribute("aria-hidden", "true");
  }

  // --- Solicitudes ---
  function initRequests() {
    $("#simIncomingBtn").addEventListener("click", async () => {
      try {
        await api("/api/requests/simulate", { method: "POST" });
        await refreshRequests();
        toast("Solicitud recibida");
      } catch (err) {
        toast(err.message);
      }
    });
  }

  async function refreshRequests() {
    state.requests = await api("/api/requests");
    renderRequests();
  }

  function renderRequests() {
    const body = $("#requestsBody");
    body.innerHTML = "";
    const pending = state.requests.filter((r) => r.status === "Pendiente").length;
    const badge = $("#reqCountBadge");
    badge.textContent = String(pending);
    badge.classList.toggle("hidden", pending === 0);

    state.requests.forEach((req) => {
      const tr = document.createElement("tr");
      const statusCls = req.status === "Aceptada" ? "badge-ok" : (req.status === "Rechazada" ? "badge-err" : "badge-pending");
      const actionsHtml = req.status === "Pendiente"
        ? `<button class="btn-solid req-accept" data-id="${req.id}" style="height:28px; padding:0 12px; font-size:12px;">Aceptar</button>
           <button class="btn-chip req-reject" data-id="${req.id}" style="height:28px; padding:0 12px; font-size:12px;">Rechazar</button>`
        : `<span class="meta-count">—</span>`;
      tr.innerHTML = `
        <td class="input-mono">${req.sourceIp}</td>
        <td class="input-mono" style="font-size:12px;">${req.zipFileName}</td>
        <td>${req.algorithmName}</td>
        <td><span class="${req.signatureValid ? "badge-ok" : "badge-err"}">${req.signatureValid ? "X.509 OK" : "Inválida"}</span></td>
        <td><span class="${statusCls}">${req.status}</span></td>
        <td class="td-center"><div class="tool-bottom-group" style="justify-content:center;">${actionsHtml}</div></td>
      `;
      body.appendChild(tr);
    });

    body.querySelectorAll(".req-accept").forEach((btn) => {
      btn.addEventListener("click", async () => {
        try {
          await api(`/api/requests/${btn.dataset.id}/accept`, { method: "POST" });
          await refreshRequests();
          await refreshConsultas();
          toast("Aceptada -> Consultas");
        } catch (err) {
          toast(err.message);
        }
      });
    });

    body.querySelectorAll(".req-reject").forEach((btn) => {
      btn.addEventListener("click", async () => {
        try {
          await api(`/api/requests/${btn.dataset.id}/reject`, { method: "POST" });
          await refreshRequests();
          toast("Solicitud rechazada");
        } catch (err) {
          toast(err.message);
        }
      });
    });
  }

  // --- Helpers ---
  function bytesToBase64(bytes) {
    let bin = "";
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin);
  }

  function base64ToBytes(b64) {
    const bin = atob(b64.trim());
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  function toast(msg) {
    const el = $("#toast");
    el.textContent = msg;
    el.classList.add("show");
    clearTimeout(toast._t);
    toast._t = setTimeout(() => el.classList.remove("show"), 2400);
  }

  // --- Boot ---
  async function boot() {
    initTheme();
    initNav();
    initOperate();
    initInspector();
    initConsultas();
    initRequests();
    initSettings();
    try {
      await Promise.all([refreshAlgorithms(), refreshConsultas(), refreshRequests()]);
    } catch (err) {
      toast(err.message);
    }
  }

  boot();
})();
