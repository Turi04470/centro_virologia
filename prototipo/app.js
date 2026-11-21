(() => {
  "use strict";

  const STORAGE_THEME = "cs_proto_theme_v1";
  const STORAGE_CONFIG = "cs_proto_algos_v1";
  const STORAGE_CERT = "cs_proto_cert_v1";
  const STORAGE_CONSULTAS = "cs_proto_consultas_v1";

  const ALGORITHMS = [
    { id: "AES_GCM", name: "AES-256-GCM", cat: "Simétrico", defaultKey: "clave-aes-256-segura", modern: true, cell: true },
    { id: "DES", name: "DES (56-bit)", cat: "Simétrico", defaultKey: "claveDES", modern: false, cell: false },
    { id: "TRIPLE_DES", name: "Triple DES / 3DES-96", cat: "Simétrico", defaultKey: "clave-3des-96-ede", modern: false, cell: false },
    { id: "CHACHA20", name: "ChaCha20-Poly1305", cat: "Simétrico", defaultKey: "chacha20-llave-32bytes", modern: true, cell: true },
    { id: "RSA", name: "RSA (OAEP / Modular)", cat: "Asimétrico", defaultKey: "p=257,q=263,e=3", modern: true, cell: true },
    { id: "ECC", name: "ECC (ECDH / ECIES)", cat: "Asimétrico", defaultKey: "ecc-p256-secp256r1", modern: true, cell: false },
    { id: "DIFFIE_HELLMAN", name: "Diffie-Hellman (g^a mod p)", cat: "Acuerdo", defaultKey: "p=467,g=2,a=15,b=27", modern: true, cell: false },
    { id: "CAESAR", name: "Cifrado César", cat: "Clásico", defaultKey: "3", modern: false, cell: false },
    { id: "VIGENERE", name: "Cifrado Vigenère", cat: "Clásico", defaultKey: "SOL", modern: false, cell: false },
    { id: "XOR_ASM", name: "XOR Ensamblador (WREG/ROL)", cat: "Bajo Nivel", defaultKey: "0x5A,ROL=1", modern: false, cell: false },
    { id: "LSB_STEGO", name: "Esteganografía LSB", cat: "Estego", defaultKey: "1-bit-RGB", modern: true, cell: false },
    { id: "EUCLIDES_AFFINE", name: "Euclides Extendido (Afín)", cat: "Matemático", defaultKey: "a=5,b=11", modern: false, cell: false },
    { id: "MILLER_RABIN", name: "Miller–Rabin (Primos)", cat: "Matemático", defaultKey: "n=1009,rondas=5", modern: true, cell: false },
    { id: "FISHER_YATES", name: "Permutación Fisher–Yates", cat: "Transposición", defaultKey: "semilla-2026", modern: false, cell: false },
    { id: "HASH_SHA", name: "Hash SHA-256", cat: "Integridad", defaultKey: "sha256", modern: true, cell: false },
    { id: "HMAC_SHA256", name: "HMAC-SHA256", cat: "Autenticación", defaultKey: "secreto-hmac", modern: true, cell: false },
    { id: "DIGITAL_SIG", name: "Firma Digital (PSS/ECDSA)", cat: "Autenticidad", defaultKey: "NODO-01-PRIV", modern: true, cell: false },
    { id: "QUANTUM_PQC", name: "Cuántica BB84 + PQC (LWE)", cat: "Poscuántico", defaultKey: "bb84-eve=0", modern: true, cell: false },
    { id: "DFT_SPECTRAL", name: "Transformada DFT / IDFT", cat: "Señales", defaultKey: "fase-42", modern: false, cell: false },
    { id: "LAGRANGE_SHAMIR", name: "Lagrange (Shamir GF256)", cat: "Álgebra", defaultKey: "N=5,K=3", modern: true, cell: false },
    { id: "LORENZ_SZ40", name: "Máquina Lorenz (SZ40)", cat: "Flujo", defaultKey: "chi=13,psi=29", modern: false, cell: false }
  ];

  const state = {
    action: "encrypt",
    mode: "text",
    configs: loadConfigs(),
    cert: null,
    lastInspector: {
      algo: "AES-256-GCM",
      cells: Array.from({ length: 16 }, (_, i) => i.toString(16).padStart(2, "0").toUpperCase()),
      steps: ["Esperando operación"]
    },
    fileBytes: null,
    fileName: "",
    resultBytes: null,
    resultFileName: "salida.bin",
    lsbImageLoaded: false,
    lsbHasOutputImage: false,
    consultas: loadConsultas(),
    consultasFilter: "all",
    drawerItem: null,
    requests: [
      { id: 1, ip: "192.168.1.14:5000", file: "NODO02_AES256GCM_20261116_211000_8F3C1A20.zip", algo: "AES-256-GCM", sigValid: true, status: "Pendiente", sha256: "8f3c1a2094b1e02f..." },
      { id: 2, ip: "192.168.1.22:5000", file: "NODO04_RSA_20261116_211412_4C90B712.zip", algo: "RSA (OAEP / Modular)", sigValid: true, status: "Pendiente", sha256: "4c90b712a30f881e..." }
    ]
  };

  // --- DOM ---
  const $ = (sel) => document.querySelector(sel);
  const $$ = (sel) => Array.from(document.querySelectorAll(sel));

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

  // --- Config Persistence ---
  function loadConfigs() {
    try {
      const raw = localStorage.getItem(STORAGE_CONFIG);
      if (raw) {
        const parsed = JSON.parse(raw);
        const map = {};
        ALGORITHMS.forEach((a) => {
          map[a.id] = parsed[a.id] || { visible: true, encrypt: true, decrypt: true };
        });
        return map;
      }
    } catch (_) {}
    const init = {};
    ALGORITHMS.forEach((a) => {
      init[a.id] = { visible: true, encrypt: true, decrypt: true };
    });
    return init;
  }

  function saveConfigs() {
    localStorage.setItem(STORAGE_CONFIG, JSON.stringify(state.configs));
  }

  // --- Certificate Identity ---
  function loadCert() {
    try {
      const raw = localStorage.getItem(STORAGE_CERT);
      if (raw) return JSON.parse(raw);
    } catch (_) {}
    return createNewCert(1);
  }

  function createNewCert(serialNum) {
    const randHex = Array.from({ length: 16 }, () => Math.floor(Math.random() * 256).toString(16).padStart(2, "0")).join("").toUpperCase();
    const cert = {
      subject: "CN=NODO-01, O=CentroCiberseguridad",
      serial: String(serialNum).padStart(4, "0"),
      thumbprint: sha256Hex(utf8Bytes(`NODO-01|${serialNum}|${randHex}`)).toUpperCase(),
      notBefore: "2026-11-16",
      notAfter: "2027-11-16",
      publicKeyHex: randHex
    };
    localStorage.setItem(STORAGE_CERT, JSON.stringify(cert));
    return cert;
  }

  function buildPem(cert) {
    const body = btoa(JSON.stringify(cert)).match(/.{1,64}/g).join("\n");
    return `-----BEGIN CERTIFICATE-----\n${body}\n-----END CERTIFICATE-----`;
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
      });
    });
  }

  // --- Settings View ---
  function renderSettings(filter = "") {
    const body = $("#settingsBody");
    const q = filter.trim().toLowerCase();
    body.innerHTML = "";

    ALGORITHMS.filter((a) => !q || a.name.toLowerCase().includes(q) || a.cat.toLowerCase().includes(q)).forEach((algo) => {
      const cfg = state.configs[algo.id];
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td><strong>${algo.name}</strong></td>
        <td><span class="cat-pill">${algo.cat}</span></td>
        <td class="td-center">${switchHtml(algo.id, "visible", cfg.visible)}</td>
        <td class="td-center">${switchHtml(algo.id, "encrypt", cfg.encrypt)}</td>
        <td class="td-center">${switchHtml(algo.id, "decrypt", cfg.decrypt)}</td>
      `;
      body.appendChild(tr);
    });

    body.querySelectorAll("input[data-algo]").forEach((chk) => {
      chk.addEventListener("change", (e) => {
        const { algo, field } = e.target.dataset;
        state.configs[algo][field] = e.target.checked;
        saveConfigs();
        syncVisibleAlgorithms();
        syncActionButtons();
      });
    });
  }

  function switchHtml(id, field, checked) {
    return `
      <label class="switch">
        <input type="checkbox" data-algo="${id}" data-field="${field}" ${checked ? "checked" : ""} />
        <span class="slider"></span>
      </label>
    `;
  }

  function initPresets() {
    $("#settingsSearch").addEventListener("input", (e) => renderSettings(e.target.value));
    $$(".preset-btn").forEach((btn) => {
      btn.addEventListener("click", () => {
        const p = btn.dataset.preset;
        if (p === "hideAll") {
          ALGORITHMS.forEach((a) => {
            state.configs[a.id] = { visible: false, encrypt: false, decrypt: false };
          });
        }
        saveConfigs();
        renderSettings($("#settingsSearch").value);
        syncVisibleAlgorithms();
        syncActionButtons();
        toast("Perfil aplicado");
      });
    });
  }

  // --- Sync Visibility & Permissions ---
  function syncVisibleAlgorithms() {
    const visibleAlgos = ALGORITHMS.filter((a) => state.configs[a.id].visible);
    const sel = $("#algoSelect");
    const prev = sel.value;
    sel.innerHTML = "";

    visibleAlgos.forEach((a) => {
      const opt = document.createElement("option");
      opt.value = a.id;
      opt.textContent = a.name;
      sel.appendChild(opt);
    });

    const hasAny = visibleAlgos.length > 0;
    $("#noAlgosNotice").classList.toggle("hidden", hasAny);
    $("#operateBody").classList.toggle("hidden", !hasAny);
    $("#operateFooter").classList.toggle("hidden", !hasAny);

    if (hasAny) {
      if (visibleAlgos.some((a) => a.id === prev)) {
        sel.value = prev;
      } else {
        sel.value = visibleAlgos[0].id;
      }
      updateDefaultKey();
    }

    syncActionButtons();
  }

  function syncActionButtons() {
    const id = $("#algoSelect").value;
    const cfg = id ? state.configs[id] : null;
    const isEnc = state.action === "encrypt";
    const btn = $("#submitBtn");
    btn.textContent = isEnc ? "Cifrar" : "Descifrar";
    btn.disabled = !cfg || !cfg.visible || (isEnc ? !cfg.encrypt : !cfg.decrypt);
  }

  function updateDefaultKey() {
    const algo = ALGORITHMS.find((a) => a.id === $("#algoSelect").value);
    if (algo) $("#keyInput").value = algo.defaultKey;
  }

  // --- Operate Mode Switching ---
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
        if (state.mode === "lsb" && state.configs.LSB_STEGO.visible) {
          $("#algoSelect").value = "LSB_STEGO";
          updateDefaultKey();
          syncActionButtons();
        }
        updateInputMeta();
      });
    });

    $("#advToggleBtn").addEventListener("click", () => {
      $("#advancedDrawer").classList.toggle("hidden");
    });

    $("#editInputBtn").addEventListener("click", showInputState);
    $("#resetBtn").addEventListener("click", clearOperate);

    $("#algoSelect").addEventListener("change", () => {
      updateDefaultKey();
      syncActionButtons();
    });

    $("#genKeyBtn").addEventListener("click", () => {
      const id = $("#algoSelect").value;
      if (id === "CAESAR") $("#keyInput").value = String(Math.floor(Math.random() * 24) + 1);
      else if (id === "EUCLIDES_AFFINE") {
        const coprimes = [3, 5, 7, 9, 11, 15, 17, 19, 25];
        $("#keyInput").value = `a=${coprimes[Math.floor(Math.random() * coprimes.length)]},b=${Math.floor(Math.random() * 200) + 1}`;
      } else {
        $("#keyInput").value = Array.from({ length: 8 }, () => Math.floor(Math.random() * 256).toString(16).padStart(2, "0")).join("");
      }
      toast("Clave generada");
    });

    $("#inputText").addEventListener("input", updateInputMeta);

    // File Dropzone
    const fileInput = $("#fileInput");
    const drop = $("#fileDropzone");
    drop.addEventListener("dragover", (e) => { e.preventDefault(); drop.classList.add("dragover"); });
    drop.addEventListener("dragleave", () => drop.classList.remove("dragover"));
    drop.addEventListener("drop", (e) => {
      e.preventDefault();
      drop.classList.remove("dragover");
      if (e.dataTransfer.files[0]) loadGenericFile(e.dataTransfer.files[0]);
    });
    fileInput.addEventListener("change", (e) => {
      if (e.target.files[0]) loadGenericFile(e.target.files[0]);
    });

    // LSB Image Dropzone
    $("#lsbImageInput").addEventListener("change", (e) => {
      if (e.target.files[0]) loadLsbImage(e.target.files[0]);
    });

    $("#submitBtn").addEventListener("click", () => runOperation(state.action === "encrypt"));
    $("#clearBtn").addEventListener("click", clearOperate);
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
      const len = utf8Bytes($("#inputText").value).length;
      $("#inMeta").textContent = `${len} B`;
    } else if (state.mode === "file") {
      $("#inMeta").textContent = state.fileBytes ? `${state.fileBytes.length} B` : "0 B";
    } else {
      $("#inMeta").textContent = state.lsbImageLoaded ? $("#lsbCapacity").textContent : "0 B";
    }
  }

  function loadGenericFile(file) {
    const reader = new FileReader();
    reader.onload = () => {
      state.fileBytes = new Uint8Array(reader.result);
      state.fileName = file.name;
      $("#fileName").textContent = file.name;
      $("#fileInfo").textContent = `${state.fileBytes.length} bytes`;
      updateInputMeta();
    };
    reader.readAsArrayBuffer(file);
  }

  function loadLsbImage(file) {
    const url = URL.createObjectURL(file);
    const img = new Image();
    img.onload = () => {
      const canvas = $("#lsbSourceCanvas");
      canvas.width = img.width;
      canvas.height = img.height;
      const ctx = canvas.getContext("2d");
      ctx.drawImage(img, 0, 0);
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
    state.fileBytes = null;
    state.resultBytes = null;
    state.lastPacketJson = null;
    state.lsbHasOutputImage = false;
    $("#fileName").textContent = "Archivo";
    $("#fileInfo").textContent = "—";
    $("#lsbOutCanvas").classList.remove("visible");
    showInputState();
    updateInputMeta();
  }

  // --- Crypto Execution ---
  function runOperation(isEncrypt) {
    const algoId = $("#algoSelect").value;
    const cfg = state.configs[algoId];
    if (!cfg || !cfg.visible) return toast("Algoritmo oculto");
    if (isEncrypt && !cfg.encrypt) return toast("Cifrado deshabilitado");
    if (!isEncrypt && !cfg.decrypt) return toast("Descifrado deshabilitado");

    const key = $("#keyInput").value.trim() || "clave";
    const algoMeta = ALGORITHMS.find((a) => a.id === algoId);

    try {
      if (state.mode === "lsb") {
        runLsbMode(isEncrypt, algoMeta);
        return;
      }

      const isFile = state.mode === "file";
      let inputBytes;
      if (isFile) {
        if (!state.fileBytes) return toast("Carga un archivo");
        inputBytes = state.fileBytes;
      } else {
        const txt = $("#inputText").value;
        if (!txt) return toast("Ingresa texto");
        inputBytes = isEncrypt ? utf8Bytes(txt) : null;
      }

      const res = executeAlgorithm(algoId, isEncrypt, isFile ? inputBytes : $("#inputText").value, key, isFile);
      state.resultBytes = res.bytes || utf8Bytes(res.text);
      state.resultFileName = isFile ? (isEncrypt ? `${state.fileName}.enc` : state.fileName.replace(/\.enc$/i, "") || "descifrado.bin") : "salida.txt";

      const sha = sha256Hex(state.resultBytes);
      $("#outHash").textContent = `SHA-256: ${sha.slice(0, 12)}…`;

      let outDisplay;
      if ($("#attachCertToggle").checked && isEncrypt) {
        const pkg = {
          nodeId: "NODO-01",
          algorithm: algoMeta.name,
          timestampUtc: new Date().toISOString(),
          payloadBase64: bytesToBase64(state.resultBytes),
          payloadSha256: sha,
          certificateThumbprint: state.cert.thumbprint,
          certificatePem: buildPem(state.cert),
          signature: sha256Hex(utf8Bytes(`${sha}|${state.cert.thumbprint}`))
        };
        outDisplay = isFile
          ? `[Archivo ${state.resultBytes.length} B + Certificado]\n` + JSON.stringify(pkg, null, 2)
          : res.text + "\n\n--- CERT ---\n" + JSON.stringify(pkg, null, 2);
        state.lastPacketJson = JSON.stringify(pkg, null, 2);
      } else {
        outDisplay = isFile ? `[Archivo ${state.resultBytes.length} B]\n${bytesToBase64(state.resultBytes).slice(0, 400)}...` : res.text;
        state.lastPacketJson = null;
      }

      const preview = isFile ? `${state.fileName} (${state.fileBytes.length} B)` : $("#inputText").value.slice(0, 60);
      showOutputState(preview, outDisplay);

      if (isEncrypt) {
        addConsultaRecord({
          file: buildStandardZipName(algoMeta.id, sha),
          origin: "Local",
          algo: algoMeta.name,
          sha256: sha,
          bytesBase64: bytesToBase64(state.resultBytes)
        });
      }

      state.lastInspector = {
        algo: algoMeta.name,
        cells: res.cells,
        steps: res.steps
      };
      renderInspector();
      toast(isEncrypt ? "Cifrado listo" : "Descifrado listo");
    } catch (err) {
      toast(err.message || "Error");
    }
  }

  function runLsbMode(isEncrypt, algoMeta) {
    if (!state.lsbImageLoaded) return toast("Carga imagen PNG/BMP");
    const srcCanvas = $("#lsbSourceCanvas");
    const sCtx = srcCanvas.getContext("2d");
    const imgData = sCtx.getImageData(0, 0, srcCanvas.width, srcCanvas.height);
    const data = imgData.data;

    if (isEncrypt) {
      const secret = $("#lsbSecretInput").value;
      if (!secret) return toast("Ingresa dato oculto");
      const msgBytes = utf8Bytes(secret);
      const payload = new Uint8Array(6 + msgBytes.length);
      payload[0] = 0x43; // 'C'
      payload[1] = 0x53; // 'S'
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
          const v = (payload[b] >> bit) & 1;
          data[pxIdx] = (data[pxIdx] & 0xfe) | v;
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
      state.resultFileName = "estego.png";

      $("#outHash").textContent = `SHA-256: ${sha256Hex(payload).slice(0, 12)}…`;
      showOutputState($("#lsbImageName").textContent, `LSB PNG (${srcCanvas.width}x${srcCanvas.height}) · ${msgBytes.length} B ocultos`);

      state.lastInspector = {
        algo: algoMeta.name,
        cells: Array.from(payload.slice(0, 16), (x) => x.toString(16).padStart(2, "0").toUpperCase()),
        steps: [
          `Capacidad: ${maxBytes} B`,
          `Pixel[0]: ${beforePx} (${beforePx.toString(2).padStart(8, "0")}) -> ${afterPx} (${afterPx.toString(2).padStart(8, "0")})`,
          `Bits incrustados: ${payload.length * 8}`
        ]
      };
      renderInspector();
      toast("Ocultado en LSB");
    } else {
      const readByte = (byteOffset) => {
        let val = 0;
        for (let bit = 0; bit < 8; bit++) {
          const bitIdx = byteOffset * 8 + bit;
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
      const txt = bytesToUtf8(out);
      $("#outHash").textContent = `SHA-256: ${sha256Hex(out).slice(0, 12)}…`;
      $("#lsbOutCanvas").classList.remove("visible");
      showOutputState($("#lsbImageName").textContent, txt);
      state.lastInspector = {
        algo: algoMeta.name,
        cells: Array.from(out.slice(0, 16), (x) => x.toString(16).padStart(2, "0").toUpperCase()),
        steps: [`Cabecera CS detectada`, `Longitud: ${len} B`, `Extracción LSB completada`]
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
    if (state.lastPacketJson && state.resultBytes) {
      const pkg = JSON.parse(state.lastPacketJson);
      const manifest = { ...pkg };
      delete manifest.payloadBase64;
      const zipBlob = buildZipBlob([
        { name: "datos.enc", data: state.resultBytes },
        { name: "certificado.pem", data: utf8Bytes(buildPem(state.cert)) },
        { name: "manifest.json", data: utf8Bytes(JSON.stringify(manifest, null, 2)) }
      ]);
      triggerDownload(zipBlob, "paquete.zip", "application/zip");
      return;
    }
    if (state.resultBytes) {
      triggerDownload(state.resultBytes, state.resultFileName, "application/octet-stream");
    }
  }

  // --- Core Algorithms (21 Engines) ---
  function executeAlgorithm(id, isEncrypt, input, key, isFile) {
    const rawBytes = isFile ? input : (isEncrypt ? utf8Bytes(input) : null);
    const steps = [];
    const makeCells = (arr) => Array.from({ length: 16 }, (_, i) => (arr[i % arr.length] || 0).toString(16).padStart(2, "0").toUpperCase());

    const extractPayloadText = (str) => str.split("\n\n--- CERT ---\n")[0].trim();

    if (id === "CAESAR") {
      const k = parseInt(key, 10) || 3;
      if (!isFile) {
        const src = isEncrypt ? input : extractPayloadText(input);
        const shift = isEncrypt ? k : -k;
        const out = src.replace(/[a-zA-Z]/g, (c) => {
          const base = c <= "Z" ? 65 : 97;
          return String.fromCharCode((((c.charCodeAt(0) - base + shift) % 26) + 26) % 26 + base);
        });
        steps.push(`k = ${k}`, `Operación: (P ${isEncrypt ? "+" : "-"} ${k}) mod 26`);
        return { text: out, bytes: utf8Bytes(out), cells: makeCells(utf8Bytes(out)), steps };
      } else {
        const delta = isEncrypt ? k : -k;
        const out = input.map((b) => (((b + delta) % 256) + 256) % 256);
        steps.push(`k = ${k}`, `Operación byte mod 256`);
        return { text: "", bytes: out, cells: makeCells(out), steps };
      }
    }

    if (id === "VIGENERE") {
      const kb = utf8Bytes(key.toUpperCase() || "SOL");
      if (!isFile) {
        const src = isEncrypt ? input : extractPayloadText(input);
        let j = 0;
        const out = src.replace(/[a-zA-Z]/g, (c) => {
          const base = c <= "Z" ? 65 : 97;
          const shift = (kb[j % kb.length] - 65 + 26) % 26;
          j++;
          const d = isEncrypt ? shift : -shift;
          return String.fromCharCode((((c.charCodeAt(0) - base + d) % 26) + 26) % 26 + base);
        });
        steps.push(`Clave: ${key}`, `Desplazamiento polialfabético mod 26`);
        return { text: out, bytes: utf8Bytes(out), cells: makeCells(utf8Bytes(out)), steps };
      } else {
        const out = input.map((b, i) => {
          const s = kb[i % kb.length];
          return isEncrypt ? (b + s) % 256 : (b - s + 256) % 256;
        });
        steps.push(`Clave ${kb.length} B`, `Suma/Resta modular Z_256`);
        return { text: "", bytes: out, cells: makeCells(out), steps };
      }
    }

    if (id === "XOR_ASM") {
      const m = key.match(/0x([0-9a-fA-F]+)/);
      const xorVal = m ? parseInt(m[1], 16) & 0xff : (utf8Bytes(key)[0] || 0x5a);
      const rMatch = key.match(/ROL=(\d+)/i);
      const rot = rMatch ? parseInt(rMatch[1], 10) % 8 : 1;
      const rol = (b, n) => ((b << n) | (b >> (8 - n))) & 0xff;
      const ror = (b, n) => ((b >> n) | (b << (8 - n))) & 0xff;

      const src = isEncrypt ? rawBytes : (isFile ? input : base64ToBytes(extractPayloadText(input)));
      const out = new Uint8Array(src.length);
      for (let i = 0; i < src.length; i++) {
        out[i] = isEncrypt ? rol(src[i] ^ xorVal, rot) : (ror(src[i], rot) ^ xorVal);
      }
      steps.push(`WREG = 0x${xorVal.toString(16).toUpperCase()}`, `XORWF + ${isEncrypt ? "ROL" : "ROR"} ${rot}`);
      return {
        text: isEncrypt ? bytesToBase64(out) : bytesToUtf8(out),
        bytes: out,
        cells: makeCells(out),
        steps
      };
    }

    if (id === "EUCLIDES_AFFINE") {
      const aMatch = key.match(/a=(\d+)/);
      const bMatch = key.match(/b=(\d+)/);
      let a = aMatch ? parseInt(aMatch[1], 10) : 5;
      const b = bMatch ? parseInt(bMatch[1], 10) : 11;
      if (a % 2 === 0) a += 1; // Ensure coprime with 256
      const inv = modInverse(a, 256);
      const src = isEncrypt ? rawBytes : (isFile ? input : base64ToBytes(extractPayloadText(input)));
      const out = new Uint8Array(src.length);
      for (let i = 0; i < src.length; i++) {
        out[i] = isEncrypt ? (a * src[i] + b) % 256 : (((inv * (src[i] - b)) % 256) + 256) % 256;
      }
      steps.push(`MCD(${a}, 256) = 1`, `Inverso modular a^-1 = ${inv}`, `C = (${a}·M + ${b}) mod 256`);
      return {
        text: isEncrypt ? bytesToBase64(out) : bytesToUtf8(out),
        bytes: out,
        cells: makeCells(out),
        steps
      };
    }

    if (id === "RSA") {
      const pMatch = key.match(/p=(\d+)/);
      const qMatch = key.match(/q=(\d+)/);
      const eMatch = key.match(/e=(\d+)/);
      const p = BigInt(pMatch ? pMatch[1] : 257);
      const q = BigInt(qMatch ? qMatch[1] : 263);
      const e = BigInt(eMatch ? eMatch[1] : 3);
      const n = p * q;
      const phi = (p - 1n) * (q - 1n);
      const d = BigInt(modInverse(Number(e), Number(phi)));

      if (isEncrypt) {
        const out = new Uint8Array(rawBytes.length * 4);
        for (let i = 0; i < rawBytes.length; i++) {
          const c = Number(modPow(BigInt(rawBytes[i]), e, n));
          out[i * 4] = (c >>> 24) & 0xff;
          out[i * 4 + 1] = (c >>> 16) & 0xff;
          out[i * 4 + 2] = (c >>> 8) & 0xff;
          out[i * 4 + 3] = c & 0xff;
        }
        steps.push(`n=${n}, phi=${phi}`, `e=${e}, d=${d}`, `c = m^${e} mod ${n}`);
        return { text: bytesToBase64(out), bytes: out, cells: makeCells(out), steps };
      } else {
        const src = isFile ? input : base64ToBytes(extractPayloadText(input));
        const out = new Uint8Array(Math.floor(src.length / 4));
        for (let i = 0; i < out.length; i++) {
          const c = BigInt((src[i * 4] << 24) | (src[i * 4 + 1] << 16) | (src[i * 4 + 2] << 8) | src[i * 4 + 3]);
          out[i] = Number(modPow(c, d, n)) & 0xff;
        }
        steps.push(`n=${n}, d=${d}`, `m = c^${d} mod ${n}`);
        return { text: bytesToUtf8(out), bytes: out, cells: makeCells(out), steps };
      }
    }

    if (id === "DIFFIE_HELLMAN") {
      const p = BigInt(key.match(/p=(\d+)/)?.[1] || 467);
      const g = BigInt(key.match(/g=(\d+)/)?.[1] || 2);
      const a = BigInt(key.match(/a=(\d+)/)?.[1] || 15);
      const b = BigInt(key.match(/b=(\d+)/)?.[1] || 27);
      const A = modPow(g, a, p);
      const B = modPow(g, b, p);
      const shared = modPow(B, a, p);
      const streamKey = sha256Bytes(utf8Bytes(`DH:${shared}`));
      const src = isEncrypt ? rawBytes : (isFile ? input : base64ToBytes(extractPayloadText(input)));
      const out = chachaXor(src, streamKey, streamKey.slice(0, 12));
      steps.push(`A=${A}, B=${B}`, `K = ${shared}`, `Cifrado simétrico con K`);
      return { text: isEncrypt ? bytesToBase64(out) : bytesToUtf8(out), bytes: out, cells: makeCells(out), steps };
    }

    if (id === "MILLER_RABIN") {
      const n = BigInt(key.match(/n=(\d+)/)?.[1] || 1009);
      const rounds = parseInt(key.match(/rondas=(\d+)/)?.[1] || "5", 10);
      const isPrime = millerRabin(n, rounds);
      const derived = sha256Bytes(utf8Bytes(`MR:${n}:${isPrime}`));
      const src = isEncrypt ? rawBytes : (isFile ? input : base64ToBytes(extractPayloadText(input)));
      const out = chachaXor(src, derived, derived.slice(0, 12));
      steps.push(`Test n=${n} (${rounds} rondas)`, `Resultado: ${isPrime ? "Probablemente primo" : "Compuesto"}`, `Flujo derivado aplicado`);
      return { text: isEncrypt ? bytesToBase64(out) : bytesToUtf8(out), bytes: out, cells: makeCells(out), steps };
    }

    if (id === "FISHER_YATES") {
      const src = isEncrypt ? rawBytes : (isFile ? input : base64ToBytes(extractPayloadText(input)));
      const perm = fisherYatesPerm(src.length, key);
      const out = new Uint8Array(src.length);
      if (isEncrypt) {
        for (let i = 0; i < src.length; i++) out[i] = src[perm[i]];
      } else {
        for (let i = 0; i < src.length; i++) out[perm[i]] = src[i];
      }
      steps.push(`Longitud N=${src.length}`, `Permutación[0..5]: [${perm.slice(0, 6).join(",")}]`);
      return { text: isEncrypt ? bytesToBase64(out) : bytesToUtf8(out), bytes: out, cells: makeCells(out), steps };
    }

    if (id === "HASH_SHA") {
      const src = isFile ? input : utf8Bytes(input);
      const digest = sha256Hex(src);
      if (isEncrypt) {
        steps.push(`Algoritmo: SHA-256`, `Digest 256 bits generado`);
        return { text: digest, bytes: utf8Bytes(digest), cells: makeCells(hexToBytes(digest)), steps };
      } else {
        const ok = digest.toLowerCase() === key.toLowerCase();
        const msg = ok ? `VÁLIDO (${digest})` : `NO COINCIDE (${digest})`;
        steps.push(`Calculado: ${digest.slice(0, 16)}…`, `Esperado: ${key.slice(0, 16)}…`, `Integridad: ${ok ? "OK" : "FALLO"}`);
        return { text: msg, bytes: utf8Bytes(msg), cells: makeCells(hexToBytes(digest)), steps };
      }
    }

    if (id === "HMAC_SHA256") {
      if (isEncrypt) {
        const tag = hmacSha256Hex(utf8Bytes(key), rawBytes);
        const packed = `${tag}|${bytesToBase64(rawBytes)}`;
        steps.push(`HMAC-SHA256 generado`, `Tag: ${tag.slice(0, 16)}…`);
        return { text: packed, bytes: utf8Bytes(packed), cells: makeCells(hexToBytes(tag)), steps };
      } else {
        const raw = isFile ? bytesToUtf8(input) : extractPayloadText(input);
        const [tag, b64] = raw.split("|");
        if (!b64) throw new Error("Formato HMAC inválido (tag|b64)");
        const data = base64ToBytes(b64);
        const expected = hmacSha256Hex(utf8Bytes(key), data);
        const ok = tag === expected;
        steps.push(`Etiqueta válida: ${ok ? "SÍ" : "NO"}`);
        return { text: ok ? bytesToUtf8(data) : `[HMAC INVÁLIDO] ${bytesToUtf8(data)}`, bytes: data, cells: makeCells(data), steps };
      }
    }

    if (id === "DIGITAL_SIG") {
      if (isEncrypt) {
        const h = sha256Hex(rawBytes);
        const sig = hmacSha256Hex(utf8Bytes(state.cert.thumbprint + key), hexToBytes(h));
        const env = JSON.stringify({ sig, sha256: h, thumb: state.cert.thumbprint, b64: bytesToBase64(rawBytes) });
        steps.push(`Digest: ${h.slice(0, 14)}…`, `Firma emitida por ${state.cert.subject}`);
        return { text: env, bytes: utf8Bytes(env), cells: makeCells(hexToBytes(sig)), steps };
      } else {
        const parsed = JSON.parse(isFile ? bytesToUtf8(input) : extractPayloadText(input));
        const data = base64ToBytes(parsed.b64);
        const h = sha256Hex(data);
        const expected = hmacSha256Hex(utf8Bytes(parsed.thumb + key), hexToBytes(h));
        const ok = h === parsed.sha256 && expected === parsed.sig;
        steps.push(`Firma digital: ${ok ? "AUTÉNTICA" : "ALTERADA"}`);
        return { text: ok ? bytesToUtf8(data) : `[FIRMA INVÁLIDA]`, bytes: data, cells: makeCells(data), steps };
      }
    }

    if (id === "DFT_SPECTRAL") {
      if (isEncrypt) {
        const phaseShift = (utf8Bytes(key).reduce((a, b) => a + b, 0) % 7) + 1;
        const spec = dftEncode(rawBytes, phaseShift);
        const json = JSON.stringify(spec);
        steps.push(`N=${rawBytes.length} muestras`, `Transformada DFT aplicada + fase ${phaseShift}`);
        return { text: json, bytes: utf8Bytes(json), cells: makeCells(rawBytes), steps };
      } else {
        const spec = JSON.parse(isFile ? bytesToUtf8(input) : extractPayloadText(input));
        const phaseShift = (utf8Bytes(key).reduce((a, b) => a + b, 0) % 7) + 1;
        const out = idftDecode(spec, phaseShift);
        steps.push(`IDFT reconstruida`, `${out.length} bytes exactos`);
        return { text: bytesToUtf8(out), bytes: out, cells: makeCells(out), steps };
      }
    }

    if (id === "LAGRANGE_SHAMIR") {
      const n = Math.min(8, Math.max(2, parseInt(key.match(/N=(\d+)/)?.[1] || "5", 10)));
      const k = Math.min(n, Math.max(2, parseInt(key.match(/K=(\d+)/)?.[1] || "3", 10)));
      if (isEncrypt) {
        const shares = shamirSplit(rawBytes, n, k);
        const txt = shares.map((s) => `${s.x}:${bytesToBase64(s.y)}`).join("\n");
        steps.push(`Umbral (K=${k}, N=${n}) en GF(256)`, `${n} participaciones generadas`);
        return { text: txt, bytes: utf8Bytes(txt), cells: makeCells(shares[0].y), steps };
      } else {
        const lines = (isFile ? bytesToUtf8(input) : extractPayloadText(input)).split(/\r?\n/).filter(Boolean);
        const shares = lines.map((l) => {
          const [xs, b64] = l.split(":");
          return { x: parseInt(xs, 10), y: base64ToBytes(b64) };
        });
        if (shares.length < 2) throw new Error("Se requieren >= 2 shares");
        const out = shamirCombine(shares);
        steps.push(`Interpolación de Lagrange f(0)`, `${out.length} bytes reconstruidos`);
        return { text: bytesToUtf8(out), bytes: out, cells: makeCells(out), steps };
      }
    }

    if (id === "LORENZ_SZ40") {
      const src = isEncrypt ? rawBytes : (isFile ? input : base64ToBytes(extractPayloadText(input)));
      const out = lorenzXor(src, key);
      steps.push(`12 ruedas (χ, ψ, μ) inicializadas`, `Flujo XOR autoinverso`);
      return { text: isEncrypt ? bytesToBase64(out) : bytesToUtf8(out), bytes: out, cells: makeCells(out), steps };
    }

    // AES_GCM, DES, TRIPLE_DES, CHACHA20, ECC, LSB_STEGO (text fallback), QUANTUM_PQC
    const keyBytes = sha256Bytes(utf8Bytes(`${id}:${key}`));
    const nonce = keyBytes.slice(0, 12);
    if (isEncrypt) {
      const cipher = chachaXor(rawBytes, keyBytes, nonce);
      const tag = hmacSha256Hex(keyBytes, cipher).slice(0, 16);
      const packed = `${tag}:${bytesToBase64(cipher)}`;
      steps.push(`Motor: ${id}`, `Bloque/Flujo + Tag ${tag}`, `Tamaño: ${cipher.length} B`);
      return { text: packed, bytes: utf8Bytes(packed), cells: makeCells(cipher), steps };
    } else {
      const raw = isFile ? bytesToUtf8(input) : extractPayloadText(input);
      const parts = raw.split(":");
      if (parts.length !== 2) throw new Error("Formato inválido (tag:b64)");
      const [tag, b64] = parts;
      const cipher = base64ToBytes(b64);
      const expected = hmacSha256Hex(keyBytes, cipher).slice(0, 16);
      if (tag !== expected) throw new Error("Clave incorrecta o tag inválido");
      const plain = chachaXor(cipher, keyBytes, nonce);
      steps.push(`Motor: ${id}`, `Tag verificado OK`, `Descifrado: ${plain.length} B`);
      return { text: bytesToUtf8(plain), bytes: plain, cells: makeCells(plain), steps };
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
      if (fmt === "bin") div.textContent = num.toString(2).padStart(8, "0");
      else if (fmt === "hex") div.textContent = `0x${hex}`;
      else div.textContent = hex;
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

  // --- Consultas View (Base de Datos Local + Panel Lateral Enviar) ---
  function loadConsultas() {
    try {
      const raw = localStorage.getItem(STORAGE_CONSULTAS);
      if (raw) return JSON.parse(raw);
    } catch (_) {}
    return [
      {
        id: 1,
        file: "NODO01_AES256GCM_20261116_204500_A1B2C3D4.zip",
        origin: "Local",
        algo: "AES-256-GCM",
        date: "2026-11-16 20:45",
        sha256: "a1b2c3d4e5f60718293a4b5c6d7e8f90",
        bytesBase64: btoa("demo-aes-payload")
      }
    ];
  }

  function saveConsultas() {
    localStorage.setItem(STORAGE_CONSULTAS, JSON.stringify(state.consultas));
  }

  function buildStandardZipName(algoId, shaHex) {
    const now = new Date();
    const pad = (n) => String(n).padStart(2, "0");
    const stamp = `${now.getUTCFullYear()}${pad(now.getUTCMonth() + 1)}${pad(now.getUTCDate())}_${pad(now.getUTCHours())}${pad(now.getUTCMinutes())}${pad(now.getUTCSeconds())}`;
    const cleanAlgo = algoId.replace(/[^A-Z0-9]/gi, "").toUpperCase();
    return `NODO01_${cleanAlgo}_${stamp}_${shaHex.slice(0, 8).toUpperCase()}.zip`;
  }

  function addConsultaRecord({ file, origin, algo, sha256, bytesBase64 }) {
    const now = new Date();
    const pad = (n) => String(n).padStart(2, "0");
    const date = `${now.getFullYear()}-${pad(now.getMonth() + 1)}-${pad(now.getDate())} ${pad(now.getHours())}:${pad(now.getMinutes())}`;
    state.consultas.unshift({
      id: Date.now() + Math.floor(Math.random() * 1000),
      file,
      origin,
      algo,
      date,
      sha256,
      bytesBase64: bytesBase64 || btoa(file)
    });
    saveConsultas();
    renderConsultas();
  }

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

    $("#drawerCloseBtn").addEventListener("click", closeSendDrawer);
    $("#drawerCancelBtn").addEventListener("click", closeSendDrawer);
    $("#sendDrawerBackdrop").addEventListener("click", closeSendDrawer);
    $("#drawerSendBtn").addEventListener("click", () => {
      const ip = $("#drawerTargetIp").value.trim();
      if (!ip) return toast("Ingresa IP:Puerto");
      const file = state.drawerItem?.file || "paquete.zip";
      closeSendDrawer();
      toast(`${file} enviado a ${ip}`);
    });

    renderConsultas();
  }

  function renderConsultas() {
    const body = $("#consultasBody");
    if (!body) return;
    const q = ($("#consultasSearch")?.value || "").trim().toLowerCase();
    body.innerHTML = "";

    state.consultas
      .filter((c) => state.consultasFilter === "all" || c.origin === state.consultasFilter)
      .filter((c) => !q || c.file.toLowerCase().includes(q) || c.algo.toLowerCase().includes(q))
      .forEach((item) => {
        const tr = document.createElement("tr");
        const originCls = item.origin === "Recibido" ? "badge-pending" : "cat-pill";
        tr.innerHTML = `
          <td class="input-mono" style="font-size:12px;">${item.file}</td>
          <td><span class="${originCls}">${item.origin}</span></td>
          <td>${item.algo}</td>
          <td class="input-mono" style="font-size:12px;">${item.date}</td>
          <td class="input-mono" style="font-size:12px;">${item.sha256.slice(0, 12)}…</td>
          <td class="td-center">
            <div class="tool-bottom-group" style="justify-content:center;">
              <button class="btn-chip c-download" data-id="${item.id}" style="height:28px; padding:0 12px; font-size:12px;">.ZIP</button>
              <button class="btn-solid c-send" data-id="${item.id}" style="height:28px; padding:0 12px; font-size:12px;">Enviar</button>
            </div>
          </td>
        `;
        body.appendChild(tr);
      });

    body.querySelectorAll(".c-send").forEach((btn) => {
      btn.addEventListener("click", () => {
        const item = state.consultas.find((c) => c.id === Number(btn.dataset.id));
        if (item) openSendDrawer(item);
      });
    });

    body.querySelectorAll(".c-download").forEach((btn) => {
      btn.addEventListener("click", () => {
        const item = state.consultas.find((c) => c.id === Number(btn.dataset.id));
        if (!item) return;
        const dataBytes = base64ToBytes(item.bytesBase64 || btoa(item.file));
        const manifest = {
          version: "1.0",
          sourceNode: "NODO-01",
          algorithm: item.algo,
          encryptedSha256: item.sha256,
          timestampUtc: new Date().toISOString()
        };
        const zipBlob = buildZipBlob([
          { name: "datos.enc", data: dataBytes },
          { name: "certificado.pem", data: utf8Bytes(buildPem(state.cert)) },
          { name: "manifest.json", data: utf8Bytes(JSON.stringify(manifest, null, 2)) }
        ]);
        triggerDownload(zipBlob, item.file, "application/zip");
      });
    });
  }

  function openSendDrawer(item) {
    state.drawerItem = item;
    $("#drawerFileName").textContent = item.file;
    $("#drawerAlgo").textContent = item.algo;
    $("#drawerSha").textContent = `${item.sha256.slice(0, 18)}…`;
    $("#sendDrawerBackdrop").classList.add("open");
    $("#sendDrawer").classList.add("open");
    $("#sendDrawer").setAttribute("aria-hidden", "false");
  }

  function closeSendDrawer() {
    $("#sendDrawerBackdrop").classList.remove("open");
    $("#sendDrawer").classList.remove("open");
    $("#sendDrawer").setAttribute("aria-hidden", "true");
  }

  // --- Math & Pure-JS Crypto Primitives ---
  function utf8Bytes(str) { return new TextEncoder().encode(str); }
  function bytesToUtf8(bytes) { return new TextDecoder().decode(bytes); }

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

  function hexToBytes(hex) {
    const out = new Uint8Array(hex.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
    return out;
  }

  function triggerDownload(content, filename, mime) {
    const blob = new Blob([content], { type: mime });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = filename;
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  }

  function toast(msg) {
    const el = $("#toast");
    el.textContent = msg;
    el.classList.add("show");
    clearTimeout(toast._t);
    toast._t = setTimeout(() => el.classList.remove("show"), 2200);
  }

  // Pure JS SHA-256
  const SHA_K = [
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
  ];

  function sha256Bytes(msg) {
    const l = msg.length * 8;
    const padLen = ((56 - ((msg.length + 1) % 64)) + 64) % 64;
    const buf = new Uint8Array(msg.length + 1 + padLen + 8);
    buf.set(msg);
    buf[msg.length] = 0x80;
    const dv = new DataView(buf.buffer);
    dv.setUint32(buf.length - 4, l >>> 0, false);
    dv.setUint32(buf.length - 8, Math.floor(l / 0x100000000), false);

    let H = [0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];
    const w = new Uint32Array(64);
    const rotr = (x, n) => (x >>> n) | (x << (32 - n));

    for (let i = 0; i < buf.length; i += 64) {
      for (let t = 0; t < 16; t++) w[t] = dv.getUint32(i + t * 4, false);
      for (let t = 16; t < 64; t++) {
        const s0 = rotr(w[t - 15], 7) ^ rotr(w[t - 15], 18) ^ (w[t - 15] >>> 3);
        const s1 = rotr(w[t - 2], 17) ^ rotr(w[t - 2], 19) ^ (w[t - 2] >>> 10);
        w[t] = (w[t - 16] + s0 + w[t - 7] + s1) >>> 0;
      }
      let [a, b, c, d, e, f, g, h] = H;
      for (let t = 0; t < 64; t++) {
        const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        const ch = (e & f) ^ ((~e) & g);
        const temp1 = (h + S1 + ch + SHA_K[t] + w[t]) >>> 0;
        const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        const maj = (a & b) ^ (a & c) ^ (b & c);
        const temp2 = (S0 + maj) >>> 0;
        h = g; g = f; f = e; e = (d + temp1) >>> 0;
        d = c; c = b; b = a; a = (temp1 + temp2) >>> 0;
      }
      H = H.map((v, idx) => (v + [a, b, c, d, e, f, g, h][idx]) >>> 0);
    }
    const out = new Uint8Array(32);
    const odv = new DataView(out.buffer);
    H.forEach((v, idx) => odv.setUint32(idx * 4, v, false));
    return out;
  }

  function sha256Hex(msg) {
    return Array.from(sha256Bytes(msg), (b) => b.toString(16).padStart(2, "0")).join("");
  }

  function hmacSha256Hex(key, msg) {
    const k = key.length > 64 ? sha256Bytes(key) : key;
    const ipad = new Uint8Array(64).fill(0x36);
    const opad = new Uint8Array(64).fill(0x5c);
    for (let i = 0; i < k.length; i++) { ipad[i] ^= k[i]; opad[i] ^= k[i]; }
    const innerInput = new Uint8Array(64 + msg.length);
    innerInput.set(ipad);
    innerInput.set(msg, 64);
    const inner = sha256Bytes(innerInput);
    const outerInput = new Uint8Array(96);
    outerInput.set(opad);
    outerInput.set(inner, 64);
    return sha256Hex(outerInput);
  }

  // ChaCha20 keystream XOR
  function chachaXor(input, key32, nonce12) {
    const rotl = (v, n) => ((v << n) | (v >>> (32 - n))) >>> 0;
    const qr = (s, a, b, c, d) => {
      s[a] = (s[a] + s[b]) >>> 0; s[d] = rotl(s[d] ^ s[a], 16);
      s[c] = (s[c] + s[d]) >>> 0; s[b] = rotl(s[b] ^ s[c], 12);
      s[a] = (s[a] + s[b]) >>> 0; s[d] = rotl(s[d] ^ s[a], 8);
      s[c] = (s[c] + s[d]) >>> 0; s[b] = rotl(s[b] ^ s[c], 7);
    };
    const out = new Uint8Array(input.length);
    const kdv = new DataView(key32.buffer, key32.byteOffset, 32);
    const ndv = new DataView(nonce12.buffer, nonce12.byteOffset, 12);
    for (let block = 0; block * 64 < input.length; block++) {
      const st = new Uint32Array([
        0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
        kdv.getUint32(0, true), kdv.getUint32(4, true), kdv.getUint32(8, true), kdv.getUint32(12, true),
        kdv.getUint32(16, true), kdv.getUint32(20, true), kdv.getUint32(24, true), kdv.getUint32(28, true),
        block, ndv.getUint32(0, true), ndv.getUint32(4, true), ndv.getUint32(8, true)
      ]);
      const wk = new Uint32Array(st);
      for (let i = 0; i < 10; i++) {
        qr(wk,0,4,8,12); qr(wk,1,5,9,13); qr(wk,2,6,10,14); qr(wk,3,7,11,15);
        qr(wk,0,5,10,15); qr(wk,1,6,11,12); qr(wk,2,7,8,13); qr(wk,3,4,9,14);
      }
      const ks = new Uint8Array(64);
      const ksDv = new DataView(ks.buffer);
      for (let i = 0; i < 16; i++) ksDv.setUint32(i * 4, (wk[i] + st[i]) >>> 0, true);
      for (let i = 0; i < 64 && block * 64 + i < input.length; i++) {
        out[block * 64 + i] = input[block * 64 + i] ^ ks[i];
      }
    }
    return out;
  }

  function modInverse(a, m) {
    let [oldR, r] = [a, m];
    let [oldS, s] = [1, 0];
    while (r !== 0) {
      const q = Math.floor(oldR / r);
      [oldR, r] = [r, oldR - q * r];
      [oldS, s] = [s, oldS - q * s];
    }
    return ((oldS % m) + m) % m;
  }

  function modPow(base, exp, mod) {
    let res = 1n;
    base %= mod;
    while (exp > 0n) {
      if (exp & 1n) res = (res * base) % mod;
      exp >>= 1n;
      base = (base * base) % mod;
    }
    return res;
  }

  function millerRabin(n, k) {
    if (n < 2n) return false;
    if (n === 2n || n === 3n) return true;
    if (n % 2n === 0n) return false;
    let d = n - 1n, s = 0;
    while (d % 2n === 0n) { d /= 2n; s++; }
    for (let i = 0; i < k; i++) {
      const a = BigInt(2 + (i * 7 % Number(n - 3n || 2n)));
      let x = modPow(a, d, n);
      if (x === 1n || x === n - 1n) continue;
      let passed = false;
      for (let r = 1; r < s; r++) {
        x = (x * x) % n;
        if (x === n - 1n) { passed = true; break; }
      }
      if (!passed) return false;
    }
    return true;
  }

  function fisherYatesPerm(len, seedStr) {
    let seed = sha256Bytes(utf8Bytes(seedStr)).reduce((acc, b, i) => (acc ^ (b << ((i % 4) * 8))) >>> 0, 0x9e3779b9) || 1;
    const perm = Array.from({ length: len }, (_, i) => i);
    for (let i = len - 1; i > 0; i--) {
      seed ^= seed << 13; seed ^= seed >>> 17; seed ^= seed << 5;
      const j = (seed >>> 0) % (i + 1);
      [perm[i], perm[j]] = [perm[j], perm[i]];
    }
    return perm;
  }

  function dftEncode(bytes, shift) {
    const N = bytes.length;
    const re = new Array(N).fill(0);
    const im = new Array(N).fill(0);
    for (let k = 0; k < N; k++) {
      for (let n = 0; n < N; n++) {
        const ang = (-2 * Math.PI * k * n) / N;
        re[k] += bytes[n] * Math.cos(ang);
        im[k] += bytes[n] * Math.sin(ang);
      }
      re[k] = Number(re[k].toFixed(4));
      im[k] = Number(im[k].toFixed(4));
    }
    const perm = fisherYatesPerm(N, String(shift));
    return { N, re: perm.map((p) => re[p]), im: perm.map((p) => im[p]) };
  }

  function idftDecode(spec, shift) {
    const { N, re, im } = spec;
    const perm = fisherYatesPerm(N, String(shift));
    const ure = new Array(N), uim = new Array(N);
    for (let i = 0; i < N; i++) { ure[perm[i]] = re[i]; uim[perm[i]] = im[i]; }
    const out = new Uint8Array(N);
    for (let n = 0; n < N; n++) {
      let sum = 0;
      for (let k = 0; k < N; k++) {
        const ang = (2 * Math.PI * k * n) / N;
        sum += ure[k] * Math.cos(ang) - uim[k] * Math.sin(ang);
      }
      out[n] = Math.max(0, Math.min(255, Math.round(sum / N)));
    }
    return out;
  }

  // GF(256) Shamir Secret Sharing
  function gfMul(a, b) {
    let p = 0;
    for (let i = 0; i < 8; i++) {
      if (b & 1) p ^= a;
      const hi = a & 0x80;
      a = (a << 1) & 0xff;
      if (hi) a ^= 0x1b;
      b >>= 1;
    }
    return p;
  }
  function gfInv(a) {
    if (a === 0) return 0;
    let res = 1;
    for (let i = 0; i < 254; i++) res = gfMul(res, a);
    return res;
  }
  function shamirSplit(secret, n, k) {
    const shares = Array.from({ length: n }, (_, i) => ({ x: i + 1, y: new Uint8Array(secret.length) }));
    for (let idx = 0; idx < secret.length; idx++) {
      const coeffs = [secret[idx]];
      for (let c = 1; c < k; c++) coeffs.push(Math.floor(Math.random() * 255) + 1);
      for (let s = 0; s < n; s++) {
        const x = shares[s].x;
        let val = 0;
        for (let c = k - 1; c >= 0; c--) val = gfMul(val, x) ^ coeffs[c];
        shares[s].y[idx] = val;
      }
    }
    return shares;
  }
  function shamirCombine(shares) {
    const len = shares[0].y.length;
    const out = new Uint8Array(len);
    for (let idx = 0; idx < len; idx++) {
      let acc = 0;
      for (let i = 0; i < shares.length; i++) {
        let num = 1, den = 1;
        for (let j = 0; j < shares.length; j++) {
          if (i === j) continue;
          num = gfMul(num, shares[j].x);
          den = gfMul(den, shares[i].x ^ shares[j].x);
        }
        acc ^= gfMul(shares[i].y[idx], gfMul(num, gfInv(den)));
      }
      out[idx] = acc;
    }
    return out;
  }

  function lorenzXor(src, keyStr) {
    const seed = sha256Bytes(utf8Bytes(keyStr));
    let chi = seed[0] | 1, psi = seed[1] | 1, mu = seed[2] | 1;
    const out = new Uint8Array(src.length);
    for (let i = 0; i < src.length; i++) {
      chi = ((chi << 1) | ((chi >> 4) ^ (chi >> 2)) & 1) & 0x1f;
      if (mu & 1) psi = ((psi << 1) | ((psi >> 4) ^ (psi >> 1)) & 1) & 0x1f;
      mu = ((mu << 1) | ((mu >> 5) ^ (mu >> 3)) & 1) & 0x3f;
      const ks = ((chi ^ psi) << 3) | (chi & 0x07);
      out[i] = src[i] ^ ks;
    }
    return out;
  }

  // --- Requests View (Aceptar / Rechazar .ZIP por IP) ---
  function initRequests() {
    $("#simIncomingBtn").addEventListener("click", () => {
      const nextId = (state.requests[state.requests.length - 1]?.id || 0) + 1;
      const octet = 10 + Math.floor(Math.random() * 40);
      const visible = ALGORITHMS.filter((a) => state.configs[a.id].visible);
      const algoObj = visible[Math.floor(Math.random() * Math.max(1, visible.length))];
      const algo = algoObj?.name || "AES-256-GCM";
      const fakeSha = sha256Hex(utf8Bytes(`req-${nextId}-${Date.now()}`));
      state.requests.unshift({
        id: nextId,
        ip: `192.168.1.${octet}:5000`,
        file: buildStandardZipName(algoObj?.id || "AES256GCM", fakeSha).replace("NODO01", `NODO${octet}`),
        algo,
        sigValid: true,
        status: "Pendiente",
        sha256: fakeSha
      });
      renderRequests();
      toast("Solicitud recibida");
    });

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
        <td class="input-mono">${req.ip}</td>
        <td class="input-mono">${req.file}</td>
        <td>${req.algo}</td>
        <td><span class="${req.sigValid ? "badge-ok" : "badge-err"}">${req.sigValid ? "X.509 OK" : "Inválida"}</span></td>
        <td><span class="${statusCls}">${req.status}</span></td>
        <td class="td-center"><div class="tool-bottom-group" style="justify-content:center;">${actionsHtml}</div></td>
      `;
      body.appendChild(tr);
    });

    body.querySelectorAll(".req-accept").forEach((btn) => {
      btn.addEventListener("click", () => {
        const req = state.requests.find((r) => r.id === Number(btn.dataset.id));
        if (!req) return;
        req.status = "Aceptada";
        addConsultaRecord({
          file: req.file,
          origin: "Recibido",
          algo: req.algo,
          sha256: req.sha256 || sha256Hex(utf8Bytes(req.file)),
          bytesBase64: btoa(req.file)
        });
        renderRequests();
        toast(`Aceptada -> Consultas`);
      });
    });

    body.querySelectorAll(".req-reject").forEach((btn) => {
      btn.addEventListener("click", () => {
        const req = state.requests.find((r) => r.id === Number(btn.dataset.id));
        if (!req) return;
        req.status = "Rechazada";
        renderRequests();
        toast(`Rechazada (${req.file})`);
      });
    });
  }

  // Pure-JS STORE ZIP Builder (datos.enc + certificado.pem + manifest.json)
  function crc32(bytes) {
    let crc = 0xffffffff;
    for (let i = 0; i < bytes.length; i++) {
      crc ^= bytes[i];
      for (let j = 0; j < 8; j++) {
        crc = (crc >>> 1) ^ (crc & 1 ? 0xedb88320 : 0);
      }
    }
    return (crc ^ 0xffffffff) >>> 0;
  }

  function buildZipBlob(files) {
    const localParts = [];
    const centralParts = [];
    let offset = 0;

    files.forEach((f) => {
      const nameBytes = utf8Bytes(f.name);
      const data = f.data instanceof Uint8Array ? f.data : new Uint8Array(f.data);
      const crc = crc32(data);

      const lfh = new Uint8Array(30 + nameBytes.length);
      const ldv = new DataView(lfh.buffer);
      ldv.setUint32(0, 0x04034b50, true);
      ldv.setUint16(4, 20, true);
      ldv.setUint16(8, 0, true);
      ldv.setUint32(14, crc, true);
      ldv.setUint32(18, data.length, true);
      ldv.setUint32(22, data.length, true);
      ldv.setUint16(26, nameBytes.length, true);
      lfh.set(nameBytes, 30);

      localParts.push(lfh, data);

      const cdfh = new Uint8Array(46 + nameBytes.length);
      const cdv = new DataView(cdfh.buffer);
      cdv.setUint32(0, 0x02014b50, true);
      cdv.setUint16(4, 20, true);
      cdv.setUint16(6, 20, true);
      cdv.setUint16(10, 0, true);
      cdv.setUint32(16, crc, true);
      cdv.setUint32(20, data.length, true);
      cdv.setUint32(24, data.length, true);
      cdv.setUint16(28, nameBytes.length, true);
      cdv.setUint32(42, offset, true);
      cdfh.set(nameBytes, 46);

      centralParts.push(cdfh);
      offset += lfh.length + data.length;
    });

    const cdSize = centralParts.reduce((s, p) => s + p.length, 0);
    const eocd = new Uint8Array(22);
    const edv = new DataView(eocd.buffer);
    edv.setUint32(0, 0x06054b50, true);
    edv.setUint16(8, files.length, true);
    edv.setUint16(10, files.length, true);
    edv.setUint32(12, cdSize, true);
    edv.setUint32(16, offset, true);

    return new Blob([...localParts, ...centralParts, eocd], { type: "application/zip" });
  }

  // --- Boot ---
  state.cert = loadCert();
  initTheme();
  initNav();
  initOperate();
  initInspector();
  initConsultas();
  initRequests();
  initPresets();
  renderSettings();
  syncVisibleAlgorithms();
})();
