"use strict";

const $ = (sel) => document.querySelector(sel);

let session = null;
let pollTimer = null;

async function api(path, opts = {}) {
  const res = await fetch(path, {
    method: opts.method || "GET",
    headers: { "Content-Type": "application/json" },
    body: opts.body ? JSON.stringify(opts.body) : undefined,
  });
  let data = {};
  try { data = await res.json(); } catch (e) { /* пустой ответ */ }
  if (!res.ok) {
    const detail = data.detail || `Ошибка ${res.status}`;
    throw new Error(typeof detail === "string" ? detail : JSON.stringify(detail));
  }
  return data;
}

function showError(sel, message) {
  const el = $(sel);
  el.textContent = message;
  el.classList.add("show");
}

function hideError(sel) {
  $(sel).classList.remove("show");
}

function fmtElapsed(startedAt) {
  if (!startedAt) return "–";
  let sec = Math.max(0, Math.floor(Date.now() / 1000 - startedAt));
  const d = Math.floor(sec / 86400); sec %= 86400;
  const h = Math.floor(sec / 3600); sec %= 3600;
  const m = Math.floor(sec / 60);
  if (d) return `${d} д ${h} ч`;
  if (h) return `${h} ч ${m} мин`;
  return `${m} мин`;
}

// ---------------------------------------------------------------- рендер

function render() {
  if (!session) return;
  const step = session.step;

  for (let i = 1; i <= 6; i++) {
    const el = $(`#step${i}`);
    el.classList.toggle("open", i === step);
    el.classList.toggle("done", i < step);
    el.classList.toggle("locked", i > step);
    const num = el.querySelector(".step-num");
    num.textContent = i < step ? "✓" : String(i);
  }

  // шаг 2: публичный ключ
  if (session.api_public_key_pem) {
    $("#public-key").textContent = session.api_public_key_pem.trim();
  }
  if (session.oci) {
    $("#config-ok").innerHTML =
      `<span class="ok-badge">✓ Подключено · регион ${session.oci.region}</span>`;
  }

  // шаг 3: подзадачи автонастройки
  const setup = session.setup || {};
  const icons = { pending: "⏳", running: '<span class="spinner"></span>', done: "✅" };
  $("#setup-steps").innerHTML = (setup.steps || [])
    .map((s) => `<li><span class="icon">${icons[s.status] || "⏳"}</span>${s.name}</li>`)
    .join("");
  if (setup.status === "error") {
    showError("#setup-error", setup.error || "Ошибка автонастройки");
    $("#btn-step3").disabled = false;
    $("#btn-step3").textContent = "Повторить";
  } else if (setup.status === "running") {
    hideError("#setup-error");
    $("#btn-step3").disabled = true;
    $("#btn-step3").textContent = "Настраиваем...";
  } else {
    $("#btn-step3").disabled = false;
  }

  // шаг 5: охота
  const hunt = session.hunt || {};
  $("#hunt-attempts").textContent = hunt.attempts || 0;
  $("#hunt-elapsed").textContent = fmtElapsed(hunt.started_at);
  $("#hunt-log").textContent = hunt.last_message || "Ожидание...";
  const stateLabels = {
    running: '<span class="spinner"></span>',
    provisioning: "🚀",
    success: "🎉",
    error: "⛔",
    stopped: "⏸",
    idle: "–",
  };
  $("#hunt-state").innerHTML = stateLabels[hunt.status] || "–";
  if (hunt.status === "error") {
    showError("#hunt-error", hunt.error || "Ошибка");
  } else {
    hideError("#hunt-error");
  }
  const active = hunt.status === "running" || hunt.status === "provisioning";
  $("#btn-hunt-stop").style.display = active ? "" : "none";
  $("#btn-hunt-restart").style.display =
    !active && (hunt.status === "stopped" || hunt.status === "error") ? "" : "none";

  // шаг 6: успех
  if (hunt.status === "success") {
    $("#vm-ip").textContent = hunt.public_ip || "смотрите в консоли Oracle";
    if (session.network) $("#vm-image").textContent = session.network.image_name || "Ubuntu";
    $("#ssh-cmd").textContent = `ssh -i oracle_vm_key ubuntu@${hunt.public_ip || "<IP>"}`;
  }

  schedulePoll();
}

function schedulePoll() {
  const setupRunning = session.setup && session.setup.status === "running";
  const huntActive = session.hunt &&
    ["running", "provisioning"].includes(session.hunt.status);
  clearTimeout(pollTimer);
  if (setupRunning || huntActive) {
    pollTimer = setTimeout(refresh, 3000);
  }
}

async function refresh() {
  try {
    session = await api("/api/session");
    render();
  } catch (e) {
    // сеть моргнула — попробуем ещё раз позже
    pollTimer = setTimeout(refresh, 5000);
  }
}

// ---------------------------------------------------------------- события

document.addEventListener("click", async (ev) => {
  const btn = ev.target.closest(".copy-btn");
  if (!btn) return;
  const text = $(btn.dataset.copy).textContent;
  try {
    await navigator.clipboard.writeText(text);
  } catch (e) {
    const ta = document.createElement("textarea");
    ta.value = text;
    document.body.appendChild(ta);
    ta.select();
    document.execCommand("copy");
    ta.remove();
  }
  btn.textContent = "Скопировано ✓";
  setTimeout(() => { btn.textContent = "Копировать"; }, 2000);
});

$("#btn-step1").addEventListener("click", async () => {
  $("#btn-step1").disabled = true;
  try {
    await api("/api/registration_done", { method: "POST" });
    await refresh();
  } finally {
    $("#btn-step1").disabled = false;
  }
});

$("#btn-step2").addEventListener("click", async () => {
  hideError("#config-error");
  const snippet = $("#config-snippet").value.trim();
  if (!snippet) {
    showError("#config-error", "Вставьте сниппет конфига из консоли Oracle.");
    return;
  }
  $("#btn-step2").disabled = true;
  $("#btn-step2").textContent = "Проверяем...";
  try {
    await api("/api/submit_config", { method: "POST", body: { snippet } });
    await refresh();
  } catch (e) {
    showError("#config-error", e.message);
  } finally {
    $("#btn-step2").disabled = false;
    $("#btn-step2").textContent = "Проверить подключение";
  }
});

$("#btn-step3").addEventListener("click", async () => {
  hideError("#setup-error");
  try {
    await api("/api/setup", { method: "POST" });
    await refresh();
  } catch (e) {
    showError("#setup-error", e.message);
  }
});

$("#vm-ocpus").addEventListener("input", () => {
  const ocpus = Number($("#vm-ocpus").value);
  $("#ocpus-label").textContent = ocpus;
  $("#mem-label").textContent = ocpus * 6;
});

$("#btn-step4").addEventListener("click", async () => {
  const ocpus = Number($("#vm-ocpus").value);
  $("#btn-step4").disabled = true;
  try {
    await api("/api/start_hunt", {
      method: "POST",
      body: {
        display_name: $("#vm-name").value.trim() || "free-arm-vm",
        ocpus,
        memory_gb: ocpus * 6,
      },
    });
    await refresh();
  } catch (e) {
    alert(e.message);
  } finally {
    $("#btn-step4").disabled = false;
  }
});

$("#btn-hunt-stop").addEventListener("click", async () => {
  if (!confirm("Остановить охоту?")) return;
  await api("/api/stop_hunt", { method: "POST" });
  await refresh();
});

$("#btn-hunt-restart").addEventListener("click", async () => {
  const hunt = session.hunt;
  await api("/api/start_hunt", {
    method: "POST",
    body: {
      display_name: hunt.display_name || "free-arm-vm",
      ocpus: hunt.ocpus || 4,
      memory_gb: hunt.memory_gb || 24,
    },
  });
  await refresh();
});

$("#btn-download-key").addEventListener("click", () => {
  window.location.href = "/api/download_key";
});

$("#btn-wipe").addEventListener("click", async () => {
  if (!confirm("Удалить все ваши данные с сервиса? Убедитесь, что SSH-ключ скачан — восстановить его будет нельзя.")) return;
  await api("/api/wipe", { method: "POST" });
  await refresh();
  alert("Данные удалены. Спасибо, что воспользовались!");
});

refresh();
