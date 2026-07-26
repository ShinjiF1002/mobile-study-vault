const encoder = new TextEncoder();
const decoder = new TextDecoder();
const unlockPanel = document.querySelector("#unlock-panel");
const unlockForm = document.querySelector("#unlock-form");
const passwordInput = document.querySelector("#password");
const unlockStatus = document.querySelector("#unlock-status");
const library = document.querySelector("#library");
const documentList = document.querySelector("#document-list");
const lockButton = document.querySelector("#lock-button");
const reader = document.querySelector("#reader");
const readerFrame = document.querySelector("#reader-frame");
const readerTitle = document.querySelector("#reader-title");
const readerClose = document.querySelector("#reader-close");

let password = "";
let activeBlobUrl = "";

async function deriveKey(secret, salt, iterations) {
  const material = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    "PBKDF2",
    false,
    ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"]
  );
}

async function decryptAsset(path, secret) {
  const response = await fetch(path);
  if (!response.ok) throw new Error(`Fetch failed: ${response.status}`);
  const bytes = new Uint8Array(await response.arrayBuffer());
  if (bytes.length < 37 || decoder.decode(bytes.slice(0, 5)) !== "SVLT1") {
    throw new Error("Invalid encrypted asset");
  }
  const iterations = new DataView(bytes.buffer, bytes.byteOffset + 5, 4).getUint32(0, false);
  const salt = bytes.slice(9, 25);
  const iv = bytes.slice(25, 37);
  const ciphertext = bytes.slice(37);
  const key = await deriveKey(secret, salt, iterations);
  const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ciphertext);
  return new Uint8Array(plain);
}

function closeReader() {
  reader.close();
  readerFrame.removeAttribute("src");
  if (activeBlobUrl) URL.revokeObjectURL(activeBlobUrl);
  activeBlobUrl = "";
}

async function openDocument(item, button) {
  const priorText = button.querySelector(".document-meta").textContent;
  button.disabled = true;
  button.querySelector(".document-meta").textContent = "復号しています…";
  try {
    const bytes = await decryptAsset(item.asset, password);
    const blob = new Blob([bytes], { type: item.mime });
    activeBlobUrl = URL.createObjectURL(blob);

    if (item.mime === "application/pdf") {
      const pdfWindow = window.open(activeBlobUrl, "_blank", "noopener");
      if (!pdfWindow) window.location.assign(activeBlobUrl);
      setTimeout(() => {
        if (activeBlobUrl) URL.revokeObjectURL(activeBlobUrl);
        activeBlobUrl = "";
      }, 120000);
      return;
    }

    readerTitle.textContent = item.title;
    readerFrame.src = activeBlobUrl;
    reader.showModal();
  } catch (error) {
    console.error(error);
    alert("資料を開けませんでした。通信状態を確認して、もう一度お試しください。");
  } finally {
    button.disabled = false;
    button.querySelector(".document-meta").textContent = priorText;
  }
}

function renderLibrary(manifest) {
  documentList.replaceChildren();
  manifest.documents.forEach((item, index) => {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "document-card";

    const number = document.createElement("span");
    number.className = "document-index";
    number.textContent = String(index + 1).padStart(2, "0");

    const copy = document.createElement("span");
    copy.className = "document-copy";
    const title = document.createElement("strong");
    title.className = "document-title";
    title.textContent = item.title;
    const meta = document.createElement("span");
    meta.className = "document-meta";
    meta.textContent = item.meta;
    copy.append(title, meta);

    const arrow = document.createElement("span");
    arrow.className = "document-arrow";
    arrow.setAttribute("aria-hidden", "true");
    arrow.textContent = "›";

    button.append(number, copy, arrow);
    button.addEventListener("click", () => openDocument(item, button));
    documentList.append(button);
  });
}

unlockForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const submitButton = unlockForm.querySelector("button");
  submitButton.disabled = true;
  unlockStatus.classList.remove("error");
  unlockStatus.textContent = "確認しています…";
  try {
    const candidate = passwordInput.value;
    const manifestBytes = await decryptAsset("./vault/manifest.bin", candidate);
    const manifest = JSON.parse(decoder.decode(manifestBytes));
    password = candidate;
    localStorage.setItem("study-vault-password", candidate);
    renderLibrary(manifest);
    unlockPanel.hidden = true;
    library.hidden = false;
    passwordInput.value = "";
  } catch (error) {
    console.error(error);
    localStorage.removeItem("study-vault-password");
    unlockStatus.classList.add("error");
    unlockStatus.textContent = "パスワードが違うか、データを取得できません。";
    passwordInput.select();
  } finally {
    submitButton.disabled = false;
  }
});

lockButton.addEventListener("click", () => {
  closeReader();
  password = "";
  localStorage.removeItem("study-vault-password");
  documentList.replaceChildren();
  library.hidden = true;
  unlockPanel.hidden = false;
  unlockStatus.classList.remove("error");
  unlockStatus.textContent = "ロックしました。この端末に記憶したパスワードも削除しました。";
  passwordInput.focus();
});

readerClose.addEventListener("click", closeReader);
reader.addEventListener("cancel", (event) => {
  event.preventDefault();
  closeReader();
});

if ("serviceWorker" in navigator) {
  navigator.serviceWorker.register("./sw.js").catch(console.error);
}

const savedPassword = localStorage.getItem("study-vault-password");
if (savedPassword) {
  passwordInput.value = savedPassword;
  unlockForm.requestSubmit();
}
