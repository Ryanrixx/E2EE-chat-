const socket = io();

let myUsername = null;
let myKeys = null; 
let knownPubs = {}; 


// --------- UTIL HELPERS ---------
function bufToB64(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)));
}

function b64ToBuf(b64) {
  const str = atob(b64);
  const bytes = new Uint8Array(str.length);
  for (let i = 0; i < str.length; i++) bytes[i] = str.charCodeAt(i);
  return bytes;
}

function pemToArrayBuffer(pem) {
  const b64 = pem.replace(/-----.*KEY-----/g, "").replace(/\s/g, "");
  return b64ToBuf(b64).buffer;
}


// --------- RSA KEY EXPORT / IMPORT ---------
async function exportPublicKeyToPem(key) {
  const spki = await crypto.subtle.exportKey("spki", key);
  const b64 = bufToB64(spki);
  return `-----BEGIN PUBLIC KEY-----\n${b64.match(/.{1,64}/g).join('\n')}\n-----END PUBLIC KEY-----`;
}

async function importPublicKeyFromPem(pem) {
  const buf = pemToArrayBuffer(pem);
  return crypto.subtle.importKey("spki", buf, { name: "RSA-OAEP", hash: "SHA-256" }, false, ["encrypt"]);
}

async function generateRSA() {
  return crypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true,
    ["encrypt", "decrypt"]
  );
}


// ---------- HYBRID ENCRYPTION (AES-GCM + RSA-OAEP) ----------
async function hybridEncryptForRecipient(recipientPem, plaintext) {
  const aesKey = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const enc = new TextEncoder();

  const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, aesKey, enc.encode(plaintext));
  const bytes = new Uint8Array(encrypted);

  const tag = bytes.slice(bytes.length - 16);
  const ciphertext = bytes.slice(0, bytes.length - 16);

  const rawAes = await crypto.subtle.exportKey("raw", aesKey);
  const recipientPub = await importPublicKeyFromPem(recipientPem);

  const encryptedKey = await crypto.subtle.encrypt({ name: "RSA-OAEP" }, recipientPub, rawAes);

  return {
    encryptedKey: bufToB64(encryptedKey),
    iv: bufToB64(iv.buffer),
    ciphertext: bufToB64(ciphertext.buffer),
    tag: bufToB64(tag.buffer)
  };
}


async function hybridDecryptWithMyKey(payload) {
  const encryptedKeyBuf = b64ToBuf(payload.encryptedKey).buffer;
  const rawAes = await crypto.subtle.decrypt({ name: "RSA-OAEP" }, myKeys.privateKey, encryptedKeyBuf);
  const aesKey = await crypto.subtle.importKey("raw", rawAes, { name: "AES-GCM" }, false, ["decrypt"]);

  const iv = b64ToBuf(payload.iv);
  const ciphertext = b64ToBuf(payload.ciphertext);
  const tag = b64ToBuf(payload.tag);

  const combined = new Uint8Array(ciphertext.length + tag.length);
  combined.set(ciphertext);
  combined.set(tag, ciphertext.length);

  const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, aesKey, combined);
  return new TextDecoder().decode(decrypted);
}


// ----------- REGISTER -----------
async function register() {
  const username = document.getElementById("username").value.trim();
  if (!username) return alert("Enter a username");

  myUsername = username;
  myKeys = await generateRSA();

  const publicPem = await exportPublicKeyToPem(myKeys.publicKey);
  knownPubs[username] = publicPem;

  socket.emit("register", { username, publicKeyPem: publicPem });

  document.getElementById("you").textContent = `You: ${username}`;
  document.getElementById("status").textContent = "Status: connected & encrypted ✅";
}


// ---------- SEND MESSAGE ----------
const recipientSelect = document.getElementById("recipient");
document.getElementById("sendBtn").addEventListener("click", async () => {
  const to = recipientSelect.value;
  const msg = document.getElementById("messageInput").value.trim();
  if (!to) return alert("Select recipient");
  if (!msg) return;

  if (!knownPubs[to]) {
    socket.emit("request_pub", { username: to });
    await new Promise(res => setTimeout(res, 200));
  }

  const payload = await hybridEncryptForRecipient(knownPubs[to], msg);

  socket.emit("message", { from: myUsername, to, payload });
  appendMessage(`Me ➜ ${to}: ${msg}`, "me");

  document.getElementById("messageInput").value = "";
});


// ---------- RECEIVE FROM SERVER ----------
socket.on("message", async ({ from, payload }) => {
  const txt = await hybridDecryptWithMyKey(payload);
  appendMessage(`${from}: ${txt}`, "other");
});

socket.on("ack", async (payload) => {
  const txt = await hybridDecryptWithMyKey(payload);
  appendMessage(`✅ ACK: ${txt}`, "ack");
});


// ---------- UI UPDATES ----------
socket.on("user_list", (list) => {
  const userListEl = document.getElementById("userList");
  userListEl.innerHTML = "";
  recipientSelect.innerHTML = `<option value="">Select recipient</option>`;

  list.forEach(u => {
    const li = document.createElement("li");
    li.textContent = u;
    userListEl.appendChild(li);

    if (u !== myUsername) {
      const opt = document.createElement("option");
      opt.value = u;
      opt.textContent = u;
      recipientSelect.appendChild(opt);
    }
  });
});

socket.on("public_key", ({ username, publicKeyPem }) => {
  if (publicKeyPem) knownPubs[username] = publicKeyPem;
});


// ---------- DISPLAY CHAT ----------
const messagesEl = document.getElementById("messages");
function appendMessage(text, type) {
  const d = document.createElement("div");
  d.className = `msg ${type}`;
  d.textContent = text;
  messagesEl.appendChild(d);
  messagesEl.scrollTop = messagesEl.scrollHeight;
}


// REGISTER BUTTON
document.getElementById("registerBtn").addEventListener("click", register);
