// Utility
const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => Array.from(document.querySelectorAll(sel));

// State
let credentialId = null;     // Personalausweis
let credentialDegree = null; // Hochschulabschluss
let currentPresentation = null;
let currentRequest = null;   // { type: 'age' | 'residence' | 'degree' | 'kyc' | 'manual', via: 'qr'|'direct'|'manual' }

// ---------------- Helpers ----------------
function flash(el) {
  el.style.outline = "2px solid #93c5fd";
  setTimeout(() => el.style.outline = "none", 350);
}

// pseudo-random short hash for visual SD-JWT "blinding"
function blindHash(key) {
  const src = key + ":" + Date.now() + ":" + Math.random().toString(36).slice(2);
  let h = 0;
  for (let i = 0; i < src.length; i++) h = Math.imul(31, h) + src.charCodeAt(i) | 0;
  const x = (h >>> 0).toString(16);
  return x.slice(0, 8);
}

// ---------------- Issuer ----------------
function issueId() {
  credentialId = {
    vct: "https://credentials.example.com/id_credential",
    issuer: "EU ID Authority",
    subject: "did:example:holder123",
    format: "vc+sd-jwt",
    type: "IdCredential",
    issuedAt: new Date().toISOString(),
    claims: {
      name: "Max Mustermann",
      dob: "2000-05-01",
      street: "Hauptstrasse 12",
      city: "Frankfurt",
      nationality: "German",
      ageOver18: true,
      residenceEU: true
    },
    signature: "sd-jwt-signature-id-xyz"
  };
  $("#credentialId").textContent = JSON.stringify(credentialId, null, 2);
  renderSdView();
  flash($("#issuer"));
}

function issueDegree() {
  credentialDegree = {
    vct: "https://credentials.example.com/degree_credential",
    issuer: "University Frankfurt",
    subject: "did:example:holder123",
    format: "vc+sd-jwt",
    type: "DegreeCredential",
    issuedAt: new Date().toISOString(),
    claims: {
      degree: "M.Sc. Informatik",
      university: "University Frankfurt",
      year: 2022
    },
    signature: "sd-jwt-signature-degree-abc"
  };
  $("#credentialDegree").textContent = JSON.stringify(credentialDegree, null, 2);
  renderSdView();
  flash($("#issuer"));
}

// ---------------- Wallet: SD-JWT Visual ----------------
function renderSdView() {
  // Personalausweis claims
  const idView = $("#sdViewId");
  idView.innerHTML = "";
  const idForm = document.forms.disclosureId?.elements;
  if (credentialId && idForm) {
    const entries = [
      ["name", credentialId.claims.name],
      ["dob", credentialId.claims.dob],
      ["ageOver18", credentialId.claims.ageOver18],
      ["street", credentialId.claims.street],
      ["city", credentialId.claims.city],
      ["nationality", credentialId.claims.nationality],
      ["residenceEU", credentialId.claims.residenceEU]
    ];
    for (const [k, v] of entries) {
      const disclosed = idForm[k].checked;
      idView.appendChild(makeChip("ID", k, v, disclosed));
    }
  }
  // Degree claims
  const dView = $("#sdViewDegree");
  dView.innerHTML = "";
  const dForm = document.forms.disclosureDegree?.elements;
  if (credentialDegree && dForm) {
    const entries = [
      ["degree", credentialDegree.claims.degree],
      ["university", credentialDegree.claims.university],
      ["year", credentialDegree.claims.year]
    ];
    for (const [k, v] of entries) {
      const disclosed = dForm[k].checked;
      dView.appendChild(makeChip("DEG", k, v, disclosed));
    }
  }
}

function makeChip(ns, key, val, disclosed) {
  const chip = document.createElement("span");
  chip.className = "chip" + (disclosed ? "" : " blinded");
  const lock = document.createElement("span");
  lock.className = "lock";
  lock.textContent = disclosed ? "🔓" : "🔒";
  const keyEl = document.createElement("span");
  keyEl.className = "key";
  keyEl.textContent = `${ns}:${key}`;
  const valEl = document.createElement("span");
  valEl.className = "val";
  valEl.textContent = disclosed ? String(val) : `#${blindHash(ns+":"+key)}`; // show hash placeholder
  chip.append(lock, keyEl, valEl);
  return chip;
}

// Build disclosed + blinded for JSON
function buildPresentationParts() {
  const disclosed = {};
  const blinded = {};
  // ID
  const f = document.forms.disclosureId?.elements;
  if (credentialId && f) {
    disclosed.id = {};
    blinded.id = {};
    [["name","name"],["dob","dob"],["ageOver18","ageOver18"],["street","street"],["city","city"],["nationality","nationality"],["residenceEU","residenceEU"]].forEach(([k]) => {
      if (f[k].checked) {
        disclosed.id[k] = credentialId.claims[k];
      } else {
        blinded.id[k] = { salted_hash: `h_${blindHash("id:"+k)}` };
      }
    });
    if (!Object.keys(disclosed.id).length) delete disclosed.id;
    if (!Object.keys(blinded.id).length) delete blinded.id;
  }
  // Degree
  const g = document.forms.disclosureDegree?.elements;
  if (credentialDegree && g) {
    disclosed.degree = {};
    blinded.degree = {};
    [["degree","degree"],["university","university"],["year","year"]].forEach(([k]) => {
      if (g[k].checked) {
        disclosed.degree[k] = credentialDegree.claims[k];
      } else {
        blinded.degree[k] = { salted_hash: `h_${blindHash("deg:"+k)}` };
      }
    });
    if (!Object.keys(disclosed.degree).length) delete disclosed.degree;
    if (!Object.keys(blinded.degree).length) delete blinded.degree;
  }
  if (!Object.keys(disclosed).length) delete disclosed.id;
  if (!Object.keys(blinded).length) delete blinded.id;
  return { disclosed, blinded };
}

// ---------------- Wallet: Presentation ----------------
function preview() {
  const { disclosed, blinded } = buildPresentationParts();
  const presentation = {
    type: "verifiable_presentation",
    format: "sd-jwt-derived",
    disclosed,
    blinded, // visual aid – not real SD-JWT structure
    proof: {
      type: "sd-jwt",
      derivedFrom: [
        credentialId ? credentialId.signature : null,
        credentialDegree ? credentialDegree.signature : null
      ].filter(Boolean),
      created: new Date().toISOString()
    }
  };
  $("#presentation").textContent = JSON.stringify(presentation, null, 2);
  currentPresentation = presentation;
  flash($("#wallet"));
}

function openConsentModal() {
  const list = $("#shareList");
  list.innerHTML = "";
  const { disclosed } = buildPresentationParts();
  const addLi = (t) => { const li=document.createElement("li"); li.textContent=t; list.appendChild(li); };
  if (disclosed?.id) Object.keys(disclosed.id).forEach(k => addLi(`Personalausweis: ${k}`));
  if (disclosed?.degree) Object.keys(disclosed.degree).forEach(k => addLi(`Hochschulabschluss: ${k}`));
  if (!disclosed?.id && !disclosed?.degree) addLi("Keine Attribute ausgewählt");
  // Request label
  $("#modalRequest").textContent = currentRequest
    ? (currentRequest.type === "age" ? "Age Verification (over 18)" :
       currentRequest.type === "residence" ? "Residency in EU" :
       currentRequest.type === "degree" ? "University Degree" :
       currentRequest.type === "kyc" ? "Open Bank Account (KYC)" : "Manual Presentation")
    : "Manual Presentation";
  $("#modal").classList.remove("hidden");
  $("#modal").setAttribute("aria-hidden","false");
}

function closeModal() {
  $("#modal").classList.add("hidden");
  $("#modal").setAttribute("aria-hidden","true");
}

// ---------------- Verifier ----------------
function showQr(which) {
  // which: 'A' age, 'B' residence, 'C' degree, 'D' kyc
  const map = { A: 'age', B: 'residence', C: 'degree', D: 'kyc' };
  const type = map[which];
  currentRequest = { type, via: 'qr', created: new Date().toISOString() };
  const labelEl = $("#qr" + which + "Label");
  labelEl.textContent = "QR: On (" + type.toUpperCase() + ")";
  $("#qr" + which).classList.add("pulse");
  setTimeout(() => $("#qr" + which).classList.remove("pulse"), 1200);
}

function directRequest(which) {
  const map = { A: 'age', B: 'residence', C: 'degree', D: 'kyc' };
  currentRequest = { type: map[which], via: 'direct', created: new Date().toISOString() };
  verify(which);
}

function verify(which) {
  const p = currentPresentation;
  const resEl = $("#result" + which);
  let ok = false;
  if (!p || !p.disclosed) {
    resEl.textContent = "❌ No valid proof (no Presentation)";
    resEl.className = "result bad";
    return;
  }
  if (which === 'A') {
    ok = !!p.disclosed.id && p.disclosed.id.ageOver18 === true;
  } else if (which === 'B') {
    ok = !!p.disclosed.id && p.disclosed.id.residenceEU === true;
  } else if (which === 'C') {
    ok = !!p.disclosed.degree && !!p.disclosed.degree.degree && !!p.disclosed.degree.university;
  } else if (which === 'D') {
    ok = !!p.disclosed.id && p.disclosed.id.ageOver18 === true && p.disclosed.id.residenceEU === true;
  }
  if (ok) {
    const okMsg = {
      A: "✅ Verified: Person is over 18",
      B: "✅ Verified: EU residence confirmed",
      C: "✅ Verified: University degree certified",
      D: "✅ Verified: KYC verification (age & residence) completed"
    }[which];
    resEl.textContent = okMsg;
    resEl.className = "result ok";
  } else {
    resEl.textContent = "❌ Invalid proof (required attributes are missing)";
    resEl.className = "result bad";
  }
  flash($("#verifier"));
}

// ---------------- QR Scan (Wallet) ----------------
function scanQr() {
  if (!currentRequest || currentRequest.via !== 'qr') {
    alert("No QR active. Please display a QR at the verifier.");
    return;
  }
  openConsentModal();
}

// ---------------- Wire up ----------------
document.addEventListener("DOMContentLoaded", () => {
  // Issuer
  $("#btnIssueId").addEventListener("click", issueId);
  $("#btnIssueDegree").addEventListener("click", issueDegree);
  // Wallet
  $("#btnPreview").addEventListener("click", (e)=>{ e.preventDefault(); preview(); });
  $("#btnPresent").addEventListener("click", (e)=>{ e.preventDefault(); currentRequest = { type: 'manual', via: 'manual' }; openConsentModal(); });
  $("#btnScanQr").addEventListener("click", (e)=>{ e.preventDefault(); scanQr(); });
  // Checkbox changes -> re-render SD-JWT chips
  ["disclosureId","disclosureDegree"].forEach(formId => {
    const form = document.getElementById(formId);
    form.addEventListener("change", renderSdView);
  });
  // Verifier Events
  [["A","btnShowQrA","btnRequestA"],["B","btnShowQrB","btnRequestB"],["C","btnShowQrC","btnRequestC"],["D","btnShowQrD","btnRequestD"]]
    .forEach(([w, showId, reqId]) => {
      document.getElementById(showId).addEventListener("click", ()=> showQr(w));
      document.getElementById(reqId).addEventListener("click", ()=> directRequest(w));
    });
  // Modal
  $("#modalCancel").addEventListener("click", closeModal);
  $("#modalConfirm").addEventListener("click", () => {
    preview();   // build currentPresentation
    closeModal();
    if (currentRequest && ['age','residence','degree','kyc'].includes(currentRequest.type)) {
      const rev = { age:'A', residence:'B', degree:'C', kyc:'D' }[currentRequest.type];
      verify(rev);
    }
  });
});
