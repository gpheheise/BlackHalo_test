/* Why BlackHalo: live figures from the public record, topic picker and discussion brief.
   Reads the same data/ files as the record page; nothing is sent anywhere. */

const DATA = "data/";
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const nf = new Intl.NumberFormat("en-GB");
const num = (v) => nf.format(v);
const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
const monthFmt = { format: (t) => { const d = new Date(t); return `${MONTHS[d.getUTCMonth()]} ${d.getUTCFullYear()}`; } };
const CLASS_SHORT = { "Cross-Site Scripting": "XSS", "Insecure Direct Object Reference": "IDOR", "Server-Side Request Forgery": "SSRF", "Cross-Site Request Forgery": "CSRF" };

const TOPICS = {
  programme: "A continuous enterprise programme",
  assessment: "A focused baseline for one service",
  research: "Software vulnerability research",
  nofix: "A finding with no fix available",
};

async function getJSON(path) {
  const res = await fetch(DATA + path, { cache: "no-cache" });
  if (!res.ok) throw new Error(`${path}: HTTP ${res.status}`);
  return res.json();
}

/* ---------- live figures ---------- */
async function renderProof() {
  const [stats, emb] = await Promise.all([getJSON("stats.json").catch(() => null), getJSON("embargo.json").catch(() => null)]);
  if (!stats && !emb) return;
  const rows = emb?.rows ?? [];
  const ix = Object.fromEntries((emb?.fields ?? []).map((k, i) => [k, i]));
  const released = stats?.released?.total ?? 0;
  const reported = stats?.reported?.total ?? rows.length + released;
  if (!reported) return;
  const fixedEmb = ix.fixedDay == null ? 0 : rows.filter((r) => r[ix.fixedDay] != null).length;
  const fixedBefore = fixedEmb + (stats?.response?.fixedBefore ?? 0);

  // first month with a report: from the reported months, else the oldest embargo row
  const months = Object.keys(stats?.reported?.months ?? {}).sort();
  let since = months[0] ? Date.parse(`${months[0]}-01T00:00:00Z`) : null;
  if (since == null && ix.reported != null && rows.length) since = Math.min(...rows.map((r) => r[ix.reported] * 1000));

  // most common class across everything reported
  let top = stats?.reported?.classes?.[0];
  if (!top && rows.length && ix.type != null) {
    const c = new Map();
    for (const r of rows) { const t = emb.types?.[r[ix.type]]; if (t) c.set(t, (c.get(t) ?? 0) + 1); }
    const best = [...c].sort((a, b) => b[1] - a[1])[0];
    if (best) top = [best[0], best[1]];
  }

  $("#p-rep").textContent = num(reported);
  $("#p-since").textContent = since ? ` since ${monthFmt.format(since)}` : "";
  $("#p-dis").textContent = num(released);
  $("#p-fix").textContent = num(fixedBefore);
  if (top) {
    const [type, n] = top;
    $("#p-cls").textContent = num(n);
    $("#p-cls-lab").textContent = `${CLASS_SHORT[type] || type}, the most common class`;
  } else {
    $("#p-cls").closest(".w-stat").hidden = true;
  }
  $("#proof-wrap").hidden = false;

  // tie the scenario and the research engagement to the record
  const access = (stats?.reported?.classes ?? []).find(([t]) => /access control|direct object reference/i.test(t));
  const note = $("#sc-note");
  if (access && note) {
    note.textContent = `${access[0]} accounts for ${num(access[1])} of the ${num(reported)} findings in our public research record.`;
    note.hidden = false;
  }
  const live = $("#eng-live");
  if (live) {
    live.innerHTML = `<b class="num">${num(reported)}</b> findings reported to vendors${since ? ` since ${monthFmt.format(since)}` : ""}, <b class="num">${num(released)}</b> disclosed so far.`;
    live.hidden = false;
  }
}

/* ---------- topic picker, enquiry and brief ---------- */
function selectedTopic() {
  return $("input[name=topic]:checked")?.value ?? "programme";
}

function brief() {
  return [
    "BlackHalo · discussion brief",
    "",
    `Topic: ${TOPICS[selectedTopic()]}`,
    "Business services: (the services and systems to start with)",
    "Current practice: (existing assessments, scanning, reporting and change processes)",
    "Objective: (what you need to know or decide)",
    "Constraints: (environments, testing windows, permitted actions, stopping conditions)",
    "Timing: (when you need first results)",
    "Contact: (name, role, email)",
  ].join("\n");
}

/* The enquiry button opens the LHIND contact form and puts the brief on the clipboard.
   If the button carries data-mailto="team@example", it becomes a pre-filled e-mail instead. */
function syncEnquiry() {
  const topic = TOPICS[selectedTopic()];
  const now = $("#topic-now");
  if (now) now.textContent = topic;
  const a = $("#enquiry");
  const mail = a?.dataset.mailto;
  if (mail) {
    a.href = `mailto:${mail}?subject=${encodeURIComponent(`BlackHalo enquiry: ${topic}`)}&body=${encodeURIComponent(brief())}`;
    a.removeAttribute("target");
  }
}

async function copyBrief() {
  try { await navigator.clipboard.writeText(brief()); return true; } catch { return false; }
}

let toastTimer;
function toast(msg) {
  const t = $("#toast");
  t.textContent = msg;
  t.classList.add("on");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.remove("on"), 2600);
}

function wire() {
  $("#year").textContent = new Date().getFullYear();

  // engagement links preselect their topic
  for (const a of $$("[data-topic]")) {
    a.addEventListener("click", () => {
      const input = $(`input[name=topic][value="${a.dataset.topic}"]`);
      if (input) input.checked = true;
    });
  }
  // "Discuss your current exposure" in the no-fix section
  const gapBtn = $("#gap .btn");
  gapBtn?.addEventListener("click", () => { $('input[name=topic][value="nofix"]').checked = true; });

  $("#copy-brief").addEventListener("click", async () => {
    const out = $("#brief-out");
    if (await copyBrief()) {
      out.hidden = true;
      toast("Brief copied. Paste it into your message to the LHIND team.");
    } else {
      // clipboard blocked (embedded view, older browser): show it to copy by hand
      out.value = brief();
      out.hidden = false;
      out.focus();
      out.select();
      toast("Select the brief below and copy it.");
    }
  });

  // main enquiry: carry the chosen topic along (clipboard for the web form, or a pre-filled e-mail)
  const enquiry = $("#enquiry");
  if (enquiry && !enquiry.dataset.mailto) {
    enquiry.addEventListener("click", () => {
      copyBrief().then((ok) => toast(ok ? "Your topic and brief are on the clipboard. Paste them into the contact form." : "Use \u201cOnly copy the brief\u201d if you want a template for your message."));
    });
  }

  for (const r of $$("input[name=topic]")) r.addEventListener("change", () => {
    const out = $("#brief-out");
    if (!out.hidden) out.value = brief();
    syncEnquiry();
  });
  for (const a of $$("[data-topic]")) a.addEventListener("click", syncEnquiry);
  gapBtn?.addEventListener("click", syncEnquiry);
  syncEnquiry();
}

wire();
renderProof().catch(() => {});
