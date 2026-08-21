/* OPEN-SOURCE repo showcase — pulls live data from the GitHub REST API */
const REPO = "AHMADOAFRIDI/OPEN-SOURCE";
const API = "https://api.github.com/repos/" + REPO;
const CACHE_TTL = 5 * 60 * 1000; // 5 minutes

const $ = (id) => document.getElementById(id);

const icons = {
  stars: '<svg viewBox="0 0 24 24" width="15" height="15" fill="#fbbf24"><path d="M12 2l3.09 6.26L22 9.27l-5 4.87 1.18 6.88L12 17.77l-6.18 3.25L7 14.14 2 9.27l6.91-1.01L12 2z"/></svg>',
  forks: '<svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M7 18V15a3 3 0 0 1 3-3h4a3 3 0 0 1 3 3v3"/><circle cx="7" cy="18" r="2"/><circle cx="17" cy="18" r="2"/><circle cx="7" cy="6" r="2"/></svg>',
  watchers: '<svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>',
  issues: '<svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="1.5" fill="currentColor"/></svg>',
  license: '<svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/><path d="M16 13H8"/><path d="M16 17H8"/></svg>',
  language: '<svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 5h16"/><path d="M12 5v14"/><path d="M7 19h10"/><path d="M5 9l-2 3 2 3"/><path d="M19 9l2 3-2 3"/></svg>',
  calendar: '<svg viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="18" height="18" rx="2"/><path d="M16 2v4"/><path d="M8 2v4"/><path d="M3 10h18"/></svg>',
  clock: '<svg viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 3"/></svg>',
  star: '<svg viewBox="0 0 24 24" width="12" height="12" fill="#fbbf24"><path d="M12 2l3.09 6.26L22 9.27l-5 4.87 1.18 6.88L12 17.77l-6.18 3.25L7 14.14 2 9.27l6.91-1.01L12 2z"/></svg>',
};

const fmt = new Intl.NumberFormat("en-US");
const timeAgo = (iso) => {
  const s = (Date.now() - new Date(iso).getTime()) / 1000;
  if (s < 60) return "just now";
  if (s < 3600) return Math.floor(s / 60) + "m ago";
  if (s < 86400) return Math.floor(s / 3600) + "h ago";
  if (s < 86400 * 30) return Math.floor(s / 86400) + "d ago";
  return new Date(iso).toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
};

/* ---------- tiny cached fetch ---------- */
async function cachedFetch(key, url) {
  try {
    const hit = JSON.parse(localStorage.getItem("showcase:" + key));
    if (hit && Date.now() - hit.t < CACHE_TTL) return hit.data;
  } catch (_) {}
  const res = await fetch(url, { headers: { Accept: "application/vnd.github+json" } });
  if (!res.ok) throw new Error("GitHub API " + res.status);
  const data = await res.json();
  try { localStorage.setItem("showcase:" + key, JSON.stringify({ t: Date.now(), data })); } catch (_) {}
  return data;
}

async function fetchForks() {
  const all = [];
  let page = 1;
  for (;;) {
    const batch = await cachedFetch(
      "forks-p" + page,
      `${API}/forks?sort=newest&per_page=100&page=${page}`
    );
    all.push(...batch);
    if (batch.length < 100 || page >= 3) break; // cap at 300 forks
    page++;
  }
  return all;
}

/* ---------- state ---------- */
let repo = null, forks = [], contributors = [];
let sortMode = "newest";
let query = "";

/* ---------- render ---------- */
function renderHero(r) {
  $("repoAvatar").src = r.owner.avatar_url + "&s=168";
  $("repoAvatar").alt = r.full_name;
  $("repoKicker").textContent = (r.owner.type === "Organization" ? "Organization" : "User") + " repository";
  $("repoName").textContent = r.name;
  $("repoDesc").textContent = r.description || "No description provided.";
  $("repoLink").href = r.html_url;
  $("forksLink").href = r.html_url + "/forks";
  $("forksLink2").href = r.html_url + "/forks";
  $("repoMeta").innerHTML = `
    <a class="chip chip-primary" href="${r.html_url}" target="_blank" rel="noopener">${icons.star} ${fmt.format(r.stargazers_count)} stars</a>
    ${r.license ? `<span class="chip chip-license">${icons.license} ${r.license.spdx_id}</span>` : ""}
  `;
  document.title = `${r.full_name} — Repo Showcase`;
}

const statColors = ["#6366f1", "#22d3ee", "#34d399", "#f472b6", "#fbbf24", "#a78bfa", "#f87171", "#4ade80"];

function renderStats(r) {
  const rows = [
    { label: "Stars", value: fmt.format(r.stargazers_count), icon: icons.stars },
    { label: "Forks", value: fmt.format(r.forks_count), icon: icons.forks },
    { label: "Watchers", value: fmt.format(r.subscribers_count), icon: icons.watchers },
    { label: "Open Issues", value: fmt.format(r.open_issues_count), icon: icons.issues },
    { label: "License", value: r.license ? r.license.spdx_id : "None", icon: icons.license },
    { label: "Language", value: r.language || "—", icon: icons.language },
    { label: "Created", value: new Date(r.created_at).toLocaleDateString(undefined, { year: "numeric", month: "short" }), icon: icons.calendar },
    { label: "Updated", value: timeAgo(r.updated_at), icon: icons.clock },
  ];
  $("statsGrid").innerHTML = rows.map((s, i) => `
    <div class="stat card" style="--stat-color:${statColors[i % statColors.length]}">
      <div class="stat-label" style="display:flex;align-items:center;gap:6px;">${s.icon} ${s.label}</div>
      <div class="stat-value">${s.value}</div>
    </div>`).join("");
}

function forkCard(f, i) {
  const isDefaultBranchFork = f.default_branch === "main" || f.default_branch === "master";
  return `
  <div class="fork card" style="animation-delay:${Math.min(i * 40, 400)}ms">
    <div class="fork-top">
      <img class="fork-avatar" src="${f.owner.avatar_url}&s=84" alt="${f.owner.login}" loading="lazy" />
      <div style="min-width:0">
        <div class="fork-user"><a href="${f.owner.html_url}" target="_blank" rel="noopener">${f.owner.login}</a></div>
        <div class="fork-name"><a class="link" href="${f.html_url}" target="_blank" rel="noopener">${f.full_name}</a></div>
      </div>
    </div>
    <div class="fork-body">
      <span class="fork-date">${icons.clock} ${timeAgo(f.created_at)}</span>
      <span class="fork-stars">${icons.star} ${fmt.format(f.stargazers_count)}</span>
    </div>
    <div style="display:flex;gap:6px;flex-wrap:wrap">
      <span class="chip chip-primary">${isDefaultBranchFork ? "default branch" : f.default_branch}</span>
      ${f.description ? `<span class="chip chip-license" title="${f.description.replace(/"/g, "&quot;")}">${f.description.slice(0, 40)}${f.description.length > 40 ? "…" : ""}</span>` : ""}
    </div>
  </div>`;
}

function renderForks() {
  const q = query.toLowerCase();
  const list = forks.filter((f) => (f.owner.login + " " + f.full_name).toLowerCase().includes(q));
  const grid = $("forkGrid");
  $("forkEmpty").classList.toggle("hidden", list.length > 0);
  $("forkCount").textContent = `${list.length} fork${list.length === 1 ? "" : "s"} shown · ${forks.length} total`;
  grid.innerHTML = list.map(forkCard).join("") ||
    `<div class="fork card" style="grid-column:1/-1;color:var(--muted);align-items:center;justify-content:center;padding:28px;text-align:center;">No forks yet — be the first! 🚀</div>`;
}

function renderContributors() {
  $("contribGrid").innerHTML = contributors.length
    ? contributors.map((c, i) => `
        <div class="contrib card" style="animation-delay:${i * 50}ms">
          <img class="contrib-avatar" src="${c.avatar_url}&s=80" alt="${c.login}" loading="lazy" />
          <div style="min-width:0">
            <div class="contrib-name"><a class="link" href="${c.html_url}" target="_blank" rel="noopener">${c.login}</a></div>
            <div class="contrib-count">${c.contributions} commits</div>
          </div>
          <span class="contrib-rank">#${i + 1}</span>
        </div>`).join("")
    : `<div class="fork card" style="grid-column:1/-1;color:var(--muted);align-items:center;justify-content:center;padding:24px;text-align:center;">No contributors listed.</div>`;
}

/* ---------- sorting / filtering ---------- */
function setSort(mode) {
  sortMode = mode;
  $("sortLabel").textContent = mode[0].toUpperCase() + mode.slice(1);
  if (mode === "newest") forks.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
  else if (mode === "oldest") forks.sort((a, b) => new Date(a.created_at) - new Date(b.created_at));
  else forks.sort((a, b) => a.owner.login.localeCompare(b.owner.login));
  renderForks();
}

/* ---------- toast ---------- */
let toastTimer;
function toast(msg) {
  const t = $("toast");
  t.textContent = msg;
  t.classList.remove("hidden");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.add("hidden"), 4000);
}

/* ---------- boot ---------- */
async function load() {
  $("refreshBtn").disabled = true;
  try {
    [repo, forks, contributors] = await Promise.all([
      cachedFetch("repo", API),
      fetchForks(),
      cachedFetch("contributors", `${API}/contributors?per_page=12`).catch(() => []),
    ]);
    renderHero(repo);
    renderStats(repo);
    setSort("newest");
    renderContributors();
    toast("Data refreshed from GitHub ✓");
  } catch (err) {
    console.error(err);
    $("statsGrid").innerHTML = "";
    $("forkGrid").innerHTML = `<div class="fork card" style="grid-column:1/-1;color:var(--muted);align-items:center;justify-content:center;padding:28px;text-align:center;">
      ⚠️ Could not reach the GitHub API (rate limit or network).<br>
      <a class="link" href="https://github.com/${REPO}" target="_blank" rel="noopener">Visit the repository directly →</a>
    </div>`;
    toast("GitHub API error — showing cached data if available");
  } finally {
    $("refreshBtn").disabled = false;
  }
}

$("refreshBtn").addEventListener("click", () => {
  Object.keys(localStorage).filter((k) => k.startsWith("showcase:")).forEach((k) => localStorage.removeItem(k));
  load();
});
$("forkSearch").addEventListener("input", (e) => { query = e.target.value.trim(); renderForks(); });
$("sortBtn").addEventListener("click", () => {
  const next = sortMode === "newest" ? "oldest" : sortMode === "oldest" ? "name" : "newest";
  setSort(next);
});

load();
