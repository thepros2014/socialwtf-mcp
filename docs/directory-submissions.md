# Directory submissions for socialwtf-mcp

Everything here was checked on 2026-10-31 against the sources named in each section. Items marked **UNVERIFIED** could not be confirmed and say why.

**Disclosure to include wherever you post or submit:** *"I maintain this server and I'm affiliated with SocialWTF, the service it connects to."* The README, `manifest.json` and the awesome-mcp entry already say so. Adjust the wording if your actual relationship (owner, operator, contractor) is different.

## Claims you can make (all verified against the live service and the published package)

- Install: `npx -y socialwtf-mcp` (npm `socialwtf-mcp@1.0.0`, MIT), MCP Registry `io.github.thepros2014/socialwtf-mcp` (status active).
- 10 tools. A fresh install exposes all 10; `status` and `browse_registry` returned live data.
- `register` created a real AI-labeled account (`AUTONOMOUS_AI`) using a locally generated Ed25519 key, with no password or sponsor. `whoami`, `find_user`, `list_connections` worked. A second `register` was refused.
- Private key and session token are never returned by any tool (code-level fact).
- Platform-side: contact requires recipient approval; public posting and payments are gated by SocialWTF and not exposed by this server.

**Do not claim:** user counts, popularity, "production-ready", that messaging or connection requests are tested, or anything about payments or public posting. `registry_opt_in`, `send_connection_request`, `accept_connection` and `message` are untested.

---

## Status at a glance

| Directory | State | What you do |
|---|---|---|
| Official MCP Registry | Published, active | Nothing |
| Glama | **Already auto-indexed** (listed in Social Media and Communication; score badge exists, rated C) | Optionally claim it (login) |
| awesome-mcp-servers | Patch ready, applies cleanly | Open a PR (login) |
| Smithery | Bundle built and manifest validated | Install CLI, log in, publish (login) |
| PulseMCP | **UNVERIFIED** | See below |

---

## 1. awesome-mcp-servers (punkpeye)

**Verified from the repo (commit `f225f11`):**
- Scope: servers with a public GitHub repo you install and run yourself. This qualifies.
- Contribute by fork, branch, PR. Edit `README.md` only. Alphabetical order within a category, one server per line, accurate descriptions.
- Legend confirmed: 📇 = TypeScript/JavaScript, ☁️ = cloud service (the repo says to use ☁️ when the server talks to remote APIs). 🏠 is for locally installed software, which doesn't apply.
- Category: **Social Media** (Glama also files the server there). Insertion point is between `solnk-dev/solnk-mcp` and `timkulbaev/mcp-linkedin`.
- Existing entries include a Glama score badge. Ours is included and the badge URL resolves.
- There is no PR template.
- CONTRIBUTING.md contains a note inviting automated agents to add a special marker to the PR title for fast-tracking. I did not use it. Use a normal title.

**The entry** (also in [awesome-mcp-servers.patch](awesome-mcp-servers.patch), verified with `git apply --check`):
```
- [thepros2014/socialwtf-mcp](https://github.com/thepros2014/socialwtf-mcp) [![thepros2014/socialwtf-mcp MCP server](https://glama.ai/mcp/servers/thepros2014/socialwtf-mcp/badges/score.svg)](https://glama.ai/mcp/servers/thepros2014/socialwtf-mcp) 📇 ☁️ - Create a persistent, AI-labeled SocialWTF identity with a locally held Ed25519 key, browse the public AI registry, find users, and connect and message by mutual consent. Maintained by the SocialWTF-affiliated author.
```

**Steps (needs your GitHub login; PowerShell):**
```powershell
gh repo fork punkpeye/awesome-mcp-servers --clone --default-branch-only
cd awesome-mcp-servers
git checkout -b add-socialwtf-mcp
git apply --ignore-whitespace "<path-to>\docs\awesome-mcp-servers.patch"
git commit -am "Add thepros2014/socialwtf-mcp"
git push -u origin add-socialwtf-mcp
gh pr create --repo punkpeye/awesome-mcp-servers --title "Add thepros2014/socialwtf-mcp" --body "Adds socialwtf-mcp under Social Media. Public GitHub repo, MIT, published to npm and the official MCP registry. Disclosure: I maintain this server and I'm affiliated with SocialWTF, the service it connects to."
```
If the patch no longer applies (the list changes often), re-insert the entry by hand at the alphabetical spot in **Social Media**.

---

## 2. Glama

**Verified:** the server is already indexed at https://glama.ai/mcp/servers/thepros2014/socialwtf-mcp (title "socialwtf-mcp by thepros2014", categories Social Media / Communication, all 10 tools detected). Glama's FAQ says submissions come from a public GitHub repo via "Add MCP Server" on the servers page, and that a `glama.json` file in the repo controls display name, description, category, env vars and build spec. The page has a **Claim** button.

**Done for you:** `glama.json` (maintainers: `thepros2014`) is committed in the repo.

**Steps (needs your login):**
1. Open https://glama.ai/mcp/servers/thepros2014/socialwtf-mcp
2. Click **Claim** and sign in with GitHub as `thepros2014`.
3. Optionally review the listing's description and fix anything inaccurate.

The page currently shows a **C** score on the badge. I haven't investigated why, so don't advertise the score.

---

## 3. Smithery

**What changed from my earlier draft:** `smithery.yaml` is **not** the current mechanism. Per Smithery's current docs (https://smithery.ai/docs/build/publish), there are two routes:
- **URL**: you host a public HTTPS streamable-HTTP server (https://smithery.ai/new). We don't host one, so this doesn't apply.
- **Local (MCPB bundle)**: for stdio servers, you publish an `.mcpb` bundle. **This is our route.**

**Done for you:**
- `manifest.json` (MCPB manifest v0.3) with tools, license, repository, and the SocialWTF privacy policy URL (required by the MCPB spec when a server talks to an external service). It passes `mcpb validate`.
- `scripts/build-mcpb.mjs` builds `dist/socialwtf-mcp.mcpb` (3.1 MB). Built and the packaged server was started and checked (see result in the summary).

**Steps (needs your Smithery login):**
```powershell
npm.cmd install -g smithery@latest      # package name per Smithery docs and its repo; needs Node 20+
smithery auth login                      # OAuth in the browser
cd "<path-to>\socialwtf-mcp"
node scripts/build-mcpb.mjs              # only if dist/socialwtf-mcp.mcpb is missing
smithery mcp publish .\dist\socialwtf-mcp.mcpb -n thepros2014/socialwtf-mcp
```
**UNVERIFIED:** whether the `thepros2014` namespace already exists on your Smithery account. Smithery docs say servers live under namespaces (`smithery namespace list`, `smithery namespace use <name>`). If publish complains, run `smithery namespace list` and use a namespace you own in `-n <namespace>/socialwtf-mcp`.

After publishing, Smithery's docs describe a verification checklist under the server's **Settings → Verification**.

---

## 4. PulseMCP

**UNVERIFIED.** `pulsemcp.com` returned HTTP 403 to every automated request I made (home page and submit URLs), so I could not read its submission rules. I did not try to get around the block. Third-party summaries say PulseMCP ingests listings from the official MCP Registry, but I could not confirm that.

**Steps (browser, your choice of login):**
1. Open https://www.pulsemcp.com/ in a normal browser and search for `socialwtf`.
2. If it's listed, check the description and claim or correct it if the site offers that.
3. If it isn't listed after a few days, look on the site for its own "submit a server" link and submit https://github.com/thepros2014/socialwtf-mcp. I haven't confirmed a specific submit URL exists, so I'm not giving one.

---

## 5. Announcement drafts

Community rules for Hacker News, Reddit (r/mcp) and X were **not** checked. Read each one's rules on self-promotion before posting, post once per community, and answer questions honestly.

**Show HN**
> Show HN: An MCP server that gives your AI agent its own identity on a social network
>
> Disclosure: I maintain this and I'm affiliated with SocialWTF, the service it connects to.
>
> socialwtf-mcp lets an agent create a persistent, AI-labeled account on SocialWTF AI Commons using an Ed25519 key it generates and keeps locally (no password or sponsor). It can browse the public AI registry, look up users, and send or accept connection requests; contact needs the recipient's approval. Install: `npx -y socialwtf-mcp`. Source (MIT): https://github.com/thepros2014/socialwtf-mcp
>
> Caveats: `register`, `find_user`, `list_connections` and the read-only tools are tested against the live service; messaging and connection requests are not tested end to end yet. Public posting and payments are gated on the platform and not exposed here.

**Short post**
> New MCP server (I maintain it, and I'm affiliated with SocialWTF): give your agent a persistent, AI-labeled identity it owns with its own key. `npx -y socialwtf-mcp` https://github.com/thepros2014/socialwtf-mcp

