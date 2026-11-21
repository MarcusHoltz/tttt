<h1 align="center">message-me-cve</h1>

<p align="center">
  <strong>Tell it what you run. It messages your phone when a serious CVE hits.</strong><br>
  CISA KEV and NVD alerts per project, to Telegram or ntfy.
</p>


---


<p align="center">
  <picture><img src="https://raw.githubusercontent.com/MarcusHoltz/marcusholtz.github.io/refs/heads/main/assets/img/header/header--cvenotify--nvd-notification-per-project-github.jpg" alt="message-me-cve header banner: NVD and CISA KEV notifications per project, sent from GitHub Actions"></picture>
</p>

<p align="center">
  <img src="https://github.com/MarcusHoltz/tttt/actions/workflows/message-me-cve.yml/badge.svg" alt="Check status">
</p>

<p align="center">
  <a href="#-quickstart">Quickstart</a> ·
  <a href="#-schedule">Schedule</a> ·
  <a href="#-watch-lists">Watch lists</a> ·
  <a href="#-troubleshooting">Troubleshooting</a> ·
  <a href="#-reference">Reference</a>
</p>


---


## 👍 Overview

Each project gets a watch list, one product per line: `php`, `nginx`,
`wordpress`. At the times you set, a GitHub Actions run checks every list
against:

| Source | What you get |
|---|---|
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Exploited in the wild. Sent as `ACT NOW`, urgent. |
| [NVD](https://nvd.nist.gov/) | New CRITICAL and HIGH CVEs, published in the last 90 days. |
| [CVE.org](https://www.cve.org/) | The product list of new CVEs NVD has not analyzed yet. |

What lands on your phone:

```text
[shop, blog] ACT NOW [php]: exploited PHP CVE-2024-4577
[shop] CRITICAL 9.8 [nginx]: CVE-2026-12345
message-me-cve: cannot check NVD
message-me-cve: NVD OK again
```

No message means nothing new matched. Failures are messaged too.


* * *


## 🚀 Quickstart

> [!IMPORTANT]
> Watch lists and run pages show what your servers run. Use a private
> repo for real infrastructure.
>
> - Do not fork: a fork of a public repo is always public. Create an
>   empty private repo and push a clone of this one (step 1).
> - Actions minutes in a private repo count against your plan's included
>   usage. Public repos are free. Two runs a day is about 60 minutes a
>   month.

1. 🏗️ **Push this repo to your own GitHub repo**, `main` first:

   ```bash
   git clone https://github.com/MarcusHoltz/tttt.git message-me-cve
   cd message-me-cve
   git remote set-url origin https://github.com/<owner>/<repo>.git
   git push -u origin main
   ```

2. 🔑 **Add secrets** in **Settings > Secrets and variables > Actions**.
   At least one channel:

   | Secret | |
   |---|---|
   | `TELEGRAM_BOT_TOKEN` and `TELEGRAM_CHAT_ID` | Telegram, set both. See [Phone](#-phone) |
   | `NTFY_URL` | ntfy, `https://ntfy.sh/<topic>` |
   | `NVD_API_KEY` | Optional, [free](https://nvd.nist.gov/developers/request-an-api-key). Faster NVD paging |

3. 🌿 **Create the state branch** once:

   ```bash
   git switch --orphan state && git commit --allow-empty -m state
   git push -u origin state && git switch main
   ```

4. 📝 **Write the watch lists**, one per project, in `profiles/<name>.txt`.
   Push to `main`. The next run uses them.
5. ▶️ **Run it once**: **Actions > message-me-cve > Run workflow**. Green
   means configuration, feeds and state work. Delivery is only tested when
   something is sent: send a [test message](#-phone).
6. ⏰ **Schedule it**, see [Schedule](#-schedule).


* * *


## ⏰ Schedule

An outside cron service starts the run through GitHub's API. GitHub's own
cron (`schedule:`) is not used: it drops runs. See
[Why not GitHub's cron](#why-not-githubs-cron).

### 1. Token

**GitHub > Settings > Developer settings > Personal access tokens >
Fine-grained tokens > Generate new token**

- Repository access: only this repo. A private repo must be selected
  here, or every call returns `404`.
- Permissions: **Actions: Read and write**. Nothing else.
- Note the expiry date. When it passes, runs stop.

### 2. cron-job.org

[cron-job.org](https://cron-job.org/) (free), create one job.

**Common** tab:

- URL, with your owner and repo name. Same for public and private repos:
  `https://api.github.com/repos/<owner>/<repo>/actions/workflows/message-me-cve.yml/dispatches`
- Execution schedule: **Custom**, for example `0 6,14 * * *` for 06:00
  and 14:00. "Every day at" runs once a day.

**Advanced** tab:

- Headers, three rows, key and value in separate fields:

  | Key | Value |
  |---|---|
  | `Authorization` | `Bearer <token>`: the word Bearer, one space, the token |
  | `Accept` | `application/vnd.github+json` |
  | `X-GitHub-Api-Version` | `2026-03-10` |

- Time zone: yours. The schedule uses it.
- Request method `POST`. Request body `{"ref":"main"}`.
- Ignore the "Sending JSON data?" Content-Type suggestion. GitHub accepts
  the body without it.

**Notifications** tab: email on failure.

### 3. Test and save

**TEST RUN**, then **SAVE**. Unsaved changes are not used.

A working call returns `200` and the new run:

```json
{"workflow_run_id":44918328720,"run_url":"...","html_url":"https://github.com/<owner>/<repo>/actions/runs/44918328720"}
```

The run shows up under **Actions > message-me-cve** at once. Anything else:
see [Troubleshooting](#-troubleshooting).

- Turn off: pause the cron job, or **Actions > message-me-cve > ... >
  Disable workflow**.
- Any cron that can send this POST works, for example `curl` in a
  server's crontab.


* * *


## 📝 Watch lists

```text
# shop.example.com
php
nginx
apache http server
```

- One product per line. `#` starts a comment. Case does not matter.
- Matched as whole words against vendor and product names, never
  descriptions: `php` does not match a WordPress plugin that mentions PHP.
- Use product names: `apache http server`, not `apache`, which matches
  every Apache project.
- `python python` means CPython only. NVD files every PyPI package under
  vendor `python`.
- A new word sends every KEV entry for it on the next run, more than 5 as
  one combined list. Older NVD CVEs for it are not sent.


* * *


## 📱 Phone

- **Telegram**: create a bot with [@BotFather](https://t.me/BotFather),
  message it once, then read `message.chat.id` from
  `https://api.telegram.org/bot<token>/getUpdates`.
- **ntfy**: install the [ntfy](https://ntfy.sh/) app and subscribe to a
  long random topic. Anyone who knows the topic can read and send to it.

Send a test message, with the secrets in `.env`:

```bash
docker compose run --rm message-me-cve -test-notify
```


* * *


## 🔨 Troubleshooting

### cron-job.org test run fails

GitHub's reply is in the response body:

| Status | Body | Fix |
|---|---|---|
| `401` | `Requires authentication` | Add the `Authorization` row; its value needs the `Bearer ` prefix |
| `401` | `Bad credentials` | Token value wrong (typo, cut off, extra characters). Paste it again |
| `404` | `Not Found` | URL wrong: owner, repo or workflow file name. Private repo: also the token has no access to it. GitHub answers `404`, not `403`, so it does not reveal the repo exists |
| `422` | `No ref found for: ...` | Request body names a branch that does not exist |

### No message after a run

Nothing new matched. The run page has a table per profile: words, new
matches, sent. To check delivery, send a [test message](#-phone).

### The run is red

The run page lists each problem. A feed down or a bad watch list is
messaged once when it starts and once when it clears. Undelivered alerts
are retried on the next run.


* * *


## 🧠 How it works

1. Check out `main`. Read every `profiles/*.txt`, and `state.json` from
   the `state` branch.
2. Fetch the KEV catalog (GitHub mirror, then cisa.gov).
3. If NVD was last polled 2 hours ago or more: fetch every CVE NVD changed
   since the cursor.
4. Match every profile. A CVE that matches several profiles is one
   message naming all of them.
5. Send. Mark each alert sent, per profile, only after every channel
   accepted it.
6. Move the NVD cursor to now only if everything from NVD was handled.
7. Commit `state.json` to the `state` branch. Exit 1 if anything is
   failing.

### Design decisions

| Decision | Why |
|---|---|
| NVD at most every 2 h, in code | NVD asks clients to poll for changes no more than once every two hours. Manual runs count too. |
| A missed run loses nothing | KEV is read in full every run. NVD reads from a cursor. A late or missed run only delays alerts. |
| Marked sent only after delivery | A failed send is retried next run, not lost. |
| Failures messaged once, recovery once | A feed down for a day is two messages, not one per run. The run stays red while it lasts. |
| Highest CVSS from any source | NVD often scores new CVEs weeks late. The publisher's score arrives with the CVE. 3.x first, 4.0 if no 3.x. |
| State on its own branch | `main` holds code only. One run at a time, so no merge conflicts. |
| No write token in the check step | The step that parses third-party feed data cannot read the token. Only the step that pushes state gets it. |
| Pinned | Actions by commit SHA, the base image by digest. Updated by hand. |

### Why not GitHub's cron

GitHub's docs: scheduled runs "can be delayed during periods of high
loads", and "some queued jobs may be dropped"
([community #207346](https://github.com/orgs/community/discussions/207346),
[#210932](https://github.com/orgs/community/discussions/210932)). On this
account, Nov 19-21 2026, it started 4 runs from 60+ scheduled times.
Manual runs started every time, within seconds.


* * *


## 🚧 Limitations

- **No version matching.** It does not know which versions you run. A KEV
  alert can be for a CVE your version already fixes. NVD alerts list
  `Fixed in` versions when NVD gives them.
- **Latency is the schedule's.** A new CVE waits up to the gap between two
  runs.
- **No CI, no tests.** The next run uses whatever is on `main`. A code
  mistake shows as a red run.


* * *


## 📚 Reference

### Flags and environment

| Flag | Default | Purpose |
|---|---|---|
| `-profiles` | `profiles` | Directory of `<name>.txt` watch lists |
| `-state` | `state/state.json` | State file |
| `-dry-run` | off | Print alerts instead of sending; do not write state |
| `-test-notify` | off | Send one test message to every channel and exit |

| Variable | Purpose |
|---|---|
| `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID` | Telegram bot and chat, set together |
| `NTFY_URL` | ntfy topic URL |
| `NVD_API_KEY` | Optional. NVD allows 50 requests per 30 s with it, 5 without |

Exit codes: `0` all OK, `1` something is failing (and was messaged), `2`
bad configuration (nothing ran).

### State

`state.json` on the `state` branch. Delete it to start over: every KEV
match is sent again, plus the last 7 days of NVD.

### Run with Docker

Same program, scheduled by the host instead of Actions:

```bash
mkdir -p state   # else Docker creates it as root and UID 1000 cannot write
docker compose run --rm message-me-cve -dry-run
docker compose run --rm message-me-cve
```

Reads `profiles/`, writes `state/state.json`, secrets from `.env`. The
image is one static binary on `scratch`, running as UID 1000.

### Layout

| Path | What |
|---|---|
| `cmd/message-me-cve` | Flags, wiring, run page output |
| `internal/check` | One run: matching, alerts, delivery, failure tracking |
| `internal/feed` | KEV, NVD and CVE.org clients |
| `internal/match` | Watch lists and word matching |
| `internal/notify` | Telegram and ntfy |
| `internal/state` | State file |
