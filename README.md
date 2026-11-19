<h1 align="center">message-me-cve</h1>

<p align="center">
  <strong>Tell it what you run. It messages your phone when it gets a serious CVE.</strong><br>
  CVE and exploit alerts per project, from CISA KEV and NVD, to ntfy or Telegram.
</p>


---


<p align="center">
  <picture><img src="https://raw.githubusercontent.com/MarcusHoltz/marcusholtz.github.io/refs/heads/main/assets/img/header/header--cvenotify--nvd-notification-per-project-github.jpg" alt="message-me-cve header banner: NVD and CISA KEV notifications per project, sent from GitHub Actions"></picture>
</p>

<p align="center">
  <img src="https://github.com/MarcusHoltz/message-me-cve/actions/workflows/message-me-cve.yml/badge.svg" alt="Workflow status">
  <img src="https://img.shields.io/badge/feeds-CISA%20KEV%20%7C%20NVD%20%7C%20CVE.org-2D56A8" alt="Feeds: CISA KEV, NVD, CVE.org">
  <img src="https://img.shields.io/badge/alerts-ntfy%20%7C%20Telegram-278EF5" alt="Alerts: ntfy, Telegram">
  <img src="https://img.shields.io/badge/runs%20on-GitHub%20Actions%20%7C%20Docker-blue" alt="Runs on GitHub Actions or Docker">
</p>

<p align="center">
  <a href="#-overview">Overview</a> ·
  <a href="#-alerts">Alerts</a> ·
  <a href="#-phone-setup">Phone setup</a> ·
  <a href="#-run-on-github-actions">GitHub Actions</a> ·
  <a href="#-run-with-docker">Docker</a> ·
  <a href="#-watch-lists">Watch lists</a> ·
  <a href="#-reference">Reference</a>
</p>


---


## 👍 Overview

Write down what a project runs, one word per line: `php`, `nginx`,
`wordpress`. message-me-cve checks those words against public
vulnerability feeds and pushes a message to your phone when one of them
is being exploited or gets a new critical or high CVE.

Feeds:

- **[CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)**:
  vulnerabilities known to be exploited in the wild.
- **[NVD](https://nvd.nist.gov/)**: new CVEs, their scores, and the products
  they affect.
- **[CVE.org](https://www.cve.org/)**: the affected-product list for CVEs
  NVD has not analyzed yet.


* * *


## 📱 Phone setup

Pick ntfy, Telegram, or both. Every alert goes to every channel you set up.


### ntfy

1. Install the [ntfy](https://ntfy.sh/) app and subscribe to a long,
   random topic name.
2. Your push URL is `https://ntfy.sh/<topic>`.

> [!WARNING]
> Anyone who knows the topic name can read your alerts and send fake ones
> to your phone. Treat it like a password.


### Telegram

1. Create a bot with [@BotFather](https://t.me/BotFather). Keep its token.
2. Send your bot any message. Bots cannot message you first.
3. Open `https://api.telegram.org/bot<token>/getUpdates` and read
   `message.chat.id`. That is your chat ID.

Telegram messages are sent at most one per second, Telegram's limit for
a single chat. Each message waits 1 s after Telegram's reply to the
previous one, so Telegram never receives two within a second.


* * *


## 🚀 Run on GitHub Actions

No server needed. One workflow checks every profile.

1. Create a new **private** GitHub repo and push this code to it. Do not
   fork: a fork of a public repo cannot be private.

   > [!IMPORTANT]
   > The watch lists in `profiles/` and the alerts on each run page
   > describe what your servers run. A public repo shows them to everyone.
   > The profiles in this repo are open-source projects whose dependencies
   > are already public in their own repos. Replace them with your own.

2. **Settings > Secrets and variables > Actions > New repository secret.**
   Add `NTFY_URL`, or `TELEGRAM_BOT_TOKEN` and `TELEGRAM_CHAT_ID`, or all
   three. Optional: `NVD_API_KEY`, free from
   [NVD](https://nvd.nist.gov/developers/request-an-api-key).
3. Edit the watch lists in `profiles/`, one file per project. Commit.
4. **Actions > message-me-cve > Run workflow** for the first run. After
   that it chains itself every 10 minutes.

Each run:

- Fetches KEV and NVD once and checks every `profiles/<name>.txt` against
  that one fetch.
- Commits its state (CVEs sent, open failures, NVD position) to
  `state/<name>.json` when it changed. Any run where NVD was read moves
  the NVD position and poll time, so that is every run where NVD was due.
  A run that changed nothing (NVD not due or still down, nothing sent)
  makes no commit; its table is on the run page. A new profile gets its
  state file on its first run.
- Names the profiles that sent alerts or failed in the commit subject,
  e.g. `message-me-cve: sent example.com (2); failed example-project`, or
  `message-me-cve: nothing sent`. The commit body has one line per
  profile with its counts.
- Fails red when anything is broken. GitHub notifies the user who last
  changed the workflow file.
- Records every message on the run page: an annotation, plus a job
  summary entry with UTC time, full text, and the delivery result per
  channel. Kept for the repo's log retention (90 days by default).
- Ends the job summary with a **profiles checked** table: one row per
  profile, on every run, also when nothing was sent.

  | Profile | Words | New KEV | New NVD | Sent | Not sent | Status |
  |---|---|---|---|---|---|---|
  | example.com | 11 | 1 | 1 | 2 | 0 | ok |
  | example-project | 1 | 0 | 0 | 0 | 0 | ok |

  New KEV and New NVD are matches not sent before. Not sent means
  delivery failed; KEV ones are tried again next run, NVD ones at the
  next NVD poll.

Cost: a run every 10-11 minutes, all day. About 1 minute each; NVD runs
(every 2 hours) take 1 to 1.5. Free on public repos. On a private repo
that is about 4000-5000 billed minutes a month, over GitHub Free's 2000.


### Schedule

Runs chain themselves. Each run ends with a `next` job that waits 9
minutes in the `tick` environment (wait timer, no runner used while
waiting), then dispatches the next run with `workflow_dispatch`.

- **Why not cron:** GitHub starts scheduled runs on this account 6 to 10
  hours late, or not at all. The `*/10` cron stays only as a backup that
  restarts the chain if a dispatch ever fails.
- **One chain:** the workflow concurrency group allows one run plus one
  pending; a newer pending run cancels the older one, so extra chains
  merge.
- **NVD:** polled at most every 2 hours, as NVD asks. The program
  enforces it with `nvd_polled` in each state file; other runs check KEV
  only (status `ok, NVD not due`).
- **Setup on a new repo:** Settings > Environments > New environment
  `tick`, wait timer 9 minutes. Wait timers on private repos need a paid
  plan. Then run the workflow once by hand to start the chain.
- **Change the gap:** edit the `tick` wait timer.
- **Stop it:** Actions > message-me-cve > Disable workflow.

The `check` job times out after 80 minutes. That leaves room for one 60
minute round of NVD retries (see [How a run works](#how-a-run-works)).


* * *


## 🐳 Run with Docker

Runs on any box with Docker. Docker mode uses one watch list, `watch.txt`,
and one state file, `state/state.json`. It does not read `profiles/`.

1. Create `.env` next to `compose.yaml`:

   ```bash
   NTFY_URL=https://ntfy.sh/<topic>
   # and/or
   TELEGRAM_BOT_TOKEN=...
   TELEGRAM_CHAT_ID=...
   # optional
   NVD_API_KEY=...
   ```

2. Edit `watch.txt`.
3. Start it:

   ```bash
   docker compose up -d --build
   ```

It checks every 2 hours, day and night. Logs:

```bash
docker compose logs -f
```

Every check logs one line, also when nothing was sent:
`run done: new KEV 0, new NVD 0, sent 0, ok`.

The image is about 10 MB: one static binary on `scratch`, no shell,
running as UID 1000. `state/` must be writable by UID 1000, or every run
fails with `cannot save state`.


* * *


## 📝 Watch lists

One word or phrase per line. `#` starts a comment. Case does not matter.

```text
# example.com
php
laravel
nginx
postgresql
fluent bit
```

Matching:

- **Whole words, in vendor and product names only.** Not in descriptions.
  `php` does not match a WordPress plugin whose description mentions PHP.
- **Use product names.** `apache http server`, not `apache`. `apache`
  matches every Apache project.
- **KEV:** matched on the entry's vendor and product.
- **NVD:** matched on the CVE's affected-product list (CPE vendor and
  product). New CVEs that NVD has not analyzed yet have no such list. For
  those, when the description mentions a watch word, the product list
  from the CVE.org record is checked instead, and the message says so.

Where the lists live:

| Mode | Watch list | State |
|---|---|---|
| GitHub Actions | `profiles/<name>.txt` | `state/<name>.json` |
| Docker | `watch.txt` | `state/state.json` |

New profile: add `profiles/<name>.txt`. The file name becomes the profile
name in alert titles.

> [!NOTE]
> Adding a word to an existing list sends every KEV entry for it on the
> next run (more than 5: one combined list). NVD is only checked for CVEs
> changed since the previous run, so older CVEs for the word are not sent.


* * *


## ⚙️ Settings

Environment variables. The workflow sets `PROFILES_DIR` and
`compose.yaml` sets `INTERVAL`. You set the channel variables (as secrets
or in `.env`).

| Variable | Default | Purpose |
|---|---|---|
| `NTFY_URL` | unset: no ntfy | ntfy push URL |
| `TELEGRAM_BOT_TOKEN` | unset: no Telegram | Telegram bot token |
| `TELEGRAM_CHAT_ID` | unset | Required with the token |
| `NVD_API_KEY` | unset | Faster NVD paging |
| `WATCH_FILE` | `watch.txt` | Watch list (single mode) |
| `STATE_FILE` | `state/state.json` | State file (single mode). Delete it to start over: resends all KEV matches and the last 7 days of NVD |
| `PROFILE` | unset | Prefixes alert titles with `[name]` (single mode) |
| `PROFILES_DIR` | unset | Check every `<dir>/<name>.txt` as profile `name`. Set to `profiles` by the workflow |
| `INTERVAL` | unset: run once and exit | e.g. `2h`: run forever at that interval. Set by `compose.yaml` |


* * *

## 🔔 Alerts

| Alert | When | Priority |
|---|---|---|
| `ACT NOW [word]: exploited ...` | A watched product is on CISA KEV | urgent |
| `CRITICAL 9.8 [word]: CVE-...` | New critical CVE for a watched product | normal |
| `HIGH 7.5 [word]: CVE-...` | New high CVE for a watched product | normal |
| `message-me-cve: cannot check ...` | A feed is down: CISA KEV, NVD, or CVE.org | urgent |
| `message-me-cve: FAILED, you are not covered` | Missing or empty watch list, no profiles found, state file errors | urgent |
| `message-me-cve: bad INTERVAL` | `INTERVAL` is not a duration of at least 1m (Docker) | urgent |
| `message-me-cve: ... OK again` | The failure above has cleared | normal |

With profiles, every title starts with the profile name:
`[example.com] ACT NOW [nginx]: ...`.

What gets sent:

- **Exploited (KEV):** any KEV entry whose vendor or product names a watch
  word, no matter how old the CVE is. The message has the required action,
  ransomware use, and the date CISA added it.
- **New CVEs (NVD):** critical or high, published in the last 90 days.
  NVD re-edits old CVEs all the time (a 2000 OpenSSL bug, for example);
  those are not sent again. The message has the score, the description,
  and the fixed versions when NVD lists them.
- **Each CVE once per kind.** A CVE already sent as ACT NOW is not sent
  again as a plain CVE. A CVE sent as CRITICAL/HIGH is sent again as
  ACT NOW if it later lands on KEV.
- **Many at once:** more than 5 new KEV or NVD matches in one run (a new
  word with years of KEV history, for example) arrive as one combined
  list, split into parts when long.
- **Failures once.** A broken feed or watch list is reported once when it
  breaks and once when it is fixed, not on every run. Exceptions, sent
  every time: an unreadable state file, no profiles found, a bad
  `INTERVAL`.
- **Nothing lost on a failed push.** An alert that could not be delivered
  is not marked sent, and is tried again next run (NVD alerts: at the next
  NVD poll).


* * *


## 📚 Reference


### How a run works

1. Fetch CISA KEV, from CISA's GitHub mirror, falling back to cisa.gov.
2. Fetch every CVE NVD changed since the last successful run. The first
   run looks back 7 days. Skipped when any profile polled NVD less than
   2 hours ago (`nvd_polled`); the next due run covers the gap.
3. For each profile, send:
   - KEV entries matching a watch word, as ACT NOW.
   - NVD CVEs that are critical or high, published in the last 90 days,
     and matching a watch word.
4. Mark each delivered alert as sent in the profile's state file.
5. Report broken feeds or config once, and their recovery once. Exit
   non-zero while anything is broken.

NVD errors (503 and the like) are retried for up to 60 minutes before an
alert goes out: 30 s backoff, doubling to a 5 minute cap.

CVE.org:

- Each record is fetched at most once per run, shared by every profile
  that needs it. A failed lookup is not retried in the same run.
- A failed lookup holds back only the CVE that needed it. Every other
  CVE is still sent. The NVD position is not moved forward, so the
  held-back CVE is checked again next run.


### Severity

- The highest CVSS 3.x base score from any source NVD carries: NVD itself,
  the CVE's publisher (F5 for NGINX, for example), or CISA.
- No 3.x score from anyone: the highest CVSS 4.0 score.
- No score at all: skipped for now. The CVE is checked again the next time
  NVD changes it, for example when a score is added.
- Why not wait for NVD's own score: NVD often has not scored a new CVE
  yet.


### Files

| Path | What |
|---|---|
| `main.go` | The whole program |
| `main_test.go` | Tests |
| `profiles/<name>.txt` | Watch list per project (GitHub Actions) |
| `state/<name>.json` | Sent CVEs and open failures per profile, written by the workflow |
| `watch.txt` | Watch list (Docker) |
| `.github/workflows/message-me-cve.yml` | Scheduled workflow |
| `Dockerfile`, `compose.yaml` | Docker mode |


### Develop

Run the tests:

```bash
docker run --rm -v "$PWD":/src -w /src golang:1.27-alpine go test ./...
```

The Docker build also runs the tests and fails if they fail.
