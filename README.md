<h1 align="center">message-me-cve</h1>

<p align="center">
  <strong>Tell it what you run. It messages your phone when it gets a serious CVE.</strong><br>
  CVE and exploit alerts per project, from CISA KEV and NVD, to ntfy or Telegram.
</p>

<p align="center">
  <picture><img src="https://raw.githubusercontent.com/MarcusHoltz/marcusholtz.github.io/refs/heads/main/assets/img/header/header--cvenotify--nvd-notification-per-project-github.jpg" alt="message-me-cve header banner: NVD and CISA KEV notifications per project, sent from GitHub Actions"></picture>
</p>

<p align="center">
  <img src="https://github.com/MarcusHoltz/message-me-cve/actions/workflows/message-me-cve.yml/badge.svg" alt="Check status">
  <img src="https://github.com/MarcusHoltz/message-me-cve/actions/workflows/ci.yml/badge.svg" alt="CI status">
</p>


## Overview

Each project gets a watch list, one product per line: `php`, `nginx`,
`wordpress`. Every hour, GitHub Actions checks the lists against:

- **[CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)**:
  vulnerabilities exploited in the wild. Sent as `ACT NOW`, urgent.
- **[NVD](https://nvd.nist.gov/)**: new CRITICAL and HIGH CVEs, published
  in the last 90 days.
- **[CVE.org](https://www.cve.org/)**: the affected-product list for new
  CVEs that NVD has not analyzed yet.

```text
[shop, blog] ACT NOW [php]: exploited PHP CVE-2024-4577
[shop] CRITICAL 9.8 [nginx]: CVE-2026-12345
message-me-cve: cannot check NVD
message-me-cve: NVD OK again
```


## Setup

1. Push this repo to GitHub. Public repos run Actions for free.

   > [!IMPORTANT]
   > The watch lists and the run pages show what your servers run. Use a
   > private repo for real infrastructure.

2. **Settings > Secrets and variables > Actions**: add `NTFY_URL`, or
   `TELEGRAM_BOT_TOKEN` and `TELEGRAM_CHAT_ID`, or all three. Optional:
   `NVD_API_KEY` ([free](https://nvd.nist.gov/developers/request-an-api-key)),
   for faster NVD paging.
3. Create the state branch once:

   ```bash
   git switch --orphan state && git commit --allow-empty -m state
   git push -u origin state && git switch main
   ```

4. Put one watch list per project in `profiles/<name>.txt`. Commit.
5. **Actions > message-me-cve > Run workflow** to check the setup. After
   that it runs every hour.

Check delivery without waiting for a CVE:

```bash
NTFY_URL=https://ntfy.sh/<topic> go run ./cmd/message-me-cve -test-notify
```

### Phone

- **ntfy**: install the [ntfy](https://ntfy.sh/) app, subscribe to a long
  random topic. `NTFY_URL` is `https://ntfy.sh/<topic>`. Anyone who knows
  the topic can read and send to it.
- **Telegram**: create a bot with [@BotFather](https://t.me/BotFather),
  message it once, then read `message.chat.id` from
  `https://api.telegram.org/bot<token>/getUpdates`.


## Watch lists

```text
# shop.example.com
php
nginx
apache http server
```

- One product per line. `#` starts a comment. Case does not matter.
- Matched as whole words against vendor and product names only, never
  descriptions: `php` does not match a WordPress plugin that mentions PHP.
- Use product names: `apache http server`, not `apache`, which matches
  every Apache project.
- Adding a word sends every KEV entry for it on the next run, more than 5
  as one combined list. Older NVD CVEs for the word are not sent.


## How a run works

1. Read every `profiles/*.txt` and `state.json` from the `state` branch.
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

The run page shows a table per run, every message, and its delivery
result per channel.


## Design decisions

| Decision | Why |
|---|---|
| NVD at most every 2 h, enforced in code | NVD asks API clients to poll for changes no more than once every two hours. Manual runs count too, so a cron interval alone cannot enforce it. |
| Correctness does not depend on the schedule | GitHub starts scheduled runs late or drops them under load, and new repos can go days before their first scheduled run. KEV is read in full every run; NVD reads from a cursor. A late run only delays alerts. |
| Marked sent only after delivery | A failed push is retried next run instead of lost. |
| NVD cursor moves only when all of it was handled | NVD down, CVE.org down for a CVE, or an undelivered NVD alert: the next poll re-reads the same changes. |
| Failures messaged once, recovery once | A feed down for a day is two messages, not 24. The run stays red while it lasts. |
| Highest CVSS from any source | NVD often scores new CVEs weeks late. The publisher's score (F5 for NGINX, for example) arrives with the CVE. 3.x first, 4.0 if no 3.x. Unscored CVEs wait until a score appears. |
| State on its own branch | `main` history holds code changes only. One writer (the concurrency group), so no merge conflicts. |
| One run, then exit | Scheduling belongs to the scheduler (Actions, cron, systemd timer). |


## Limitations

- **No version matching.** The program does not know which versions you
  run. A KEV alert can be for a CVE your version already fixes. NVD
  alerts list `Fixed in` versions when NVD gives them.
- **Word matching is name matching.** NVD files every PyPI package under
  vendor `python`; write `python python` to mean CPython only.
- **Latency is the schedule's.** Hourly at best; later when GitHub delays
  scheduled runs.


## Reference

### Flags and environment

| Flag | Default | Purpose |
|---|---|---|
| `-profiles` | `profiles` | Directory of `<name>.txt` watch lists |
| `-state` | `state/state.json` | State file |
| `-dry-run` | off | Print alerts instead of sending; do not write state |
| `-test-notify` | off | Send one test message to every channel and exit |

| Variable | Purpose |
|---|---|
| `NTFY_URL` | ntfy topic URL |
| `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID` | Telegram bot and chat, set together |
| `NVD_API_KEY` | Optional; NVD rate limit 50 instead of 5 requests per 30 s |

Exit codes: `0` all OK, `1` something is failing (and was messaged), `2`
bad configuration (nothing ran).

### State

`state.json` on the `state` branch. Delete it to start over: every KEV
match is sent again, plus the last 7 days of NVD.

### Layout

| Path | What |
|---|---|
| `cmd/message-me-cve` | Flags, wiring, run page output |
| `internal/check` | One run: matching, alerts, delivery, failure tracking |
| `internal/feed` | KEV, NVD and CVE.org clients |
| `internal/match` | Watch lists and word matching |
| `internal/notify` | ntfy and Telegram |
| `internal/state` | State file |

### Run with Docker

Same program, scheduled by the host instead of Actions:

```bash
mkdir -p state   # else Docker creates it as root and UID 1000 cannot write
docker compose run --rm message-me-cve -dry-run
docker compose run --rm message-me-cve
```

Reads `profiles/`, writes `state/state.json`, secrets from `.env`. The
image is one static binary on `scratch`, running as UID 1000.

### Develop

```bash
docker run --rm -v "$PWD":/src -w /src golang:1.27 go test -race ./...
```

CI runs gofmt, `go vet` and `go test -race` on every push and PR.
