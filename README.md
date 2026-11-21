# message-me-cve

Tell it what software your projects run. When a serious CVE shows up for one of them, it messages your phone.


![message-me-cve header banner: NVD and CISA KEV notifications per project, sent from GitHub Actions](https://raw.githubusercontent.com/MarcusHoltz/marcusholtz.github.io/refs/heads/main/assets/img/header/header--cvenotify--nvd-notification-per-project-github.jpg "CISA KEV and NVD alerts per project, to Telegram or ntfy")


![Check status](https://github.com/OWNER/REPO/actions/workflows/message-me-cve.yml/badge.svg)


* * *

## What does message-me-cve do?

Say you run a handful of projects, and each one is built on a different pile of software. You want to know when one of those pieces gets a bad CVE, without reading vulnerability feeds every morning.

So each project gets a watch list. A watch list is a text file with one product per line: `php`, `nginx`, `openssl`.

When the run is started, a GitHub Actions job checks every watch list against the public vulnerability feeds. Anything new that matches gets sent to Telegram, ntfy, or both.

> No message means nothing new matched.


* * *

### Where the alerts come from

- **[CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)** - CISA's catalog of vulnerabilities known to be exploited in the wild. A match here is sent as `ACT NOW`, at urgent priority on ntfy.

- **[NVD](https://nvd.nist.gov/)** - new CVEs rated CRITICAL or HIGH, published in the last 90 days.

- **[CVE.org](https://www.cve.org/)** - NVD can take a while to analyze a new CVE. Until it does, the product list the CVE's publisher filed on CVE.org is checked instead.


* * *

### What lands on your phone

A KEV match, taken from a dry run with two watch lists, `shop.txt` and `blog.txt`, that both list `openssl`:

```text
[blog, shop] ACT NOW [openssl]: exploited OpenSSL CVE-2014-0160
```

The first brackets are the projects it matched. The second brackets are the watch words that matched.

An NVD match reads `[project] SEVERITY SCORE [word]: CVE-ID`.

More than 5 new KEV matches, or more than 5 new NVD matches, in one run come as a combined list instead of one message each:

```text
New CRITICAL/HIGH CVEs: 10 matches (part 1)
```

If a feed can't be read, you are told once when it breaks, and once when it works again:

```text
message-me-cve: cannot check NVD
message-me-cve: NVD OK again
```


* * *

## Before you set it up

> [!IMPORTANT]
> Your watch lists, and every run page, show what your servers run. Use a private repo for real infrastructure.

- **Use the template, don't fork.** A fork of a public repo is always public, and you can't change that. A repo made from the template starts with a single commit, and you pick its visibility (step 1 below).

- **Actions minutes.** A private repo uses up your plan's included Actions usage. Public repos on GitHub's standard runners are free. A normal run takes under a minute.


* * *

## Setup

### 1. Make your own repo from the template

**Use this template > Create a new repository**

- **Owner** and **Repository name:** yours.

- **Visibility:** **Private** for real infrastructure.

- **Include all branches:** leave it unchecked. You only need `main`, and you make your own `state` branch in step 3.


* * *

### 2. Add your secrets

In your repo, go to **Settings > Secrets and variables > Actions**. You need at least one channel.

| Secret | What it's for |
|---|---|
| `TELEGRAM_BOT_TOKEN` and `TELEGRAM_CHAT_ID` | Telegram. Set both, or neither. See [Phone setup](#phone-setup) |
| `NTFY_URL` | ntfy topic URL, like `https://ntfy.sh/<topic>` |
| `NVD_API_KEY` | Optional. [Request a key from NVD](https://nvd.nist.gov/developers/request-an-api-key) for faster NVD paging |


* * *

### 3. Create the state branch

This only needs to happen once. The `state` branch is where the run remembers what it already sent.

```bash
git clone https://github.com/<owner>/<repo>.git && cd <repo>
git switch --orphan state && git commit --allow-empty -m state
git push -u origin state && git switch main
```


* * *

### 4. Write your watch lists

One file per project: `profiles/<project>.txt`. The lists in `profiles/` are examples, replace them with yours. See [Writing watch lists](#writing-watch-lists).

Push to `main`. The next run uses them.


* * *

### 5. Run it once

**Actions > message-me-cve > Run workflow**

Green means your secrets, the feeds, and the state branch all work.

> Delivery is only tested when something is actually sent. Send a [test message](#send-a-test-message) to be sure.


* * *

### 6. Put it on a schedule

See [Scheduling](#scheduling) right below.


* * *

## Scheduling

The workflow has no `schedule:` trigger. An outside cron service starts it through GitHub's API instead.

> Why not GitHub's own cron?

GitHub's docs say it themselves: the `schedule` event "can be delayed during periods of high loads of GitHub Actions workflow runs", and "if the load is sufficiently high enough, some queued jobs may be dropped."

People are running into it: [community #207346](https://github.com/orgs/community/discussions/207346), [community #210932](https://github.com/orgs/community/discussions/210932).


* * *

### Make a token

**GitHub > Settings > Developer settings > Personal access tokens > Fine-grained tokens > Generate new token**

- **Repository access:** only this repo. If it's private and not selected here, every call comes back `404`.

- **Permissions:** **Actions: Read and write**. Nothing else.

- **Expiration:** write down the date. When the token expires, the runs stop.


* * *

### Set up cron-job.org

[cron-job.org](https://cron-job.org/) is free. Make one job.

#### Common

- **URL:** put in your owner and repo name. It's the same for public and private repos:

  `https://api.github.com/repos/<owner>/<repo>/actions/workflows/message-me-cve.yml/dispatches`

- **Execution schedule:** pick **Custom** and use a crontab line, like `0 6,14 * * *` for 06:00 and 14:00. ("Every day at" only runs once a day.)

#### Advanced

- **Headers:** three of them. The key and the value go in separate fields.

  | Key | Value |
  |---|---|
  | `Authorization` | `Bearer <token>` (the word Bearer, one space, then your token) |
  | `Accept` | `application/vnd.github+json` |
  | `X-GitHub-Api-Version` | `2026-03-10` |

- **Time zone:** yours. The schedule runs in it.

- **Request method:** `POST`

- **Request body:** `{"ref":"main"}`

> cron-job.org will pop up "Sending JSON data?" and suggest a Content-Type header. You can skip it, GitHub reads the body without one.

#### Notifications

Turn on the notification for when the job fails.


* * *

### Test it, then save it

Hit **Test run**, then **Save**. Changes that aren't saved aren't used.

A working call comes back `200` with the new run:

```text
{"workflow_run_id":<run id>,"run_url":"...","html_url":"https://github.com/<owner>/<repo>/actions/runs/<run id>"}
```

> Leave out the `X-GitHub-Api-Version` header and GitHub falls back to API version `2022-11-28`. That version answers `204` with an empty body. The run still starts, you just don't get the run details back.

The run shows up under **Actions > message-me-cve** right away. Anything other than `200`, see [Troubleshooting](#troubleshooting).

- **To turn it off:** pause the cron job, or go to **Actions > message-me-cve > ... > Disable workflow**.

- **Don't want cron-job.org?** Anything that can send this POST works, like `curl` in a server's crontab.


* * *

## Writing watch lists

```text
# shop.example.com
php
nginx
apache http server
```

- One product per line. `#` starts a comment. Case doesn't matter.

- Words are matched whole, against vendor and product names. Never against descriptions. So `php` won't match some WordPress plugin just because its description mentions PHP.

- Use the product's name. `apache http server`, not `apache`. Plain `apache` matches every Apache project there is.

- `python python` means CPython only. NVD files a lot of PyPI packages under the vendor `python` (`pillow`, `requests`, `urllib3`, `setuptools`...), so plain `python` matches all of those too.

- Adding a new word? Every KEV entry for it gets sent on the next run. Older NVD CVEs for it don't.


* * *

## Phone setup

### Telegram

1. Make a bot with [@BotFather](https://t.me/BotFather). It gives you the bot token.

2. Send your new bot a message, any message.

3. Open `https://api.telegram.org/bot<token>/getUpdates` and find `message.chat.id`. That's your chat ID.


### ntfy

Install the [ntfy](https://ntfy.sh/) app and subscribe to a long, random topic name.

> ntfy has no sign-up, so the topic is essentially a password. Anyone who knows it can read it and post to it.


### Send a test message

Put your secrets in a `.env` file in the repo folder, then:

```bash
docker compose run --rm message-me-cve -test-notify
```

Every channel you set up gets one test message.


* * *

## Troubleshooting

### The cron-job.org test run fails

GitHub tells you why in the response body:

| Status | Body | Fix |
|---|---|---|
| `401` | `Requires authentication` | The `Authorization` header is missing, or its value is missing `Bearer ` in front |
| `401` | `Bad credentials` | The token is wrong. A typo, cut off, extra characters. Paste it again |
| `404` | `Not Found` | The URL is wrong: owner, repo or workflow file name. On a private repo it can also mean the token wasn't given access to it. GitHub says `404` instead of `403` so it doesn't confirm a private repo exists |
| `422` | `No ref found for: ...` | The request body names a branch that doesn't exist |


### A run finished, but no message came

Nothing new matched. The run page has a table with a row for each project: words, new matches, sent. To check that delivery works at all, send a [test message](#send-a-test-message).


### The run is red

The run page lists every problem. A feed that's down, or a watch list that can't be read, gets one message when it starts and one when it clears. The run stays red the whole time.

Alerts that didn't get delivered are tried again on the next run.


* * *

## How a run works

1. Check out `main`. Read every `profiles/*.txt`, and `state.json` from the `state` branch.

2. Get the KEV catalog. GitHub's mirror first, then cisa.gov.

3. If NVD was last asked 2 hours ago or more, get every CVE NVD changed since the last time.

4. Match every watch list. A CVE that matches several projects is one message that names all of them.

5. Send. An alert is marked sent, for each project, only after every channel took it.

6. Move the NVD bookmark up to now, but only if everything from NVD was handled.

7. Save `state.json` and exit with `1` if anything is failing. The next workflow step commits `state.json` to the `state` branch, even when the check failed.


* * *

### Why it works this way

- **NVD at most every 2 hours.** NVD's own guidance: "No more than once every two hours, automated requests should include a range where lastModStartDate equals the time of the last CVE or CPE received and lastModEndDate equals the current time." The program enforces it, so manual runs count too.

- **A missed run loses nothing.** KEV is read in full every run. NVD is read from a bookmark, so a late or missed run only delays alerts.

- **Marked sent only after delivery.** A send that fails is tried again next run, not lost.

- **Failures are messaged once, recovery once.** A feed that's down for a day is two messages, not one per run.

- **Highest CVSS score from any source.** NVD often scores a new CVE weeks after it's published, while the publisher's score shows up with the CVE. CVSS 3.x is used first, 4.0 only if there's no 3.x score.

- **State on its own branch.** `main` holds only code. Only one run happens at a time, so there are no merge conflicts.

- **No write token in the check step.** The step that reads third-party feed data never gets the token. Only the step that pushes `state.json` does.

- **Pinned.** The Actions are pinned by commit SHA, the Docker base image by digest. They're updated by hand.


* * *

## What it doesn't do

- **No version matching.** It doesn't know what version you run. A KEV alert can be for a CVE your version already fixed. NVD alerts list `Fixed in` versions when NVD has them.

- **It's only as fast as your schedule.** A new CVE waits until the next run.

- **No CI, no tests.** The next run uses whatever is on `main`. A mistake in the code shows up as a red run.


* * *

## Running it with Docker instead

Same program, but your own machine's cron starts it instead of Actions:

```bash
mkdir -p state
docker compose run --rm message-me-cve -dry-run
docker compose run --rm message-me-cve
```

> Make `state/` yourself first. If Docker has to make it, it's owned by root, and the container (UID 1000) can't write `state.json`.

It reads `profiles/`, writes `state/state.json`, and gets the secrets from `.env`. The image is one static binary on `scratch`, running as UID 1000.


* * *

## Reference

### Flags

| Flag | Default | What it does |
|---|---|---|
| `-profiles` | `profiles` | Folder of `<project>.txt` watch lists |
| `-state` | `state/state.json` | State file |
| `-dry-run` | off | Print the alerts instead of sending them. State isn't written |
| `-test-notify` | off | Send one test message to every channel, then exit |


### Environment

| Variable | What it's for |
|---|---|
| `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID` | Telegram bot and chat. Set them together |
| `NTFY_URL` | ntfy topic URL |
| `NVD_API_KEY` | Optional. NVD allows 50 requests in a rolling 30 seconds with a key, 5 without |


### Exit codes

- `0` - everything worked.

- `1` - something is failing. You were messaged about it.

- `2` - bad channel settings or flags. Nothing was checked.


### State

`state.json` lives on the `state` branch. It holds the NVD bookmark, what was sent to each project, and what's currently broken.

Delete it to start over. Every KEV match gets sent again, plus the last 7 days of NVD.


### Files

One binary, one `package main` at the root of the repo.

| File | What's in it |
|---|---|
| `main.go` | Flags, setup |
| `check.go`, `message.go` | One run: matching, alerts, delivery, failure tracking |
| `feed.go`, `feedtypes.go` | KEV, NVD and CVE.org clients |
| `match.go` | Watch lists and word matching |
| `notify.go` | Telegram and ntfy |
| `state.go` | State file |
| `github.go` | The run page: annotations and job summary |


* * *

## Thanks!

Hope this saves someone else from reading the NVD feed every morning.
