[한국어](README.md) · [English](README.en.md)

# StopCat — a Mac cleanup tool that stops only what you don't need

When your Mac slows down, StopCat shows "what is running and why" in plain language, and cleans up only after you confirm. While the screen is open, the **guard** (지킴이) reports what is not needed and how much memory you could get back, with evidence, and only cleans up things that are definitely "not needed" when the Mac becomes unstable. It never kills or slows down anything you are using right now.

When you start servers with AI and run many agents, you pile up ownerless processes, emulators and browsers left behind by finished tests, and ports open to the network. `stopcat` looks at your Mac **by project and AI session** instead of by process ID, and before stopping anything it explains **who started it and why**.

> **The user interface is in Korean.** The screen examples below are shown exactly as they appear; the English text explains what they mean.
>
> All screen examples in this document use synthetic data. Real values differ from Mac to Mac.
>
> The name is inspired by [RunCat](https://kyome.io/runcat/), the menu bar app whose cat runs faster as your CPU gets busier, but StopCat is an independent project unrelated to RunCat.

## Using stopcat

Just type `stopcat` in a terminal. A full-screen view opens; pick items with the arrow keys and press Enter to clean up.

```
stopcat  메모리 정상 — 압력 1 · 압축 41GB · 스왑 1.6/2GB · 부하 5.8/18코어
         확보 가능 1.5GB · 확인하면 +8.0GB · 직접 하면 +22GB
[1 보고 9]  2 포트 6   3 자동 처리 기록 0   4 설정
────────────────────────────────────────────────────────────────────────────────
      대상                    크기  나이  근거                    지킴이
필요 없음 3 · 정리하면 약 1.5GB · c 로 전부 정리
> [ ] codex app-server       1.0GB  3일   주인 끝남·CPU 0·연결 0  불안정 시 자동
  [ ] headless Chrome (Chr…  380MB  7시간 주인 끝남·CPU 0·연결 0  정리 추천
  [ ] npm exec                84MB  3일   주인 끝남·CPU 0·연결 0  정리 추천
확인 필요 3 · 쓰고 있는지 확실하지 않아 보고만 · 확인하면 약 8.0GB
  [ ] Android 에뮬레이터 (…  7.5GB  3일   주인 끝남·CPU 3%·연결 6 확인 필요
  [ ] appium (앱 테스트) :…  412MB  2일   주인 있음·안 쓰는 듯    확인 필요
  [ ] 테스트 서버 (node) :…   96MB  1일   주인 끝남·CPU 0·연결 …  확인 필요
일하는 중 1 · 건드리지 않음
  [ ] Next.js 개발 서버             2시간 주인 있음·CPU 103%      건드리지 않음
직접 하면 확보 2 · 약 22GB · 방법은 w
  ↓ 2줄 더 있어요(↓ 로 내려 보기)
─ 자세히: codex app-server ─────────────────────────────────────────────────────
무엇    codex app-server — 띄운 Claude 세션 종료됨, 자식 29개 1.0GB
근거    주인 끝남 · CPU 0% · 연결 0 · 디스크 0 · 평생 CPU 낮음 · 신뢰도 확실
대상    pid 51234 · 3일 2시간째 · 프로젝트 warmtalent-ai
지킴이  평소에는 보고만 해요. 맥이 불안정해지면 자동으로 정리해요.
─ 지킴이 안정화 자동 · 평소 보고만 · 확인 17:53:20 ─────────────────────────────
↑↓ 이동  스페이스 고르기  Enter 정리  c 추천 전부 정리  w 자세히  ? 도움말  q 끝
```

- On **first run**, one screen explains what the guard will do automatically. Enter = start with Stabilize auto, n = Report only. Your choice is saved and can be changed at any time on the Settings screen (4).
- The top two lines show the memory status and how much you could get back (reclaimable now · after you check · if you do it yourself). The guard status (level; report-only, unstable, paused, or circuit breaker; last check time) is right above the key line.
- There are four screens: **1 Report** (in the order Not needed → Needs checking → Working → Reclaim it yourself, each row with a summary of the evidence), **2 Ports**, **3 Auto-action log** (what the guard did: time, what, why, how much was reclaimed), **4 Settings**.
- The guard column in the list: `정리 추천` (recommended to clean up), `불안정 시 자동` (report only normally; the guard cleans it up when the Mac becomes unstable), `자동 예정 1/2` (only when unstable; consecutive checks in progress), `확인 필요` (needs checking), `건드리지 않음` (in use right now; left alone), `직접 하면 확보` (reclaim it yourself), `앱 재시작 필요` (app restart needed), `우선순위 낮춤` (priority lowered by you).
- If the window is smaller than 80×24, only "please make the window a little bigger" is shown.

### Keys

| Key | What it does |
|---|---|
| ↑ ↓ (or j k) | Move in the list |
| Space | Select multiple (press again to unselect) |
| Enter | Clean up the selection (or the current row if nothing is selected): preview → `y` to run / `n` to cancel. Also shows why something will not be stopped (protection rules). Warns if you pick something that is Working or Needs checking |
| c | Clean up all recommendations: preview of the Not needed section only → `y`. Needs checking and Working are never included |
| d | Lower the priority of the current row (does not stop it; preview → `y`) |
| Tab, ← →, 1–4 | Switch screens |
| w | Details: who started the current row and why |
| a | Change the guard level (asks once more when raising it to Aggressive auto) |
| p | Pause / resume the guard |
| r | Reset the circuit breaker (turn automatic stopping back on) |
| u | Restore a priority you lowered |
| ? | Help |
| q, Esc, Ctrl+C | Quit (restores priorities you lowered, then exits) |

## The guard

While the screen is open, the guard checks the Mac every 5 seconds (every 2 seconds under high memory pressure). Normally it only reports; it cleans up according to the chosen level only when the Mac is unstable (memory pressure at warning or above, or swap growing quickly). Closing the screen stops the guard too (starting automatically at login and running without a screen are planned for the next version).

| Level | What it does automatically |
|---|---|
| Report only | Never cleans up automatically. Reports on screen and via notifications; one press of c cleans up the recommended items |
| **Stabilize auto** (default) | Only when the Mac is unstable, and only among definite MCP servers, dev servers, language servers, file watchers, headless browsers, and agent backends in the Not needed section that are more than 10 minutes old, have been confirmed unused for 2 more minutes after that, and got the same verdict twice in a row — and only as much as needed to get back to normal. So the first automatic cleanup can happen about 12 minutes after a process starts |
| Aggressive auto | When unstable, also cleans up "likely" findings and a wider range of kinds. Things you started on purpose, such as emulators, may be stopped too |

- At every level, **anything in use right now (owner session alive, terminal attached, connected peers, using CPU or disk, or less than 10 minutes old) is never stopped or slowed down.** Even at 100% CPU. AI chat sessions, apps, system processes, virtual machines, and databases are never stopped automatically either.
- There is no automatic priority lowering. Priority changes only when you lower it yourself with d on the screen.
- The only things stopped automatically are those that are "definite" by the rules, belong to the chosen kinds, are confirmed unused for 2 minutes after being more than 10 minutes old, and got the same verdict for the same process twice in a row.
- If it tries to stop more than 5 processes in 10 minutes, the **circuit breaker** opens and from then on it only reports. Reset it with `r`.
- Everything done automatically is recorded on the Auto-action log screen and in the audit log. macOS notifications are sent only when the Mac becomes unstable (with a summary of what can be reclaimed) and when something was cleaned up automatically.
- Priorities you lowered are restored one at a time with `u`, or all at once when you close the screen. If stopcat is killed forcibly, as with `kill -9`, they cannot be restored and may stay lowered (restarting that program returns it to normal).

## Install

macOS only. Requires Rust 1.88 or later.

```sh
cargo install --git https://github.com/NewTurn2017/stopcat stopcat-cli
```

This installs `~/.cargo/bin/stopcat`. You can also clone the repository and build it yourself:

```sh
git clone https://github.com/NewTurn2017/stopcat && cd stopcat
cargo install --path crates/stopcat-cli
```

No administrator privileges (sudo) are needed. Nothing resident and no login items are installed.

## Commands for scripts and AI

When `stopcat` is called from somewhere other than a terminal (a pipe, a script, an AI agent), it prints the text/JSON output below instead of the full screen. In a terminal, `--plain` or a subcommand does the same.

| Command | What it does |
|---|---|
| `stopcat --plain` (= `stopcat status`, and `stopcat` outside a terminal) | One status screen: memory status, how much can be reclaimed, and lists with evidence for each section (Not needed, Needs checking, Working, Reclaim it yourself) |
| `stopcat why <pid \| :port>` | Who started the process (self → parent → … → system), its kind, its project, and whether the AI session that started it is still alive |
| `stopcat ports` | Listening ports → program → project, network exposure, known conflicts (AirPlay 5000·7000) |
| `stopcat fix` | Preview cleanup of the Not needed section only. Stops step by step once you confirm |
| `stopcat kill <pid \| :port>` | Preview, then stop a single target step by step |
| `stopcat snapshot` | The raw collected data as JSON (arguments masked, allowed environment variables only). For bug reports |

How to name a target: **a leading colon means a port**, as in `:5000`; **a bare number means a process ID**, as in `4821`.

### Common options

| Option | Meaning |
|---|---|
| `--json` | One line of JSON instead of the human-readable screen |
| `--plain` | Text status screen instead of the full screen |
| `--no-cpu` | Do not measure CPU usage (faster) |
| `--interval-ms <ms>` | Interval between the two reads when measuring CPU usage (default 250, 50–5000) |
| `--no-color` | No color. Color is also off automatically when `NO_COLOR` is set or the output is not a terminal |

### `stopcat fix` options

| Option | Meaning |
|---|---|
| `-y`, `--yes` | Clean up right away without asking |
| `--only <pid>` | Only this process (can be repeated). Works even for Needs checking or Working items, with a warning |
| `--min-confidence confirmed\|likely` | Only this confidence level or higher |

### `stopcat kill` options

| Option | Meaning |
|---|---|
| `-y`, `--yes` | Stop right away without asking |
| `--tree` | Also stop child processes (children first) |

### Screen examples

```
$ stopcat --plain
메모리 정상 — 압력 1 · 압축 41GB · 스왑 1.6/2GB · 부하 5.8/18코어
확보 가능 1.5GB · 확인하면 +8.0GB · 직접 하면 +22GB
필요 없음  codex app-server 1.0GB — 주인 끝남·CPU 0·연결 0
필요 없음  npm exec 84MB — 주인 끝남·CPU 0·연결 0
필요 없음  headless Chrome (Chrome for Testing) 380MB — 주인 끝남·CPU 0·연결 0
확인 필요  Android 에뮬레이터 (qemu) 7.5GB — 주인 끝남·CPU 3%·연결 6
확인 필요  appium (앱 테스트) 412MB — 주인 있음·안 쓰는 듯
확인 필요  테스트 서버 (node) 96MB — 주인 끝남·CPU 0·연결 모름
일하는 중  Next.js 개발 서버 — 주인 있음·CPU 103% · 건드리지 않음
직접 하면  omo 세션(bun) 22GB — 핸드오프 저장 후 재시작
직접 하면  aside 좀비 20개 — 띄운 앱 다시 시작
노출  Qdrant 0.0.0.0:6333 · appium *:4723
충돌  AirPlay :5000·:7000
→ stopcat fix 로 '필요 없음' 약 1.5GB 정리 (미리보기 → 확인)
```

```
$ stopcat fix
정리 미리보기 — 3건, 최대 약 1.5GB 회수 예상
기준: '필요 없음'만 · 확실 + 가능성 높음 (확인하고 실행할 때 기본값)
  1. codex app-server (자식 29개 포함)                 1.0GB  확실
     이유: 띄운 Claude 세션이 이미 끝났어요
     방법: 자식부터 정상 종료 → 3초 기다림 → 안 꺼지면 강제 종료
  2. headless Chrome (Chrome for Testing)              380MB  가능성 높음
     이유: 테스트용 브라우저가 7시간째 남아 있어요
     방법: 정상 종료 → 3초 기다림 → 안 꺼지면 강제 종료
  3. npm exec                                           84MB  가능성 높음
     이유: 띄운 터미널이 닫혔는데 남아 있어요
     방법: 정상 종료 → 3초 기다림 → 안 꺼지면 강제 종료
건드리지 않는 것
  omo 세션 22GB — AI 세션은 끄지 않아요. 핸드오프 저장 후 직접 재시작
  Android 에뮬레이터 (qemu) — 확인 필요라 뺐어요. 직접: stopcat fix --only 40001
  appium (앱 테스트) — 확인 필요라 뺐어요. 직접: stopcat fix --only 40112
  aside 좀비 20개 — 끌 수 없어요. 띄운 앱을 다시 시작하세요
  테스트 서버 (node) — 확인 필요라 뺐어요. 직접: stopcat fix --only 61822
  … 외 1건
정리할까요? [y/N]
```

## Reading the screen

- **The first line** is always the memory status. If there is no crisis, it says "normal" (정상) first. It never warns based on usage percentage alone.
- **Not needed** (필요 없음): whatever started it has ended and it is not in use now (recommended for cleanup). **Needs checking** (확인 필요): whatever started it has ended but there are signs of use, or the starter is alive but it seems unused (report only). **Working** (일하는 중): in use right now (left alone). **Reclaim it yourself** (직접 하면 확보): things stopcat does not stop but you can reclaim yourself, such as restarting AI sessions, virtual machines and local LLMs, or zombies. **Exposed** (노출): ports reachable from other devices on the same Wi-Fi. **Conflict** (충돌): ports that commonly collide.
- **Confidence**: definite (확실) · likely (가능성 높음) · possible (가능성 있음). Shown in the details pane and in previews. "Possible" items still appear in their section on screen, but are excluded from cleanup by default.
- When several items are grouped on one line, identical names are combined like `×2`, and anything that did not fit is counted as `외 N건` ("N more").

## Safety principles

1. **Preview is the default.** `stopcat fix` and `stopcat kill` first show what will be stopped, why, and how.
2. **Nothing is stopped without confirmation.** It runs only when you answer `y` in a terminal or pass `--yes`. Called outside a terminal (scripts, pipes) without `--yes`, it only previews and exits.
3. **Cleanup criteria**: `stopcat fix` and c look only at the Not needed section. Within it, "definite + likely" is cleaned up when you confirm after reviewing, and only "definite" when you run with `--yes` without seeing the list. Targets you pick yourself with `--only <pid>` are included regardless of section or confidence (protection rules still apply). `--min-confidence` takes precedence when given.
4. **Stops step by step**: (resume if stopped) → graceful termination signal → wait 3 seconds → force kill if still running. When stopping children too, children go first.
5. **AI agent sessions (claude, codex, omo) are never stopped.** Stopping them would lose the conversation context. If one is heavy, it recommends saving a handoff and restarting it yourself.
6. **Re-checks right before running.** If the process ID was reused by a different program after the preview (different start time), it is left alone.
7. **The guard goes through the same rules.** Automatic cleanup passes through the same protection rules and step-by-step stopping below, and both confirmed cleanups from the screen and automatic cleanups send signals from one place only (the guard).

### Protection rules

If any of these apply, `stopcat` does not stop the target and shows the reason.

| Rule | Never stopped |
|---|---|
| R01 | launchd and the kernel (PID 1 or below) |
| R02 | stopcat itself |
| R03 | The terminal, shell, or agent session that started stopcat (ancestors) |
| R04 | Processes of other users or system accounts |
| R05 | macOS system components (`/System/` and so on) |
| R06 | Apps' XPC services and extensions |
| R07 | Apps and helpers inside an app bundle (cleaned up when the app quits) |
| R08 | AI agent sessions, GUI apps, virtual machines, databases |
| R09 | Targets with a live agent session or app below them |
| R10 | Zombies (already ended; they disappear only when the parent app restarts) |
| R11 | Findings that are not automatic-action targets (handoff recommended, restart parent, review). Review items are cleaned up if you pick them yourself with `--only` |
| R12 | Lowering priority (`stopcat fix` has no option to enable it; priority is lowered only when you pick it yourself with d on the full screen) |
| R13 | Findings below the chosen confidence threshold |
| R14 | Targets whose start time changed after the preview (PID reuse) |
| R15 | Children found during execution whose start time cannot confirm they are real children |
| R16 | Anything beyond the per-run limit (50 by default). Run again to continue |

### Where records are kept

When a cleanup runs, it leaves the following (a preview alone writes nothing).

- Settings: `~/Library/Application Support/stopcat/config.json` — the guard level chosen on first run and the check interval
- Audit log: `~/Library/Application Support/stopcat/audit.jsonl` — when, to what, which signal was sent, and what happened
- Revive info: `~/Library/Application Support/stopcat/revive/` — the executable, arguments, and folder before stopping (permissions 0600). This version only records it; there is no revive command yet

You can change this folder with the `STOPCAT_STATE_DIR` environment variable.

## Environment variables

| Variable | Meaning |
|---|---|
| `STOPCAT_GUARD_LEVEL=notify\|safe\|aggressive` | Sets the guard level (notify = Report only, safe = Stabilize auto, aggressive = Aggressive auto). Takes precedence over the settings file and cannot be changed on screen. An unrecognized value runs as Report only |
| `STOPCAT_STATE_DIR` | Folder for settings, audit log, and revive info |
| `STOPCAT_NOTIFY=off` | Do not send macOS notifications |
| `STOPCAT_E2E_ALLOW_PIDS` | Test lock: send signals only to the listed process IDs (comma-separated; empty blocks everything) |
| `STOPCAT_E2E_FORCE_HEALTH=watch\|critical` | For testing. Read only together with `STOPCAT_E2E_ALLOW_PIDS`; makes the guard treat the Mac as unstable (the health shown on screen stays real). Do not use normally |
| `NO_COLOR` | No color (the full screen becomes monochrome) |

## Privacy

- Only environment variables on a fixed allowlist (for example `CLAUDE_PID`, `TERM_PROGRAM`, `VIRTUAL_ENV`) are kept. All other values are discarded as soon as they are read.
- Command-line arguments shown on screen and in JSON have secret-looking values (values of options like `--api-key`, tokens, values after `Bearer`, user info in URLs, and so on) replaced with `<가림>` ("masked"). Key names are kept so you can tell what was masked.
- Nothing is ever sent off your Mac.

## What it does not do

- "RAM cleaning" such as `purge`
- Alerts based on usage percentage alone
- Force kills (`kill -9`) without confirmation
- Automatically stopping processes in use, or automatically lowering priority
- Asking for administrator privileges (sudo)
- Automatically deleting files or folders, or disk cleanup
- Resident daemons, login items or LaunchAgents (running at login is planned for the next version), menu bar apps
- Actually reviving stopped programs (it only records the info)

## Exit codes and JSON

- Exit codes: `0` for success (including when it only previewed, or was refused by a protection rule), `1` for usage errors, missing targets, and internal errors. The full screen exits with `0` when closed with a quit key, `128 + signal number` when ended by a signal (SIGTERM and so on), and `130` if you press Ctrl+C once more while it is shutting down.
- Top-level `--json` keys (`schema_version` 2. Changes from 1: report.findings[].section (section), report.classified[].usage (usage verdict), and three per-section reclaimable totals in report.totals were added, and the finding kind runaway became high_cpu):

| Command | Keys |
|---|---|
| `stopcat --json` | `schema_version`, `report`, `host`, `memory`, `limits`, `timings_ms` |
| `stopcat why` | `schema_version`, `taken_at_unix_ms`, `query`, `explanations` |
| `stopcat ports` | `schema_version`, `taken_at_unix_ms`, `listeners`, `findings` |
| `stopcat fix` | `schema_version`, `taken_at_unix_ms`, `mode`, `plan`, `outcomes`, `audit_log`, `state_dir` |
| `stopcat kill` | the `stopcat fix` keys above + `target` |
| `stopcat snapshot` | The fields of the collected data (`Snapshot`) as is |
| Error | `schema_version`, `error` (`code`, `message_ko`) |

`mode` is one of `nothing_to_do` (nothing to clean up), `non_interactive_preview` (preview only, without confirmation), `declined` (cancelled), or `executed` (ran).

## Reporting problems

Please attach the file from `stopcat snapshot --json > snapshot.json`. Secret values in arguments are masked, but folder and program names are included as is, so look it over before sending.

## License

[MIT](LICENSE)
