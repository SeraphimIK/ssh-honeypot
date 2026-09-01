# Custom SSH-Style Honeypot

A lightweight honeypot built from scratch in Python: it mimics a Linux SSH/telnet login prompt, accepts any credentials, and logs every username, password, and command an attacker tries — without ever actually executing anything.

## Why I built it

I wanted to understand honeypots at the level of actually building the logging and interaction logic myself, not just deploying someone else's tool. This also gave me a real, self-contained artifact instead of something that depends on standing up a VM/hypervisor, which wasn't practical for this exercise.

## What it does

- `honeypot.py` — the honeypot server. Presents a fake Ubuntu login banner, logs every credential attempt, then serves a fake shell that returns canned output for common recon commands (`whoami`, `id`, `uname -a`, `cat /etc/passwd`, etc.) while logging every command entered.
- `simulate_attacker.py` — simulates three different attacker sessions with different credentials and behavior, since a local project has no real internet traffic to observe.
- `honeypot.log` — the real log output from running the simulated sessions.
- `ANALYSIS.md` — a write-up analyzing what each session did and why it matters.

## Safety

This never executes real commands. Every "shell" response is a hardcoded string — nothing typed by a connecting client is ever run on the host. It's designed to listen locally only; it was not deployed to the public internet for this exercise.

## How to run

```bash
python3 honeypot.py &
python3 simulate_attacker.py
cat honeypot.log
```
