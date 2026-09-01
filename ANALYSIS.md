# Honeypot Session Analysis

Analyst: Seraphim Ikuomola

## What happened

Three separate sessions connected to the honeypot and were logged in full, capturing every credential attempt and every command they ran.

### Session 1 (src port 51122)
- Tried username root, password toor, a classic default credential guess (the well known reversed root password from old Ubuntu live CDs).
- Ran recon commands in order: whoami, id, uname -a, cat /etc/passwd.
- This is a textbook post access recon sequence: confirm who you are, confirm your privilege level, fingerprint the OS, then look for other accounts on the box. Maps to T1082, System Information Discovery, and T1087, Account Discovery.

### Session 2 (src port 51124)
- Tried admin, password admin123, another common default credential pair.
- Ran pwd and ls, checking current location and looking for interesting files. In the fake filesystem, this surfaces backup.tar.gz, which would be an obvious next target for a real attacker.

### Session 3 (src port 51132)
- Tried test, password test, and only ran whoami before leaving.
- This pattern of minimal interaction with no follow up is typical of automated credential stuffing bots that check thousands of hosts for known logins and only linger if something interesting shows up.

## Why this is useful

This mirrors what a real internet facing SSH honeypot sees constantly: automated bots and scanners trying default and common credentials, and if they get in, running a short, predictable recon sequence before deciding whether the box is worth further effort. Watching that sequence, and logging every credential and command, not just the fact that someone connected, is what separates a honeypot from just a login page.

## Design notes and safety

- The honeypot never runs anything an attacker types. Every shell response is a hardcoded string returned for a known command; unknown commands return command not found, just like a real shell.
- Login always succeeds regardless of the credentials entered. The goal is to see what the attacker does next, not to actually gate access.
- This was run locally against simulated attacker sessions since deploying a public facing honeypot wasn't practical for this exercise. In a real deployment, this same logging approach would apply to real internet traffic.
