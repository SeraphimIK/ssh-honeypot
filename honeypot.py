"""
honeypot.py

A lightweight, custom-built honeypot that mimics a Linux SSH/telnet login
over a raw TCP socket. It presents a fake login banner, accepts any
username/password (always "succeeding" so the attacker sticks around),
then serves a fake shell that returns canned output for common recon
commands. Every connection, credential attempt, and command is logged.

SAFETY: This never executes real shell commands. All "shell" responses
are hardcoded strings. Nothing an attacker types is ever run on the host.
It only listens locally (127.0.0.1) in this project — it is not deployed
to the public internet.
"""
import socket
import threading
import logging
from datetime import datetime

HOST = "127.0.0.1"
PORT = 2222

logging.basicConfig(
    filename="honeypot.log",
    level=logging.INFO,
    format="%(asctime)s %(message)s",
)

FAKE_FS = {
    "whoami": "root",
    "id": "uid=0(root) gid=0(root) groups=0(root)",
    "pwd": "/root",
    "ls": "backup.tar.gz  notes.txt  update.sh",
    "cat /etc/passwd": (
        "root:x:0:0:root:/root:/bin/bash\n"
        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
        "svc_backup:x:1001:1001::/home/svc_backup:/bin/bash"
    ),
    "uname -a": "Linux edge-gw01 5.15.0-91-generic x86_64 GNU/Linux",
}


def log_event(addr, event, detail=""):
    logging.info(f"src={addr[0]}:{addr[1]} event={event} detail={detail!r}")


def handle_client(conn, addr):
    log_event(addr, "connection_opened")
    try:
        conn.sendall(b"Ubuntu 22.04.3 LTS\r\nedge-gw01 login: ")
        username = conn.recv(1024).decode(errors="ignore").strip()
        log_event(addr, "username_attempt", username)

        conn.sendall(b"Password: ")
        password = conn.recv(1024).decode(errors="ignore").strip()
        log_event(addr, "password_attempt", password)

        # Always "succeed" so the attacker interacts further and we
        # capture what they actually try to do.
        conn.sendall(f"\r\nWelcome to edge-gw01\r\n{username}@edge-gw01:~$ ".encode())

        while True:
            data = conn.recv(1024)
            if not data:
                break
            command = data.decode(errors="ignore").strip()
            if not command:
                conn.sendall(b"$ ")
                continue

            log_event(addr, "command", command)

            if command in ("exit", "logout", "quit"):
                conn.sendall(b"logout\r\n")
                break

            response = FAKE_FS.get(command, f"bash: {command}: command not found")
            conn.sendall(f"{response}\r\n{username}@edge-gw01:~$ ".encode())
    except Exception as e:
        log_event(addr, "error", str(e))
    finally:
        log_event(addr, "connection_closed")
        conn.close()


def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(5)
    print(f"Honeypot listening on {HOST}:{PORT} (Ctrl+C to stop)")

    try:
        while True:
            conn, addr = server.accept()
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()
    except KeyboardInterrupt:
        print("\nShutting down.")
    finally:
        server.close()


if __name__ == "__main__":
    main()
