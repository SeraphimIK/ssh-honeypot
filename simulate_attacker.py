"""
simulate_attacker.py

Simulates a few different "attackers" connecting to the honeypot and
poking around, so the honeypot produces real, non-fabricated log
output for the write-up. This models the kind of recon behavior a
real opportunistic scanner/attacker commonly performs.
"""
import socket
import time

HOST = "127.0.0.1"
PORT = 2222


def run_session(username, password, commands, delay=0.2):
    with socket.create_connection((HOST, PORT), timeout=5) as s:
        s.recv(1024)  # banner + login prompt
        s.sendall((username + "\n").encode())
        time.sleep(delay)
        s.recv(1024)  # password prompt
        s.sendall((password + "\n").encode())
        time.sleep(delay)
        s.recv(1024)  # shell prompt
        for cmd in commands:
            s.sendall((cmd + "\n").encode())
            time.sleep(delay)
            s.recv(2048)
        s.sendall(b"exit\n")
        time.sleep(delay)


if __name__ == "__main__":
    # Attacker 1: credential-stuffing style guess, then basic recon
    run_session("root", "toor", ["whoami", "id", "uname -a", "cat /etc/passwd"])

    # Attacker 2: different default-credential guess, checks for backups
    run_session("admin", "admin123", ["pwd", "ls"])

    # Attacker 3: opportunistic scanner just checking who's home
    run_session("test", "test", ["whoami"])

    print("Simulated attacker sessions complete. See honeypot.log")
