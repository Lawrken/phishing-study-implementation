"""Exercise real nft rules in an explicitly disposable, disconnected container.

Never run this on the live VM. The root-owned listeners and address aliases are
owned fixtures, including aliases that resemble public/metadata destinations.
"""
import argparse
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from study.deployment import render_firewall

UID = 60001
RESOLVER = "93.184.216.35"
PUBLIC = "93.184.216.34"
ALTERNATE = "93.184.216.36"
V6 = "2001:4860::1234"


def command(*args):
    return subprocess.run(args, check=True, text=True, capture_output=True).stdout


class Listener:
    def __init__(self, address, port, udp=False):
        self.hits = 0
        self.udp = udp
        family = socket.AF_INET6 if ":" in address else socket.AF_INET
        self.sock = socket.socket(family, socket.SOCK_DGRAM if udp else socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((address, port))
        self.sock.settimeout(.1)
        if not udp:
            self.sock.listen()
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def serve(self):
        while not self.stop.is_set():
            try:
                if self.udp:
                    _, peer = self.sock.recvfrom(100)
                    self.hits += 1
                    self.sock.sendto(b"fixture", peer)
                else:
                    client, _ = self.sock.accept()
                    self.hits += 1
                    client.close()
            except socket.timeout:
                continue
            except OSError:
                break

    def close(self):
        self.stop.set()
        self.sock.close()
        self.thread.join(timeout=1)


def client(address, port, udp):
    # Drop identity before opening a socket. The firewall matches this socket UID.
    source = """import os,socket,sys
os.setgroups([])
os.setgid(60001)
os.setuid(60001)
address,port,udp=sys.argv[1],int(sys.argv[2]),sys.argv[3]=='1'
sock=socket.socket(socket.AF_INET6 if ':' in address else socket.AF_INET,socket.SOCK_DGRAM if udp else socket.SOCK_STREAM)
sock.settimeout(.3)
try:
 sock.connect((address,port))
 if udp:
  sock.send(b'fixture')
  sock.recv(100)
 print('connected')
except OSError:
 print('blocked')
finally:
 sock.close()
"""
    return command(sys.executable, "-c", source, address, str(port), "1" if udp else "0").strip() == "connected"


def run():
    if sys.platform != "linux" or os.geteuid() != 0 or not Path("/.dockerenv").exists():
        raise RuntimeError("requires the explicitly disposable root fixture container")
    interfaces = json.loads(command("ip", "-j", "link", "show"))
    if {entry["ifname"] for entry in interfaces} != {"lo"} or command("ip", "route", "show").strip():
        raise RuntimeError("requires --network none; refusing an externally connected namespace")
    tables = json.loads(command("nft", "-j", "list", "tables"))
    if any(entry.get("table", {}).get("name") in {"study_egress", "study_fixture_sentinel"} for entry in tables.get("nftables", [])):
        raise RuntimeError("fixture tables already exist; refusing to replace them")
    cases = [
        ("public_http", PUBLIC, 80, False, True),
        ("public_https_port", PUBLIC, 443, False, True),
        ("approved_dns_tcp", RESOLVER, 53, False, True),
        ("approved_dns_udp", RESOLVER, 53, True, True),
        ("alternate_dns_tcp", ALTERNATE, 53, False, False),
        ("alternate_dns_udp", ALTERNATE, 53, True, False),
        ("non_web_port", PUBLIC, 8080, False, False),
        ("udp_web_port", PUBLIC, 443, True, False),
        ("loopback", "127.0.0.1", 80, False, False),
        ("private", "10.0.0.2", 80, False, False),
        ("link_local_mock", "169.254.169.254", 80, False, False),
        ("local_public_address", "93.184.216.37", 80, False, False),
        ("public_gateway", "93.184.216.38", 80, False, False),
        ("ipv6_loopback", "::1", 80, False, False),
        ("ipv6_public_mock", V6, 80, False, False),
        ("ipv6_udp", V6, 53, True, False),
        ("mapped_private", "::ffff:10.0.0.2", 80, False, False),
    ]
    ipv4 = {address for _, address, _, _, _ in cases if ":" not in address}
    listeners = {}
    results = []
    table_created = False
    sentinel_created = False
    try:
        for address in sorted(ipv4 - {"127.0.0.1"}):
            command("ip", "address", "add", address + "/32", "dev", "lo")
        command("ip", "-6", "address", "add", V6 + "/128", "dev", "lo", "nodad")
        for _, address, port, udp, _ in cases:
            if address.startswith("::ffff:"):
                continue
            key = (address, port, udp)
            if key not in listeners:
                listeners[key] = Listener(*key)
        command("nft", "add", "table", "inet", "study_fixture_sentinel")
        sentinel_created = True
        rules = render_firewall(UID, RESOLVER, ["93.184.216.37"], ["93.184.216.38"])
        with tempfile.NamedTemporaryFile(mode="w", suffix=".nft") as rule_file:
            rule_file.write(rules)
            rule_file.flush()
            command("nft", "--check", "--file", rule_file.name)
            command("nft", "--file", rule_file.name)
        table_created = True
        for name, address, port, udp, expected in cases:
            key = ("10.0.0.2" if address.startswith("::ffff:") else address, port, udp)
            before = listeners[key].hits
            connected = client(address, port, udp)
            time.sleep(.02)
            hits = listeners[key].hits - before
            passed = connected == expected and (hits == 1 if expected else hits == 0)
            results.append({"case": name, "expected_allowed": expected, "connected": connected,
                            "receiver_hits": hits, "passed": passed})
        # The actual root helper changes this one chain for DNS outage preflight.
        command("nft", "flush", "chain", "inet", "study_egress", "dns_allow")
        for udp in (False, True):
            key = (RESOLVER, 53, udp)
            before = listeners[key].hits
            connected = client(RESOLVER, 53, udp)
            time.sleep(.02)
            hits = listeners[key].hits - before
            results.append({"case": "dns_outage_" + ("udp" if udp else "tcp"),
                            "connected": connected, "receiver_hits": hits, "passed": not connected and hits == 0})
        command("nft", "list", "table", "inet", "study_fixture_sentinel")
        return {"status": "passed" if all(row["passed"] for row in results) else "failed",
                "network": "none", "collector_uid": UID, "cases": results,
                "unrelated_table_preserved": True, "live_isolation_verified": False,
                "tls_verified": False, "public_dns_extraction_verified": False,
                "note": "Owned address aliases/listeners test kernel rules only; no host or public endpoints contacted."}
    finally:
        for listener in listeners.values():
            listener.close()
        if table_created:
            command("nft", "delete", "table", "inet", "study_egress")
        if sentinel_created:
            command("nft", "delete", "table", "inet", "study_fixture_sentinel")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--owned-disposable-container", action="store_true", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    path = Path(args.output)
    if path.exists():
        parser.error("use a fresh report path")
    try:
        report = run()
    except Exception as exc:
        report = {"status": "failed", "error_type": type(exc).__name__, "reason": str(exc),
                  "live_isolation_verified": False}
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    return 0 if report["status"] == "passed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
