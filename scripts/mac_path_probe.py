#!/usr/bin/env python3
"""macOS physical-interface-bound TCP/TLS comparison, no DNS resolution.

Use literal IP addresses that you verified independently. This script does not
test UDP, QUIC, or proxy application traffic and cannot locate a failing router.
"""
import argparse
import ipaddress
import socket
import ssl
import sys
import time
from datetime import datetime

DARWIN_IP_BOUND_IF = 25
DARWIN_IPV6_BOUND_IF = 125


def probe(ip, port, ifindex, timeout, sni=None):
    family = socket.AF_INET6 if ip.version == 6 else socket.AF_INET
    result = {"tcp": False, "tls": "not-tested", "ms": None, "error": ""}
    started = time.monotonic()
    try:
        with socket.socket(family, socket.SOCK_STREAM) as raw:
            raw.settimeout(timeout)
            if family == socket.AF_INET:
                raw.setsockopt(socket.IPPROTO_IP,
                               getattr(socket, "IP_BOUND_IF", DARWIN_IP_BOUND_IF),
                               ifindex)
                address = (str(ip), port)
            else:
                raw.setsockopt(socket.IPPROTO_IPV6,
                               getattr(socket, "IPV6_BOUND_IF", DARWIN_IPV6_BOUND_IF),
                               ifindex)
                address = (str(ip), port, 0, 0)
            raw.connect(address)
            result["tcp"] = True
            result["ms"] = round((time.monotonic() - started) * 1000, 1)
            if sni:
                context = ssl.create_default_context()
                with context.wrap_socket(raw, server_hostname=sni):
                    result["tls"] = "ok"
    except (OSError, ssl.SSLError, ValueError) as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
        if sni and result["tcp"]:
            result["tls"] = "failed"
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--interface", default="en0", help="physical interface, e.g. en0")
    parser.add_argument("--target", required=True, help="literal failed-target IPv4/IPv6")
    parser.add_argument("--control", required=True, help="literal known-good control IP")
    parser.add_argument("--port", type=int, default=443)
    parser.add_argument("--rounds", type=int, default=5)
    parser.add_argument("--timeout", type=float, default=3.0)
    parser.add_argument("--delay", type=float, default=0.4)
    parser.add_argument("--target-sni", help="optional TLS hostname for target IP")
    parser.add_argument("--control-sni", help="optional TLS hostname for control IP")
    args = parser.parse_args()

    if sys.platform != "darwin":
        parser.error("macOS only: the interface-bound socket options are Darwin-specific")
    if not (1 <= args.port <= 65535) or not (1 <= args.rounds <= 20):
        parser.error("port must be 1..65535, rounds must be 1..20")
    if args.timeout <= 0 or args.delay < 0:
        parser.error("timeout must be positive; delay must be nonnegative")

    try:
        target, control = ipaddress.ip_address(args.target), ipaddress.ip_address(args.control)
        interface_index = socket.if_nametoindex(args.interface)
    except ValueError as exc:
        parser.error(f"invalid IP or interface: {exc}")
    except OSError as exc:
        parser.error(f"interface lookup failed: {exc}")
    if target.version != control.version:
        parser.error("target and control must use the same IP family")

    print(f"interface={args.interface} family=IPv{target.version} "
          f"port={args.port}, rounds={args.rounds}; no DNS lookup")
    tally = {"target": 0, "control": 0}
    for iteration in range(1, args.rounds + 1):
        for label, ip, hostname in (
            ("target", target, args.target_sni),
            ("control", control, args.control_sni),
        ):
            stamp = datetime.now().astimezone().isoformat(timespec="seconds")
            result = probe(ip, args.port, interface_index, args.timeout, hostname)
            tally[label] += int(result["tcp"])
            print(f"{stamp} round={iteration} {label}={ip} "
                  f"TCP={'ok' if result['tcp'] else 'fail'} "
                  f"TLS={result['tls']} tcp_ms={result['ms']} "
                  f"error={result['error']}", flush=True)
            time.sleep(args.delay)
    print(f"summary: target TCP {tally['target']}/{args.rounds}, "
          f"control TCP {tally['control']}/{args.rounds}")
    print("TLS status is meaningful only when the corresponding --*-sni is provided.")
    print("Before sharing logs, redact all server and account identifiers.")


if __name__ == "__main__":
    main()
