#!/usr/bin/env python3
"""Compare TCP and TLS paths via physical macOS interface and literal IPs.

Diagnostic transport TLS deliberately skips certificate validation, separating
untrusted certificates from actual handshake failures. Use --verify-cert
for a separate, EXTRA validated TLS connection. Never use this diagnostic
TLS configuration for application traffic. No UDP, QUIC or proxy test.
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


def bound_socket(ip, ifindex, timeout):
    family = socket.AF_INET6 if ip.version == 6 else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        if family == socket.AF_INET:
            sock.setsockopt(socket.IPPROTO_IP,
                            getattr(socket, "IP_BOUND_IF", DARWIN_IP_BOUND_IF),
                            ifindex)
        else:
            sock.setsockopt(socket.IPPROTO_IPV6,
                            getattr(socket, "IPV6_BOUND_IF", DARWIN_IPV6_BOUND_IF),
                            ifindex)
    except Exception:
        sock.close()
        raise
    return sock


def address_of(ip, port):
    return (str(ip), port) if ip.version == 4 else (str(ip), port, 0, 0)


def check_certificate(ip, port, ifindex, timeout, sni):
    """Separate validated TLS connection; does not alter transport TLS result."""
    try:
        with bound_socket(ip, ifindex, timeout) as raw:
            raw.connect(address_of(ip, port))
            with ssl.create_default_context().wrap_socket(raw, server_hostname=sni):
                pass
        return "verified", ""
    except (OSError, ssl.SSLError, ValueError) as exc:
        return "failed", f"{type(exc).__name__}: {exc}"


def probe(ip, port, ifindex, timeout, sni=None, verify_cert=False):
    result = {
        "tcp": False, "tcp_ms": None, "tls": "not-tested", "tls_ms": None,
        "certificate": "not-checked", "error": "", "certificate_error": "",
    }
    try:
        with bound_socket(ip, ifindex, timeout) as raw:
            started = time.monotonic()
            raw.connect(address_of(ip, port))
            result["tcp"] = True
            result["tcp_ms"] = round((time.monotonic() - started) * 1000, 1)
            if sni:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE  # Diagnostic transport handshake only
                started_tls = time.monotonic()
                with context.wrap_socket(raw, server_hostname=sni):
                    result["tls_ms"] = round((time.monotonic() - started_tls) * 1000, 1)
                    result["tls"] = "ok"
    except (OSError, ssl.SSLError, ValueError) as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
        if sni and result["tcp"]:
            result["tls"] = "failed"
    if verify_cert and sni and result["tls"] == "ok":
        result["certificate"], result["certificate_error"] = check_certificate(
            ip, port, ifindex, timeout, sni
        )
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
    parser.add_argument("--verify-cert", action="store_true",
                        help="perform extra validated TLS connection after transport TLS success")
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
        parser.error("target/control must have same IP family; run twice for IPv4 vs IPv6")

    print(f"interface={args.interface} family=IPv{target.version} "
          f"port={args.port}, rounds={args.rounds}; literal IP, no DNS")
    print("Separate TCP/TLS timers. Diagnostic TLS ignores certificate trust; "
          "--verify-cert opens an EXTRA connection.")
    tally = {name: {"tcp": 0, "tls": 0, "tls_attempts": 0,
                    "verified": 0, "verification_attempts": 0}
             for name in ("target", "control")}
    for iteration in range(1, args.rounds + 1):
        for label, ip, hostname in (
            ("target", target, args.target_sni),
            ("control", control, args.control_sni),
        ):
            stamp = datetime.now().astimezone().isoformat(timespec="seconds")
            result = probe(ip, args.port, interface_index, args.timeout,
                           hostname, args.verify_cert)
            stats = tally[label]
            stats["tcp"] += int(result["tcp"])
            if hostname:
                stats["tls_attempts"] += 1
                stats["tls"] += int(result["tls"] == "ok")
                if args.verify_cert and result["tls"] == "ok":
                    stats["verification_attempts"] += 1
                    stats["verified"] += int(result["certificate"] == "verified")
            print(f"{stamp} round={iteration} {label}={ip} "
                  f"TCP={'ok' if result['tcp'] else 'fail'} tcp_ms={result['tcp_ms']} "
                  f"TLS={result['tls']} tls_ms={result['tls_ms']} "
                  f"cert={result['certificate']} error={result['error']} "
                  f"cert_error={result['certificate_error']}", flush=True)
            time.sleep(args.delay)
    for label, stats in tally.items():
        print(f"{label}: TCP {stats['tcp']}/{args.rounds}, "
              f"TLS {stats['tls']}/{stats['tls_attempts']}, "
              f"certificate {stats['verified']}/{stats['verification_attempts']}")
    print("Certificate validation is NOT performed during diagnostic TLS handshake.")
    print("Run separately for IPv4 and IPv6, and redact addresses before sharing.")


if __name__ == "__main__":
    main()
