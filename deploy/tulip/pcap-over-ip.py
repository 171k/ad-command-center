#!/usr/bin/env python3
"""Zero-dependency PCAP-over-IP sniffer (fallback for a vulnbox with no tcpdump).

Linux + root only, Python 3 stdlib only. Captures Ethernet frames with an
AF_PACKET raw socket and serves them as a pcap stream to any client that
connects (e.g. Tulip's assembler via PCAP_OVER_IP). One fresh capture socket per
client, so reconnects just work — same model as `socat fork + tcpdump`.

    sudo python3 pcap-over-ip.py --port 1337 [--iface any] \
         [--exclude-port 22 --exclude-port 1337] [--include-port 8080 ...]

Port filtering is done in Python (no libpcap): a packet is dropped if either of
its TCP/UDP ports is excluded, or (when --include-port is given) if neither port
is included. Non-IP / non-TCP-UDP frames pass through.
"""
import argparse
import socket
import struct
import sys
import threading
import time

ETH_P_ALL = 0x0003
PCAP_GLOBAL = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)  # LINKTYPE_ETHERNET


def _ports(frame):
    """Return (src_port, dst_port) for IPv4 TCP/UDP, else None. py2+py3."""
    if len(frame) < 14:
        return None
    etype = struct.unpack("!H", frame[12:14])[0]
    off = 14
    if etype == 0x8100:  # one VLAN tag
        if len(frame) < 18:
            return None
        etype = struct.unpack("!H", frame[16:18])[0]
        off = 18
    if etype != 0x0800:  # IPv4 only (ARP/IPv6/etc. pass through)
        return None
    if len(frame) < off + 20:
        return None
    ihl = (frame[off] & 0x0F) * 4
    proto = frame[off + 9]
    if proto not in (6, 17):  # TCP, UDP
        return None
    l4 = off + ihl
    if len(frame) < l4 + 4:
        return None
    sport, dport = struct.unpack("!HH", frame[l4:l4 + 4])
    return sport, dport


def _keep(frame, exclude, include):
    pr = _ports(frame)
    if pr is None:
        return not include  # non-TCP/UDP: keep only when not restricting to ports
    sp, dp = pr
    if sp in exclude or dp in exclude:
        return False
    if include and sp not in include and dp not in include:
        return False
    return True


def serve_client(conn, addr, args, exclude, include):
    try:
        cap = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        if args.iface and args.iface.lower() != "any":
            cap.bind((args.iface, 0))
        cap.settimeout(1.0)
        conn.sendall(PCAP_GLOBAL)
        while True:
            try:
                frame = cap.recv(65535)
            except socket.timeout:
                continue
            if not _keep(frame, exclude, include):
                continue
            t = time.time()
            hdr = struct.pack("<IIII", int(t), int((t - int(t)) * 1_000_000), len(frame), len(frame))
            conn.sendall(hdr + frame)
    except (OSError, BrokenPipeError):
        pass
    finally:
        try:
            cap.close()
        except Exception:
            pass
        try:
            conn.close()
        except Exception:
            pass
    sys.stderr.write("client %s disconnected\n" % (addr,))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=1337)
    ap.add_argument("--iface", default="any")
    ap.add_argument("--exclude-port", type=int, action="append", default=[])
    ap.add_argument("--include-port", type=int, action="append", default=[])
    ap.add_argument("--allow-ip", default="", help="only accept clients from this IP (optional)")
    args = ap.parse_args()
    exclude = set(args.exclude_port)
    include = set(args.include_port)

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", args.port))
    srv.listen(8)
    sys.stderr.write("pcap-over-ip on :%s iface=%s exclude=%s include=%s\n"
                     % (args.port, args.iface, sorted(exclude), sorted(include)))
    while True:
        conn, addr = srv.accept()
        if args.allow_ip and addr[0] != args.allow_ip:
            sys.stderr.write("refused %s (only %s allowed)\n" % (addr[0], args.allow_ip))
            conn.close()
            continue
        threading.Thread(target=serve_client, args=(conn, addr, args, exclude, include),
                         daemon=True).start()


if __name__ == "__main__":
    main()
