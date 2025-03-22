DNS Cache Poisoning PoC
A multi-threaded proof-of-concept (PoC) for DNS cache poisoning attacks.
For educational and authorized security testing purposes only.

Overview
This script attempts to brute force the combination of DNS transaction ID and source port used by a target DNS resolver in order to inject a malicious A record into its cache. Modern DNS servers typically employ randomization to mitigate such attacks, making real-world success rare unless:

The DNS server is old or misconfigured, with weak or no source-port randomization.

You have man-in-the-middle capabilities to sniff the actual TxID and port.

You’re testing a lab environment where randomization is deliberately reduced.

Despite the difficulty of succeeding against fully hardened resolvers, this PoC demonstrates the principles behind DNS cache poisoning—originally popularized by the Kaminsky attack.

Features
Multi-threaded approach using Python’s threading module.

Brute-forces a range of ports (defaults to 50000–50100) and multiple DNS transaction ID guesses per port (default 500).

Light verbosity: Logs progress so you can see how many packets have been sent per port.

Configurable via command-line arguments (e.g., domain, malicious IP, target resolver, etc.).

Uses Scapy for packet crafting and sending.

Usage
1. Install Dependencies
You’ll need Python 3 and Scapy on your system. For example:

bash
Copy
Edit
pip3 install scapy
2. Run the PoC
bash
Copy
Edit
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
All arguments explained:

--target-resolver: IP address of the DNS resolver you want to test/attack.

--fake-ns-ip: The IP you are spoofing as the authoritative nameserver. Commonly a real NS like 8.8.8.8 (Google DNS) or the actual authoritative server for the domain.

--domain: The DNS name you want to “poison.”

--malicious-ip: The IP address you want the target resolver to return for the domain once poisoned.

--port-start, --port-end: Range of UDP source ports you suspect the resolver might use for its outbound queries.

--attempts-per-port: Number of random DNS transaction ID guesses to send per port.

--threads: Number of worker threads for parallel packet sending.

--packets-per-log: Print a status update every N packets (helps you see progress).

3. Verification
If the resolver’s cache becomes poisoned, subsequent queries for mytest.domain.com (pointing to the target resolver) will return the malicious IP you specified—until the resolver’s TTL or cache is cleared.

Example check (from any machine using the target resolver):

bash
Copy
Edit
dig @192.168.1.10 mytest.domain.com
If it answers with 1.2.3.4, the attack succeeded.

Example Output
less
Copy
Edit
[+] Target Resolver : 192.168.1.10
[+] Fake NS IP      : 8.8.8.8
[+] Domain          : mytest.domain.com
[+] Malicious IP    : 1.2.3.4
[+] Port Range      : 50000 - 50100 (101 ports)
[+] Attempts/Port   : 500
[+] Threads         : 10
[+] Packets/Log     : 100
[*] Press Ctrl+C to stop early. Starting...
[Thread-1] Starting port 50000
[Thread-1] Port 50000: Sent 100 packets (0.3s elapsed)
...
[Thread-1] Finished port 50000, total 500 packets.
[Thread-1] Starting port 50001
...
[*] All ports processed. Finished sending packets.
[*] Check the DNS cache of the resolver to see if it was poisoned.
Notes
Performance: For higher throughput, you can increase --threads, use a larger port range, or reduce --packets-per-log to limit console printing overhead.

Modern Defenses: Randomizing source ports + transaction IDs makes pure brute force extremely difficult in production environments. For a realistic success rate, you typically need to observe (sniff) the actual query’s TxID + port in real-time.

Ethical Considerations: This PoC is intended for authorized penetration testing and educational demonstrations. Do not use it unlawfully.

License
[Choose an appropriate open-source license or leave as public domain / disclaimers here.]

Disclaimer: Use responsibly and legally. We are not liable for any misuse or damages. If you’re testing in a production environment, ensure you have explicit written permission.
