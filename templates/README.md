# PortScope — Port Scanner + Service Detector

A small project for learning TCP networking, socket programming, and basic
network reconnaissance, with both a CLI tool and a browser-based deployment.

> **Legal/ethical note:** only scan hosts you own or are explicitly authorized
> to test — your own machine, a VM/container on your network, or
> `scanme.nmap.org`, which the Nmap project runs specifically so people can
> practice. Unauthorized scanning of systems you don't control can violate
> computer-abuse laws in most countries, regardless of intent.

## Files

| File | What it is |
|---|---|
| `port_scanner.py` | Standalone CLI scanner. No dependencies beyond the Python standard library. |
| `app.py` | Flask web server that wraps the scanner for browser use. |
| `templates/index.html` | Front-end console UI. |
| `requirements.txt` | Just Flask. |

## Running it

**CLI:**
```bash
python3 port_scanner.py scanme.nmap.org -p 1-1000
python3 port_scanner.py 127.0.0.1 -p 20,21,22,80,443 --banner -w 300
```

**Web:**
```bash
pip install -r requirements.txt
python3 app.py
# open http://127.0.0.1:5000
```

---

## The concepts, in order

### 1. What a socket actually is
A socket is the OS-level handle for one end of a network connection —
think of it as a file descriptor that happens to point at a network peer
instead of a file on disk. `socket.socket(AF_INET, SOCK_STREAM)` asks the OS
for a **TCP** socket over **IPv4**. Everything else (`connect`, `send`,
`recv`, `close`) is just read/write-style operations on that handle.

### 2. Ports
An IP address gets you to a *machine*; a port number (0–65535) gets you to a
specific *process* listening on that machine. A web server binds port 80/443,
an SSH daemon binds 22, and so on. "Scanning" a host means systematically
asking, for each port: *is anything listening here?*

### 3. The TCP three-way handshake
TCP connections open with a handshake:

```
client -------- SYN --------> server
client <----- SYN, ACK ------ server
client -------- ACK --------> server
```

`socket.connect()` performs this handshake for you. If it completes, the
port is **open** (something is listening and accepted the connection). If
the OS replies with a TCP RST, the port is **closed**. If nothing replies at
all, the port is usually **filtered** — a firewall is silently dropping the
packets.

This project does a **TCP connect scan**: the simplest, most "textbook"
approach, and the only kind of scan that doesn't need raw sockets or root
privileges (unlike the SYN "half-open" scan Nmap uses by default, which
sends the SYN but deliberately never finishes the handshake). Connect scans
are slower and more visible in logs, but they're honest about exactly what's
happening at the protocol level — which is the point of building one from
scratch.

### 4. Why `connect_ex()` instead of `connect()`
`connect()` raises an exception on failure. `connect_ex()` returns an error
code instead (`0` means success). When you're deliberately trying thousands
of ports and expecting most to fail, avoiding exception overhead on the
common path is both faster and cleaner code.

### 5. Service detection
Two layers, cheapest first:
- **Port-number lookup** — a lot of software still follows the IANA
  well-known-ports convention (22→SSH, 80→HTTP, 3306→MySQL...). It's a
  guess, not proof.
- **Banner grabbing** — actually read what the service says. Many protocols
  (SSH, FTP, SMTP) announce a version string the instant you connect. HTTP
  servers wait to be asked, so the scanner sends a minimal
  `HEAD / HTTP/1.0` request to provoke a response. This is the same
  technique tools like Nmap's `-sV` and Shodan use, just far less
  exhaustive.

### 6. Why threading, not multiprocessing
Scanning is **I/O-bound** — each connection attempt spends nearly all its
time waiting on the network, not using the CPU. Python's Global Interpreter
Lock (GIL) is irrelevant here because threads release it while blocked on
I/O, so a `ThreadPoolExecutor` gives you real concurrency for this workload
without the overhead of separate processes. Scanning 1,000 ports serially
at a 1-second timeout each would take up to ~17 minutes; with 200 threads
it takes seconds.

### 7. Turning a CLI tool into a web service
`app.py` shows the general pattern for wrapping any script as an HTTP
service: parse the request, validate input, call the existing function,
serialize the result as JSON. The interesting part for a *scanning* tool
specifically is the guardrails, because a public port scanner is an easy
thing to abuse:
- **Port cap per request** — stops one request from asking for a 65k-port
  scan of an arbitrary host.
- **Rate limiting** — a naive per-process timer here; a real deployment
  would use Redis or similar and rate-limit per source IP.
- **No stored raw sockets/root privileges** — the web version still only
  does connect scans, same as the CLI.

## Ideas to extend it

- **UDP scanning** — UDP has no handshake, so "is it open" is inferred from
  the *absence* of an ICMP port-unreachable reply, which is a genuinely
  different (and messier) problem.
- **OS fingerprinting** — infer the OS from TTL values and TCP option
  quirks in the response.
- **Persist scan history** — store results (SQLite) and diff scans over
  time to spot newly opened ports on your own infrastructure.
- **Async instead of threaded** — rewrite the scan loop with `asyncio` +
  `asyncio.open_connection` for comparison; good exercise in async I/O.
