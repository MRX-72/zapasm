# zapasm

A single-port TCP connect scanner in x86_64 assembly. Raw syscalls only —
no libc, no `nmap`, no external tooling.

Made mostly for fun: it is a tiny recreation of the connect-scan core of my
[zapscan](https://github.com/MRX-72/zapscan) project, written from scratch in
assembly to understand exactly what the `socket()` and `connect()` calls in
`src/scanner.cpp` actually do at the instruction level.

## What it does

Takes an **IPv4 address** (dotted quad, no domain resolution) and a **single
port**, and reports `open` or `closed`.

- `socket(AF_INET, SOCK_STREAM, 0)` (syscall 41)
- `connect(fd, sockaddr_in, 16)` (syscall 42)
- prints the verdict with `write(1, ...)` (syscall 1)
- exits with `sys_exit` (syscall 60)

That's the whole program. Everything else — port scanning, CIDR/ranges, banner
grabbing, concurrency — is what [zapscan](https://github.com/MRX-72/zapscan)
adds on top of these same two system calls.

## Build & run

Requires [NASM](https://www.nasm.us/) and `ld` on Linux x86_64:

```bash
nasm -f elf64 -o zapasm.o zapasm.nasm
ld -o zapasm zapasm.o
```

```bash
python3 -m http.server 8000 &      # something listening on 127.0.0.1:8000
./zapasm 127.0.0.1 8000            # -> open
./zapasm 127.0.0.1 9999            # -> closed
```

## Layout

```
zapasm.nasm   the whole program
```

## Scope

Deliberately minimal:

- IPv4 literal only — no hostname resolution, no CIDR, no port ranges
- no `connect()` retry logic or timeouts
- Linux x86_64 syscall ABI only (macOS differs; see comments)

## License

MIT