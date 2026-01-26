# IBSR - Inline Block Simulation Report

IBSR is a **shadow-mode XDP/eBPF traffic collector** that generates offline reports showing what *would* have been blocked under conservative security rules - **without blocking anything**.

> **Shadow mode only.** IBSR never drops packets. It validates whether kernel-level enforcement *could* be safe before you commit to it.

## Quick Start

```bash
# Install
curl -LO https://github.com/NullRabbitLabs/nr-ibsr/releases/latest/download/ibsr-$(uname -m | sed 's/aarch64/arm64/')
sudo install -m 755 ibsr-* /usr/local/bin/ibsr

# Run
sudo mkdir -p /var/lib/ibsr/snapshots
sudo ibsr collect -p 8899 --out-dir /var/lib/ibsr/snapshots
```

## Documentation

**[https://nullrabbitlabs.github.io/nr-ibsr/](https://nullrabbitlabs.github.io/nr-ibsr/)**

## Requirements

- Debian 12+ / Ubuntu 22.04+ (kernel 6.1+)
- arm64 or x86_64
- root or CAP_BPF
- XDP-capable NIC

## Build from Source

```bash
docker compose run --rm test  # Run tests
./build.sh                    # Build binary -> ./dist/ibsr-<arch>
```

## Safety

- `XDP_PASS` only - cannot drop packets
- Fail-open by design
- Bounded memory (LRU map)
- Compile-time safety verification

## Status

Early-stage. Provided for controlled pilots and evaluation.

## License

MIT
