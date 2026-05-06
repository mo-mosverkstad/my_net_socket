# IronNet — Demo Index

All demos are in the `demos/` folder. Each file is fully self-contained — it includes all prerequisites, build steps, and terminal-by-terminal instructions. Pick any one and follow it independently.

## Demo Files

| File | Phase | What it demonstrates |
|------|-------|---------------------|
| [demo.01.virtual-router.md](demos/demo.01.virtual-router.md) | Phase 7 | Router startup, ICMP ping, ACL permit/deny |
| [demo.02.cli.md](demos/demo.02.cli.md) | Phase 9 | CLI commands: routes, ACLs, ARP, TCP flush |
| [demo.03.audit-log.md](demos/demo.03.audit-log.md) | Phase 10 | Audit log, JSON export, enable/disable |
| [demo.04.application-servers.md](demos/demo.04.application-servers.md) | Phase 11 | Echo, DNS, KV store, HTTP, Binary RPC |
| [demo.05.scanner.md](demos/demo.05.scanner.md) | Phase 12a | Port scan, ping, ACL validation (ironprobe) |
| [demo.06.fuzzer.md](demos/demo.06.fuzzer.md) | Phase 12b | Protocol fuzzing with 8 mutation strategies (ironfuzz) |
| [demo.07.stress-tester.md](demos/demo.07.stress-tester.md) | Phase 12c | TCP flood, route stress, ACL stress, bandwidth (ironload) |
| [demo.08.syn-flood-attack.md](demos/demo.08.syn-flood-attack.md) | Phase 13a | SYN flood attack + SYN cookies & rate limit defense |
| [demo.09.arp-spoof-attack.md](demos/demo.09.arp-spoof-attack.md) | Phase 13b | ARP spoofing attack + ARP inspection defense |
| [demo.10.vlan-hop-attack.md](demos/demo.10.vlan-hop-attack.md) | Phase 13b | VLAN hopping attack + VLAN strict mode defense |
| [demo.11.rst-inject-attack.md](demos/demo.11.rst-inject-attack.md) | Phase 13c | TCP RST injection attack + RST validation defense |
| [demo.12.ip-spoof-attack.md](demos/demo.12.ip-spoof-attack.md) | Phase 13c | IP spoofing attack + uRPF defense |
| [demo.13.slowloris-attack.md](demos/demo.13.slowloris-attack.md) | Phase 13d | Slowloris attack + connection idle timeout defense |
| [demo.14.frag-attack.md](demos/demo.14.frag-attack.md) | Phase 13d | Fragmentation attack + frag-strict defense |
| [demo.15.icmp-redirect-attack.md](demos/demo.15.icmp-redirect-attack.md) | Phase 13e | ICMP redirect attack + redirect disable defense |
| [demo.16.external-scanner.md](demos/demo.16.external-scanner.md) | Phase 13e | ironprobe-ext real SYN scan via raw socket |
| [demo.17.attack-defense-report.md](demos/demo.17.attack-defense-report.md) | Phase 13e | Automated attack-defense test report |
| [demo.18.ironsim-2node.md](demos/demo.18.ironsim-2node.md) | Phase 14a | ironsim 2-node topology emulator |
| [demo.19.ironsim-3node.md](demos/demo.19.ironsim-3node.md) | Phase 14b | ironsim 3-node topology with link impairments |
| [demo.20.ironsim-test.md](demos/demo.20.ironsim-test.md) | Phase 14c | Traffic generator and topology test report |
| [demo.21.irontrace-capture.md](demos/demo.21.irontrace-capture.md) | Phase 15a | Packet capture to pcap file + tcpdump/Wireshark viewing |
| [demo.22.irontrace-replay.md](demos/demo.22.irontrace-replay.md) | Phase 15b | Replay pcap captures for regression testing |
| [demo.23.regression-workflow.md](demos/demo.23.regression-workflow.md) | Phase 15c | Full regression workflow: capture → fix → replay → verify |
| [demo.24.mitm-relay.md](demos/demo.24.mitm-relay.md) | Phase 16a/16b/16c | MITM relay + traffic modification + detection |

## Quick Build Reference

```bash
cd IronNet
mkdir -p build && cd build
cmake ../src -DCMAKE_BUILD_TYPE=Debug
make
```

## Quick Test Reference

```bash
cd IronNet/build
ctest --output-on-failure
# Expected: 29 tests (18 unit + 11 module), all passing
```

## ironattack Subcommands

```bash
sudo ./ironattack/ironattack --help

Commands:
  syn-flood  --target <ip> --port <port> [--rate <pps>] [--count <n>] [--iface <name>]
  arp-spoof  --target <ip> --impersonate <ip> [--iface <name>] [--count <n>]
  vlan-hop   --target <ip> --target-vlan <vid> [--outer-vlan <vid>] [--iface <name>] [--count <n>]
  rst-inject --target <ip> --port <port> --src <ip> --sport <port> [--seq <n>] [--count <n>] [--iface <name>]
  slowloris  --target <ip> --port <port> [--conns <n>] [--iface <name>]
  frag-attack --target <ip> [--overlap] [--tiny] [--iface <name>] [--count <n>]
  icmp-redirect --target <ip> --new-gw <ip> --orig-dst <ip> [--count <n>] [--iface <name>]
```

## Defense Commands

```
ironctl> defense show
ironctl> defense syn-cookies enable
ironctl> defense rate-limit 100/s
ironctl> defense arp-inspection enable
ironctl> defense vlan-strict enable
ironctl> defense rst-validation enable
ironctl> defense urpf enable
ironctl> defense conn-timeout 30
ironctl> defense frag-strict enable
ironctl> defense icmp-redirect-disable enable
ironctl> tcp flush
```
