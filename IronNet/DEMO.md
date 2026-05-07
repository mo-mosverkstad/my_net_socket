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
| [demo.24.mitm-relay.md](demos/demo.24.mitm-relay.md) | Phase 16a | MITM relay engine: ARP poison + sniff + forward |
| [demo.25.mitm-modify.md](demos/demo.25.mitm-modify.md) | Phase 16b | MITM traffic modification: in-transit data alteration |
| [demo.26.mitm-detect.md](demos/demo.26.mitm-detect.md) | Phase 16c | MITM detection: MAC flap monitoring |
| [demo.27.dns-spoof.md](demos/demo.27.dns-spoof.md) | Phase 17a | DNS response spoofing — zone poisoning |
| [demo.28.dns-cache-poison.md](demos/demo.28.dns-cache-poison.md) | Phase 17b | DNS cache poisoning with TTL expiry |
| [demo.29.dns-security.md](demos/demo.29.dns-security.md) | Phase 17c | DNS security — blocking cache poisoning |
| [demo.30.dns-spoof-ext.md](demos/demo.30.dns-spoof-ext.md) | Phase 17d | External DNS cache poisoning (Kaminsky-style) |
| [demo.31.vuln-server.md](demos/demo.31.vuln-server.md) | Phase 18a | Vulnerable application (buffer overflow, format string, integer overflow) |
| [demo.32.exploit-dev.md](demos/demo.32.exploit-dev.md) | Phase 18b | Exploit development (crash PoC, pattern offset, payload crafting) |
| [demo.33.exploit-mitigations.md](demos/demo.33.exploit-mitigations.md) | Phase 18c | Exploit mitigations (stack canary, bounds checking, ASLR) |
| [demo.34.covert-channels.md](demos/demo.34.covert-channels.md) | Phase 19a | Covert channels (ICMP payload, TCP ISN, DNS subdomain) |
| [demo.35.timing-channels.md](demos/demo.35.timing-channels.md) | Phase 19b | Timing-based covert channels (delay, counting, IP ID) |
| [demo.36.covert-detect.md](demos/demo.36.covert-detect.md) | Phase 19c | Covert channel detection (entropy, timing, ISN, DNS analysis) |
| [demo.37.mac-flood.md](demos/demo.37.mac-flood.md) | Phase 20a | MAC flooding attack (bridge table overflow) |
| [demo.38.port-security.md](demos/demo.38.port-security.md) | Phase 20b | Port security defense (MAC limit per port) |
| [demo.39.stealth-scan.md](demos/demo.39.stealth-scan.md) | Phase 21a | Stealth port scanning (FIN, XMAS, NULL scans) |
| [demo.40.decoy-scan.md](demos/demo.40.decoy-scan.md) | Phase 21b | Decoy scanning (hide real IP among fakes) |
| [demo.41.session-hijack.md](demos/demo.41.session-hijack.md) | Phase 22a | TCP session hijacking (inject data into active connection) |
| [demo.42.session-hijack-defense.md](demos/demo.42.session-hijack-defense.md) | Phase 22b | Session hijacking defense (strict window + challenge ACK) |

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
# Expected: 32 tests (21 unit + 11 module), all passing
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
  dns-spoof  --domain <name> --fake-ip <ip> --target <ip> [--count <n>] [--iface <name>]
  dns-spoof-ext --domain <name> --fake-ip <ip> --target <ip> [--count <n>] [--iface <name>]
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
ironctl> defense dns-validate enable
ironctl> defense covert-detect enable
ironctl> tcp flush
ironctl> arp flush
```
