# IronNet — Test Cases

## Overview

All tests are run from `IronNet/build`:

```bash
# Run all tests (unit + module)
ctest --output-on-failure

# Run all module tests with verbose output
../src/tests/run_module_tests.sh .
```

**Current total: 29 tests (18 unit + 11 module), all passing.**

Note: The CLI (ironctl), audit logging (ironmon), application servers (ironapps: echo port 7, DNS port 53, KV port 6379, HTTP port 8080, RPC port 9000, vuln port 9999), network scanner (ironprobe), protocol fuzzer (ironfuzz), stress tester (ironload), external attack tool (ironattack: syn-flood, arp-spoof, vlan-hop, rst-inject, ip-spoof, slowloris, frag-attack, icmp-redirect, dns-spoof, dns-spoof-ext, exploit), network emulator (ironsim, ironsim-test), packet capture/replay (irontrace, irontrace-replay), MITM relay (ironmitm), and ironprobe-ext/ironreport are tested interactively, not via CTest. Defense mechanisms (syn-cookies, rate-limit, arp-inspection, vlan-strict, rst-validation, urpf, conn-timeout, frag-strict, icmp-redirect-disable, mitm-detect, dns-validate) and management commands (tcp flush, trace start/stop/replay, dns lookup/spoof-test/cache-poison/cache/cache-flush) are also tested interactively. See `demos/` folder for individual demo files (32 demos).

---

## Unit Tests

Unit tests are fast, minimal-output correctness checks. Each validates a single module in isolation using stubs for dependencies.

### test_stats (5 assertions)

| Test | What it verifies |
|------|-----------------|
| test_stats_init | All counters start at zero |
| test_stats_increment | Counter increments by 1 each call |
| test_stats_add | Counter increments by arbitrary value |
| test_stats_decrement | Counter decrements, never below zero |
| test_stats_name | Every counter has a string name |

### test_eth (5 assertions)

| Test | What it verifies |
|------|-----------------|
| test_parse_valid_ipv4_frame | 64-byte frame with EtherType 0x0800 parses correctly |
| test_parse_too_short | 10-byte frame rejected, drop counter incremented |
| test_parse_unknown_ethertype | EtherType 0x9999 rejected |
| test_build_frame | Frame built correctly (header bytes verified) |
| test_build_frame_too_large | 1600-byte payload rejected |

### test_route (4 assertions)

| Test | What it verifies |
|------|-----------------|
| test_route_add_and_lookup | Add route, lookup matches |
| test_route_no_match | Lookup for non-existent prefix returns -1 |
| test_route_longest_prefix | /32 > /24 > /0 (default) priority |
| test_route_delete | Deleted route no longer matches |

### test_acl (5 assertions)

| Test | What it verifies |
|------|-----------------|
| test_default_deny | No rules + default DENY → packet denied |
| test_default_permit | No rules + default PERMIT → packet permitted |
| test_permit_rule | TCP port 80 permitted, UDP port 80 denied (protocol mismatch) |
| test_deny_rule | Traffic to 10.0.2.0/24 denied, 10.0.3.0/24 permitted |
| test_first_match_wins | Rule 1 permits port 80, Rule 2 denies all TCP → port 80 permitted, port 443 denied |

### test_tcp (5 assertions)

| Test | What it verifies |
|------|-----------------|
| test_syn_creates_connection | SYN → SYN_RECV state, counters updated |
| test_ack_establishes_connection | SYN + ACK → ESTABLISHED, half-open decremented |
| test_fin_closes_connection | Full close: FIN→FIN_WAIT_1→ACK→FIN_WAIT_2→FIN→TIME_WAIT |
| test_invalid_flags_rejected | SYN+FIN and SYN+RST rejected, no state created |
| test_connection_table_full | 256 connections filled, next SYN rejected |

### test_ipsec (5 assertions)

| Test | What it verifies |
|------|-----------------|
| test_sa_add_find_delete | SA CRUD operations |
| test_outbound_protect | XOR transform applied correctly |
| test_inbound_decrypt | XOR reversal restores original data |
| test_discard_policy | DISCARD action returns -1 |
| test_fail_closed_no_sa | PROTECT with missing SA → drop |

### test_vlan (7 assertions)

| Test | What it verifies |
|------|-----------------|
| test_access_port_untagged | Untagged frame gets VLAN assigned |
| test_access_port_wrong_vlan_tag | Tagged frame with wrong VLAN → dropped |
| test_trunk_port_tagged | Tagged frame on trunk → tag stripped, VLAN extracted |
| test_trunk_port_vlan_not_allowed | Disallowed VLAN on trunk → dropped |
| test_trunk_port_untagged_dropped | Untagged frame on trunk → dropped |
| test_egress_trunk_inserts_tag | Egress on trunk inserts 4-byte VLAN tag |
| test_egress_access_no_tag | Egress on access sends untagged |

### test_arp (4 assertions)

| Test | What it verifies |
|------|-----------------|
| test_add_and_resolve | Add entry, resolve returns correct MAC |
| test_resolve_unknown_sends_request | Unknown IP triggers ARP request TX |
| test_arp_reply_on_request | ARP request for our IP → reply sent, sender learned |
| test_arp_entry_update | Second add for same IP updates MAC |

### test_ip_frag (4 assertions)

| Test | What it verifies |
|------|-----------------|
| test_no_fragmentation_needed | Packet within MTU → no fragmentation |
| test_fragmentation | Oversized packet → multiple fragments with MF flag |
| test_df_flag_prevents_fragmentation | DF flag set → fragmentation refused |
| test_reassembly | Two fragments → reassembled into complete packet |

### test_iface (4 assertions)

| Test | What it verifies |
|------|-----------------|
| test_iface_add_and_get | Add interface, retrieve by index |
| test_iface_find_by_ip | Find interface by IP address |
| test_iface_find_by_name | Find interface by name |
| test_iface_is_local_ip | Local IP detection (true/false) |

### test_pbr (4 assertions)

| Test | What it verifies |
|------|-----------------|
| test_pbr_match | PBR rule matches source prefix |
| test_pbr_no_match | Non-matching source → fallthrough |
| test_pbr_loop_detection | Same hop visited twice → loop detected (rc=-2) |
| test_pbr_delete | Deleted rule no longer matches |

### test_route_table (6 assertions)

| Test | What it verifies |
|------|------------------|
| test_default_main_table | "main" table created automatically at init |
| test_create_and_find | Create named table, find by name |
| test_independent_tables | Same prefix in different tables → different next-hop |
| test_longest_prefix_per_table | Longest-prefix match works per table |
| test_delete_route | Deleted route no longer matches |
| test_duplicate_table_name | Duplicate name returns existing table |

### test_conntrack (6 assertions)

| Test | What it verifies |
|------|------------------|
| test_new_connection | First packet creates NEW entry |
| test_reply_establishes | Reply packet transitions to ESTABLISHED |
| test_udp_established | UDP query+reply → ESTABLISHED |
| test_bidirectional_lookup | Entry found from both original and reply direction |
| test_unknown_is_invalid | No entry → CT_STATE_INVALID |
| test_packet_counters | Original and reply packet counts tracked |

### test_nat (6 assertions)

| Test | What it verifies |
|------|------------------|
| test_snat_outbound | Source IP rewritten, port allocated from pool |
| test_snat_return_traffic | Return traffic reverse-translated to original src |
| test_dnat_inbound | Destination IP+port rewritten to internal server |
| test_no_rule_passthrough | No rule matched → packet unchanged (rc=1) |
| test_snat_reuses_mapping | Same flow reuses existing mapping |
| test_different_flows_different_ports | Different hosts get different allocated ports |

### test_defense (5 assertions)

| Test | What it verifies |
|------|------------------|
| test_init_all_disabled | All 8 defenses start disabled after init |
| test_enable_disable | Enable/disable toggles correctly |
| test_syncookie_generate_validate | Cookie generated, validated with correct ack, rejected with wrong ack |
| test_rate_limit | Per-source rate cap enforced, different sources independent, tick resets |
| test_unknown_defense | Unknown defense name returns false/error |

### test_audit (5 assertions)

| Test | What it verifies |
|------|------------------|
| test_log_and_retrieve | Event logged to ring buffer, all fields correct |
| test_ring_buffer_wraps | Ring wraps at 256, oldest overwritten, newest preserved |
| test_disable_suppresses | Disabled audit produces no events |
| test_enable_resumes | Re-enabled audit captures new events |
| test_multiple_types | Different event types stored and retrieved correctly |

### test_app_socket (4 assertions)

| Test | What it verifies |
|------|------------------|
| test_listen_and_find | Register listener, find by protocol+port |
| test_find_wrong_port | Wrong port returns NULL |
| test_find_wrong_protocol | Wrong protocol returns NULL |
| test_multiple_listeners | Multiple listeners coexist, each found independently |

### test_dns (3 assertions)

| Test | What it verifies |
|------|------------------|
| test_zone_lookup_found | "ironnet.local" resolves to non-zero IP |
| test_zone_lookup_not_found | "nonexistent.com" returns 0 |
| test_zone_multiple_entries | All 3+ zone entries resolve correctly |

---

## Module Tests

Module tests produce verbose output with hex dumps, decoded fields, and visible packet processing. They test integration between multiple modules.

### test_l2_module (3 test cases)

| Test | What it demonstrates |
|------|---------------------|
| Text Payload Frame | Build frame with "Hello IronNet!", parse, show hex + ASCII |
| IPv4+TCP SYN Frame | Build IP+TCP packet, decode all header fields |
| Invalid Frame Handling | Short frame → DROPPED, counter verified |

### test_l3_module (3 test cases)

| Test | What it demonstrates |
|------|---------------------|
| IP packet parse and forward | Packet forwarded via route, TTL decremented 64→63 |
| IP packet TTL=1 | TTL expires after decrement → DROPPED |
| ICMP Echo Request → Reply | Ping processed, reply sent, hex dump of reply frame |

### test_pbr_acl_module (4 test cases)

| Test | What it demonstrates |
|------|---------------------|
| PBR redirects traffic | PBR overrides normal route, output on different interface |
| PBR loop detection | Same hop twice → loop detected |
| ACL denies SSH (port 22) | TCP port 22 denied, not forwarded |
| ACL permits HTTP (port 80) | TCP port 80 permitted and forwarded |

### test_l4_module (4 test cases)

| Test | What it demonstrates |
|------|---------------------|
| TCP 3-way handshake | SYN→SYN_RECV→ACK→ESTABLISHED, hex dump of SYN |
| TCP graceful close | FIN→FIN_WAIT_1→ACK→FIN_WAIT_2→FIN→TIME_WAIT |
| TCP invalid flags | SYN+FIN rejected, no state created |
| UDP packet received | UDP parsed, port/payload visible |

### test_ipsec_module (4 test cases)

| Test | What it demonstrates |
|------|---------------------|
| Encrypt/decrypt roundtrip | "Hello IronNet!" → XOR encrypted → XOR decrypted → original |
| DISCARD policy | Traffic from 10.0.1.0/24 discarded, other bypassed |
| Fail closed | PROTECT with missing SA → dropped |
| SA expiry | SA lifetime exceeded → expired by timer |

### test_vlan_module (4 test cases)

| Test | What it demonstrates |
|------|---------------------|
| Trunk egress inserts tag | Hex shows TPID=8100, VID visible in TCI |
| Trunk ingress strips tag | Tag removed, EtherType back at offset 12 |
| Access port assigns VLAN | Untagged frame gets VLAN 100 assigned |
| VLAN isolation | Wrong VLAN on access port → DROPPED |

### test_bridge_module (4 test cases)

| Test | What it demonstrates |
|------|---------------------|
| MAC learning + unicast forward | Unknown → flood, then learned → unicast to correct port |
| Broadcast flooding | Broadcast flooded to all ports except ingress |
| VLAN isolation | Broadcast only reaches ports in same VLAN |
| Same-port drop (no hairpin) | Destination on same port → dropped |

### test_route_table_module (3 test cases)

| Test | What it demonstrates |
|------|---------------------|
| Independent routing | Same destination in different tables → different next-hop |
| PBR table selection | PBR matches src prefix → uses alternate table |
| Table isolation | Route in one table not visible in another |

### test_conntrack_module (4 test cases)

| Test | What it demonstrates |
|------|---------------------|
| TCP lifecycle | SYN→NEW, SYN+ACK→ESTABLISHED, FIN→closing, packet counts |
| UDP stateful | Query→NEW, Reply→ESTABLISHED |
| Stateful ACL | Return traffic PERMIT (established), unsolicited DENY (invalid) |
| Timeout expiry | UDP entry expires after 30s timeout |

### test_nat_module (4 test cases)

| Test | What it demonstrates |
|------|---------------------|
| SNAT roundtrip | Outbound translated, return traffic reverse-translated |
| DNAT port forwarding | External 203.0.113.1:80 → internal 10.0.1.100:8080 |
| Multiple hosts share IP | 3 hosts get different ports on same public IP |
| No rule pass-through | No NAT configured → packet unchanged |

### test_security_module (3 test cases)

| Test | What it demonstrates |
|------|---------------------|
| Fuzz no crash (500 iters) | 3 seeds, 500 mutations, 0 crashes |
| Fuzz mutation changes data | 50 mutations all produce different output |
| Route stress (100 routes) | 100 routes added, all lookups succeed, non-existent fails |

---

## Live Demo

See `DEMO.md` for running the virtual router with real TAP interfaces:
- ICMP ping (echo request/reply)
- ACL deny visible in logs
- Debug logging with `-d` flag

---

## Running Tests

```bash
cd IronNet/build

# All tests
ctest --output-on-failure

# Single unit test
./tests/test_stats
./tests/test_eth
./tests/test_route
./tests/test_acl
./tests/test_tcp
./tests/test_ipsec
./tests/test_vlan
./tests/test_arp
./tests/test_ip_frag
./tests/test_iface
./tests/test_pbr
./tests/test_route_table
./tests/test_conntrack
./tests/test_nat
./tests/test_defense
./tests/test_audit
./tests/test_app_socket
./tests/test_dns

# Single module test (verbose)
./tests/test_l2_module
./tests/test_l3_module
./tests/test_pbr_acl_module
./tests/test_l4_module
./tests/test_ipsec_module
./tests/test_vlan_module
./tests/test_bridge_module
./tests/test_route_table_module
./tests/test_conntrack_module
./tests/test_nat_module
./tests/test_security_module

# All module tests via script
../src/tests/run_module_tests.sh .
```
