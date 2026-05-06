#include "cli.h"
#include "log.h"
#include "stats.h"
#include "utils.h"
#include "../ironstack/l3/route.h"
#include "../ironstack/l3/route_table.h"
#include "../ironstack/l3/acl.h"
#include "../ironstack/l3/pbr.h"
#include "../ironstack/l3/conntrack.h"
#include "../ironstack/l3/nat.h"
#include "../ironstack/l2/arp.h"
#include "../ironstack/l2/vlan.h"
#include "../ironstack/l4/tcp.h"
#include "../ironstack/core/iface.h"
#include "../ironstack/security/ipsec.h"
#include "../ironmon/audit.h"
#include "../ironmon/stats_json.h"
#include "../ironprobe/probe.h"
#include "../ironfuzz/fuzz.h"
#include "../ironload/load.h"
#include "../ironstack/security/defense.h"
#include "../irontrace/trace.h"
#include "../ironstack/io/vnic.h"
#include "../ironapps/dns_server.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <stdbool.h>

/* Defined in main.c */
extern void iron_request_shutdown(void);

#define MODULE "CLI"
#define CLI_MAX_LINE 256
#define CLI_MAX_ARGS 16

static pthread_t g_cli_thread;
static volatile bool g_cli_running = false;

/* Parse line into argc/argv */
static int cli_tokenize(char *line, char **argv, int max_args) {
    int argc = 0;
    char *tok = strtok(line, " \t");
    while (tok && argc < max_args) {
        argv[argc++] = tok;
        tok = strtok(NULL, " \t");
    }
    return argc;
}

/* --- Command handlers --- */

static void cmd_help(void) {
    printf("Available commands:\n");
    printf("  show stats              - Display counters\n");
    printf("  show stats json         - Display counters as JSON\n");
    printf("  show routes             - Display routing table\n");
    printf("  show route-tables       - Display all routing tables\n");
    printf("  show arp                - Display ARP table\n");
    printf("  show tcp                - Display TCP connections\n");
    printf("  show conntrack          - Display connection tracking\n");
    printf("  show nat                - Display NAT mappings\n");
    printf("  show interfaces         - Display interfaces\n");
    printf("  show ipsec              - Display IPsec SA/policies\n");
    printf("  show audit-log          - Display recent security events\n");
    printf("  show audit-log json     - Display security events as JSON\n");
    printf("  route add <prefix>/<len> via <next_hop> iface <idx>\n");
    printf("  route delete <prefix>/<len>\n");
    printf("  acl add <permit|deny> <tcp|udp|icmp|any> port <port>\n");
    printf("  acl delete <rule_id>\n");
    printf("  arp add <ip> <mac>\n");
    printf("  audit enable            - Enable audit logging\n");
    printf("  audit disable           - Disable audit logging\n");
    printf("  scan <ip> [start] [end] - Scan ports on target\n");
    printf("  ping <ip>               - Check if target is alive\n");
    printf("  acl-check <ip>          - Validate ACL enforcement\n");
    printf("  fuzz <tcp|dns|http|rpc> <iterations> - Fuzz a target\n");
    printf("  load <tcp|route|acl|bw> [count]       - Stress test\n");
    printf("  trace start <file> [l2|l3|l4|all]     - Start packet capture\n");
    printf("  trace stop                            - Stop capture\n");
    printf("  trace replay <file>                   - Replay pcap file\n");
    printf("  trace status                          - Show capture state\n");
    printf("  defense <name> <enable|disable>        - Toggle defense\n");
    printf("  defense rate-limit <N>/s               - Set rate limit\n");
    printf("  defense conn-timeout <secs>            - Set idle connection timeout\n");
    printf("  defense show                           - Show defense status\n");
    printf("  help                    - Show this help\n");
    printf("  exit                    - Stop the router\n");
}

static void cmd_show(int argc, char **argv) {
    if (argc < 2) {
        printf("Usage: show <stats|routes|route-tables|arp|tcp|conntrack|nat|interfaces|ipsec>\n");
        return;
    }

    if (strcmp(argv[1], "stats") == 0) {
        if (argc >= 3 && strcmp(argv[2], "json") == 0) {
            iron_stats_dump_json();
        } else {
            iron_stats_dump();
        }
    } else if (strcmp(argv[1], "routes") == 0) {
        route_dump();
    } else if (strcmp(argv[1], "route-tables") == 0) {
        route_table_dump();
    } else if (strcmp(argv[1], "arp") == 0) {
        arp_dump();
    } else if (strcmp(argv[1], "tcp") == 0) {
        tcp_dump();
    } else if (strcmp(argv[1], "conntrack") == 0) {
        conntrack_dump();
    } else if (strcmp(argv[1], "nat") == 0) {
        nat_dump();
    } else if (strcmp(argv[1], "interfaces") == 0) {
        int count = iface_get_count();
        printf("Interfaces (%d):\n", count);
        for (int i = 0; i < count; i++) {
            iface_config_t *ifc = iface_get(i);
            if (!ifc) continue;
            char ip_buf[16];
            printf("  %s  %s/%d  MAC %02X:%02X:%02X:%02X:%02X:%02X  %s\n",
                   ifc->name,
                   iron_ip_to_str(ifc->ip, ip_buf, sizeof(ip_buf)), ifc->prefix_len,
                   ifc->mac[0], ifc->mac[1], ifc->mac[2],
                   ifc->mac[3], ifc->mac[4], ifc->mac[5],
                   ifc->up ? "UP" : "DOWN");
        }
    } else if (strcmp(argv[1], "ipsec") == 0) {
        ipsec_dump();
    } else if (strcmp(argv[1], "audit-log") == 0) {
        if (argc >= 3 && strcmp(argv[2], "json") == 0) {
            audit_dump_json();
        } else {
            audit_dump();
        }
    } else {
        printf("Unknown: show %s\n", argv[1]);
    }
}

static void cmd_route(int argc, char **argv) {
    if (argc < 2) {
        printf("Usage: route <add|delete> ...\n");
        return;
    }

    if (strcmp(argv[1], "add") == 0) {
        /* route add 10.0.1.0/24 via 10.0.1.254 iface 0 */
        if (argc < 6) {
            printf("Usage: route add <prefix>/<len> via <next_hop> iface <idx>\n");
            return;
        }
        char ip_str[16]; int plen;
        if (sscanf(argv[2], "%15[^/]/%d", ip_str, &plen) != 2) {
            printf("Invalid prefix: %s\n", argv[2]);
            return;
        }
        uint32_t next_hop = iron_str_to_ip(argv[4]);
        int out_iface = atoi(argv[6]);
        ip_prefix_t prefix = { iron_str_to_ip(ip_str), (uint8_t)plen };
        route_add(prefix, next_hop, out_iface);
    } else if (strcmp(argv[1], "delete") == 0) {
        if (argc < 3) {
            printf("Usage: route delete <prefix>/<len>\n");
            return;
        }
        char ip_str[16]; int plen;
        if (sscanf(argv[2], "%15[^/]/%d", ip_str, &plen) != 2) {
            printf("Invalid prefix: %s\n", argv[2]);
            return;
        }
        ip_prefix_t prefix = { iron_str_to_ip(ip_str), (uint8_t)plen };
        if (route_delete(prefix) == 0)
            printf("Route deleted.\n");
        else
            printf("Route not found.\n");
    } else {
        printf("Unknown: route %s\n", argv[1]);
    }
}

static void cmd_acl(int argc, char **argv) {
    if (argc < 2) {
        printf("Usage: acl <add|delete|show> ...\n");
        return;
    }

    if (strcmp(argv[1], "add") == 0) {
        /* acl add permit tcp port 80 */
        if (argc < 5) {
            printf("Usage: acl add <permit|deny> <tcp|udp|icmp|any> port <port>\n");
            return;
        }
        acl_action_t action = (strcmp(argv[2], "permit") == 0) ? ACL_PERMIT : ACL_DENY;
        ip_protocol_t proto = PROTO_ANY;
        if (strcmp(argv[3], "tcp") == 0) proto = PROTO_TCP;
        else if (strcmp(argv[3], "udp") == 0) proto = PROTO_UDP;
        else if (strcmp(argv[3], "icmp") == 0) proto = PROTO_ICMP;

        uint16_t port = 0;
        if (argc >= 6 && strcmp(argv[4], "port") == 0)
            port = (uint16_t)atoi(argv[5]);

        static uint32_t acl_id_counter = 100;
        acl_match_t m = {0};
        m.protocol = proto;
        if (port > 0) m.dst_port = (port_range_t){port, port};
        acl_add_rule(acl_id_counter++, &m, action);
    } else if (strcmp(argv[1], "delete") == 0) {
        if (argc < 3) {
            printf("Usage: acl delete <rule_id>\n");
            return;
        }
        uint32_t rule_id = (uint32_t)atoi(argv[2]);
        if (acl_delete_rule(rule_id) == 0)
            printf("ACL rule %u deleted.\n", rule_id);
        else
            printf("ACL rule %u not found.\n", rule_id);
    } else if (strcmp(argv[1], "show") == 0) {
        acl_dump();
    } else {
        printf("Unknown: acl %s\n", argv[1]);
    }
}

static void cmd_arp_cli(int argc, char **argv) {
    if (argc < 2) {
        printf("Usage: arp <add|show> ...\n");
        return;
    }

    if (strcmp(argv[1], "add") == 0) {
        /* arp add 10.0.1.5 02:00:00:00:00:05 */
        if (argc < 4) {
            printf("Usage: arp add <ip> <mac>\n");
            return;
        }
        uint32_t ip = iron_str_to_ip(argv[2]);
        uint8_t mac[6];
        if (sscanf(argv[3], "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                   &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) != 6) {
            printf("Invalid MAC: %s\n", argv[3]);
            return;
        }
        arp_add_entry(ip, mac);
        printf("ARP entry added.\n");
    } else if (strcmp(argv[1], "show") == 0) {
        arp_dump();
    } else if (strcmp(argv[1], "spoof-test") == 0) {
        if (argc < 3) {
            printf("Usage: arp spoof-test <ip>\n");
        } else {
            uint32_t ip = iron_str_to_ip(argv[2]);
            uint8_t fake_mac[6] = {0x02, 0xDE, 0xAD, 0xBE, 0xEF, 0x99};
            printf("Simulating ARP spoof for %s (fake MAC 02:DE:AD:BE:EF:99)\n", argv[2]);
            arp_add_entry(ip, fake_mac);
        }
    } else {
        printf("Unknown: arp %s\n", argv[1]);
    }
}

/* --- Main command dispatch --- */

int cli_execute(const char *line) {
    char buf[CLI_MAX_LINE];
    strncpy(buf, line, CLI_MAX_LINE - 1);
    buf[CLI_MAX_LINE - 1] = 0;

    char *argv[CLI_MAX_ARGS];
    int argc = cli_tokenize(buf, argv, CLI_MAX_ARGS);
    if (argc == 0) return 0;

    if (strcmp(argv[0], "help") == 0 || strcmp(argv[0], "?") == 0) {
        cmd_help();
    } else if (strcmp(argv[0], "show") == 0) {
        cmd_show(argc, argv);
    } else if (strcmp(argv[0], "route") == 0) {
        cmd_route(argc, argv);
    } else if (strcmp(argv[0], "acl") == 0) {
        cmd_acl(argc, argv);
    } else if (strcmp(argv[0], "arp") == 0) {
        cmd_arp_cli(argc, argv);
    } else if (strcmp(argv[0], "scan") == 0) {
        /* scan <ip> [port_start] [port_end] */
        if (argc < 2) {
            printf("Usage: scan <target_ip> [port_start] [port_end]\n");
        } else {
            uint32_t target = iron_str_to_ip(argv[1]);
            uint16_t pstart = (argc >= 3) ? (uint16_t)atoi(argv[2]) : 1;
            uint16_t pend = (argc >= 4) ? (uint16_t)atoi(argv[3]) : 100;
            probe_scan_result_t result;
            probe_tcp_scan(target, pstart, pend, &result);
            probe_print_result(&result);
        }
    } else if (strcmp(argv[0], "ping") == 0) {
        if (argc < 2) {
            printf("Usage: ping <target_ip>\n");
        } else {
            uint32_t target = iron_str_to_ip(argv[1]);
            int rc = probe_icmp_ping(target);
            char ip_buf[16];
            printf("%s is %s\n", iron_ip_to_str(target, ip_buf, sizeof(ip_buf)),
                   rc == 0 ? "ALIVE" : "UNREACHABLE");
        }
    } else if (strcmp(argv[0], "acl-check") == 0) {
        /* acl-check <ip> */
        if (argc < 2) {
            printf("Usage: acl-check <target_ip>\n");
        } else {
            uint32_t target = iron_str_to_ip(argv[1]);
            uint16_t expect_open[] = {7, 53, 6379, 8080, 9000};
            uint16_t expect_filtered[] = {22};
            int mismatches;
            probe_acl_validate(target, expect_open, 5, expect_filtered, 1, &mismatches);
            printf("ACL validation: %d mismatches\n", mismatches);
        }
    } else if (strcmp(argv[0], "fuzz") == 0) {
        /* fuzz <target> <iterations> */
        /* targets: tcp, dns, http, rpc */
        if (argc < 3) {
            printf("Usage: fuzz <tcp|dns|http|rpc> <iterations>\n");
        } else {
            int iters = atoi(argv[2]);
            fuzz_engine_t engine;
            fuzz_init(&engine);

            uint8_t seed_buf[FUZZ_MAX_PACKET];
            int seed_len;

            if (strcmp(argv[1], "tcp") == 0) {
                seed_len = fuzz_seed_tcp_syn(seed_buf, sizeof(seed_buf));
                fuzz_add_seed(&engine, "tcp_syn", seed_buf, seed_len);
                extern int tcp_input(uint32_t, uint32_t, uint8_t*, int, int);
                fuzz_run(&engine, iters, (int(*)(const uint8_t*,int))tcp_input);
            } else if (strcmp(argv[1], "dns") == 0) {
                seed_len = fuzz_seed_dns_query(seed_buf, sizeof(seed_buf));
                fuzz_add_seed(&engine, "dns_query", seed_buf, seed_len);
                extern int udp_input(uint32_t, uint32_t, uint8_t*, int, int);
                fuzz_run(&engine, iters, (int(*)(const uint8_t*,int))udp_input);
            } else if (strcmp(argv[1], "http") == 0) {
                seed_len = fuzz_seed_http_get(seed_buf, sizeof(seed_buf));
                fuzz_add_seed(&engine, "http_get", seed_buf, seed_len);
                extern int tcp_input(uint32_t, uint32_t, uint8_t*, int, int);
                fuzz_run(&engine, iters, (int(*)(const uint8_t*,int))tcp_input);
            } else if (strcmp(argv[1], "rpc") == 0) {
                seed_len = fuzz_seed_rpc_ping(seed_buf, sizeof(seed_buf));
                fuzz_add_seed(&engine, "rpc_ping", seed_buf, seed_len);
                extern int tcp_input(uint32_t, uint32_t, uint8_t*, int, int);
                fuzz_run(&engine, iters, (int(*)(const uint8_t*,int))tcp_input);
            } else {
                printf("Unknown target: %s (use tcp|dns|http|rpc)\n", argv[1]);
            }

            fuzz_print_stats(&engine);
        }
    } else if (strcmp(argv[0], "load") == 0) {
        /* load <test> [count] */
        if (argc < 2) {
            printf("Usage: load <tcp|route|acl|bw> [count]\n");
        } else {
            load_config_t cfg = {0};
            cfg.count = (argc >= 3) ? atoi(argv[2]) : LOAD_DEFAULT_COUNT;
            cfg.target_ip = 0x0A000101; /* 10.0.1.1 */
            cfg.target_port = 7;

            if (strcmp(argv[1], "tcp") == 0)
                cfg.test = LOAD_TCP_FLOOD;
            else if (strcmp(argv[1], "route") == 0)
                cfg.test = LOAD_ROUTE_STRESS;
            else if (strcmp(argv[1], "acl") == 0)
                cfg.test = LOAD_ACL_STRESS;
            else if (strcmp(argv[1], "bw") == 0)
                cfg.test = LOAD_BANDWIDTH;
            else {
                printf("Unknown test: %s (use tcp|route|acl|bw)\n", argv[1]);
                return 0;
            }

            load_result_t result;
            load_run(&cfg, &result);
            load_print_result(&result);
        }
    } else if (strcmp(argv[0], "audit") == 0) {
        if (argc >= 2 && strcmp(argv[1], "enable") == 0) {
            audit_enable();
        } else if (argc >= 2 && strcmp(argv[1], "disable") == 0) {
            audit_disable();
        } else {
            printf("Usage: audit <enable|disable>\n");
        }
    } else if (strcmp(argv[0], "dns") == 0) {
        if (argc < 2) {
            printf("Usage: dns <spoof-test|lookup> ...\n");
        } else if (strcmp(argv[1], "spoof-test") == 0) {
            if (argc < 4) {
                printf("Usage: dns spoof-test <domain> <fake-ip>\n");
            } else {
                uint32_t ip = iron_str_to_ip(argv[3]);
                dns_zone_add(argv[2], ip);
                char ip_buf[16];
                printf("DNS POISONED: %s -> %s\n", argv[2],
                       iron_ip_to_str(ip, ip_buf, sizeof(ip_buf)));
            }
        } else if (strcmp(argv[1], "lookup") == 0) {
            if (argc < 3) {
                printf("Usage: dns lookup <domain>\n");
            } else {
                uint32_t ip = dns_zone_lookup(argv[2]);
                char ip_buf[16];
                if (ip)
                    printf("%s -> %s\n", argv[2], iron_ip_to_str(ip, ip_buf, sizeof(ip_buf)));
                else
                    printf("%s -> NOT FOUND\n", argv[2]);
            }
        } else {
            printf("Usage: dns <spoof-test|lookup> ...\n");
        }
    } else if (strcmp(argv[0], "trace") == 0) {
        if (argc < 2) {
            printf("Usage: trace <start|stop|status> ...\n");
        } else if (strcmp(argv[1], "start") == 0) {
            const char *file = (argc >= 3) ? argv[2] : "/tmp/irontrace.pcap";
            int mask = TRACE_ALL;
            if (argc >= 4) {
                mask = 0;
                if (strcmp(argv[3], "l2") == 0) mask = TRACE_L2;
                else if (strcmp(argv[3], "l3") == 0) mask = TRACE_L3;
                else if (strcmp(argv[3], "l4") == 0) mask = TRACE_L4;
                else mask = TRACE_ALL;
            }
            trace_start(file, mask);
        } else if (strcmp(argv[1], "stop") == 0) {
            trace_stop();
        } else if (strcmp(argv[1], "replay") == 0) {
            if (argc < 3) {
                printf("Usage: trace replay <file>\n");
            } else {
                /* Internal replay: read pcap and inject via vnic */
                FILE *fp = fopen(argv[2], "rb");
                if (!fp) { printf("Cannot open: %s\n", argv[2]); }
                else {
                    uint8_t hdr_buf[24];
                    if (fread(hdr_buf, 24, 1, fp) != 1) { printf("Bad pcap header\n"); fclose(fp); }
                    else {
                        uint8_t pkt[65535];
                        uint8_t phdr_buf[16];
                        int count = 0;
                        while (fread(phdr_buf, 16, 1, fp) == 1) {
                            uint32_t incl_len = *(uint32_t *)(phdr_buf + 8);
                            if (incl_len > sizeof(pkt)) break;
                            if (fread(pkt, 1, incl_len, fp) != incl_len) break;
                            vnic_inject(0, pkt, incl_len);
                            count++;
                        }
                        fclose(fp);
                        printf("Replayed %d packets from %s\n", count, argv[2]);
                    }
                }
            }
        } else if (strcmp(argv[1], "status") == 0) {
            trace_status();
        } else {
            printf("Usage: trace <start [file] [l2|l3|l4|all]|stop|status>\n");
        }
    } else if (strcmp(argv[0], "tcp") == 0) {
        if (argc >= 2 && strcmp(argv[1], "flush") == 0) {
            tcp_flush();
            printf("TCP connections flushed.\n");
        } else {
            printf("Usage: tcp flush\n");
        }
    } else if (strcmp(argv[0], "defense") == 0) {
        if (argc < 2) {
            printf("Usage: defense <name> <enable|disable> | defense rate-limit <N>/s | defense show\n");
        } else if (strcmp(argv[1], "show") == 0) {
            defense_dump();
        } else if (strcmp(argv[1], "rate-limit") == 0 && argc >= 3) {
            int rate = atoi(argv[2]);
            if (rate > 0) {
                rate_limit_set(rate);
                defense_enable("rate-limit");
            } else {
                printf("Invalid rate: %s\n", argv[2]);
            }
        } else if (strncmp(argv[1], "conn-timeout", 12) == 0 && argc >= 3) {
            int secs = atoi(argv[2]);
            if (secs > 0) {
                tcp_set_idle_timeout(secs);
                defense_enable("conn-timeout");
            } else {
                printf("Invalid timeout: %s\n", argv[2]);
            }
        } else if (argc >= 3) {
            if (strcmp(argv[2], "enable") == 0)
                defense_enable(argv[1]);
            else if (strcmp(argv[2], "disable") == 0)
                defense_disable(argv[1]);
            else
                printf("Usage: defense %s <enable|disable>\n", argv[1]);
        } else {
            printf("Usage: defense <name> <enable|disable>\n");
        }
    } else if (strcmp(argv[0], "exit") == 0 || strcmp(argv[0], "quit") == 0) {
        iron_request_shutdown();
        return -1; /* Signal to stop */
    } else {
        printf("Unknown command: %s (type 'help' for commands)\n", argv[0]);
    }

    return 0;
}

/* --- CLI thread --- */

static void *cli_thread_func(void *arg) {
    (void)arg;
    char line[CLI_MAX_LINE];

    printf("\nironctl> ");
    fflush(stdout);

    while (g_cli_running) {
        if (fgets(line, sizeof(line), stdin) == NULL) break;

        /* Strip newline */
        line[strcspn(line, "\r\n")] = 0;

        if (line[0] == 0) {
            printf("ironctl> ");
            fflush(stdout);
            continue;
        }

        int rc = cli_execute(line);
        if (rc == -1) {
            g_cli_running = false;
            break;
        }

        printf("ironctl> ");
        fflush(stdout);
    }

    return NULL;
}

int cli_start(void) {
    g_cli_running = true;
    if (pthread_create(&g_cli_thread, NULL, cli_thread_func, NULL) != 0) {
        LOG_ERR(MODULE, "Failed to start CLI thread");
        return -1;
    }
    LOG_INF(MODULE, "CLI started (type 'help' for commands)");
    return 0;
}

void cli_stop(void) {
    g_cli_running = false;
    /* Note: thread may be blocked on fgets, will exit on next input or EOF */
}
