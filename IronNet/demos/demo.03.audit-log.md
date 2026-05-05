# Demo 03: Audit Log (ironmon) — Security Event Logging

## Prerequisites

- WSL 2 with Ubuntu
- IronNet built: `cd IronNet/build && cmake ../src -DCMAKE_BUILD_TYPE=Debug && make`
- Two terminal windows

## Terminal 1: Start the router

```bash
cd IronNet/build
sudo ./ironstack/ironstack ../src/configs/router.conf
```

## Terminal 2: Generate security events

```bash
sudo ip addr add 10.0.1.2/24 dev iron0
sudo ip link set iron0 up

# Trigger ACL deny events (port 22 is denied by config)
for i in 1 2 3; do nc -zv 10.0.1.1 22; done
```

## Terminal 1: View audit log

```
ironctl> show audit-log
--- Audit Log (last 3 events) ---
  [17045] ACL_DENY   10.0.1.2:54321 -> 10.0.1.1:22 proto=6 rule 3
  [17046] ACL_DENY   10.0.1.2:54322 -> 10.0.1.1:22 proto=6 rule 3
  [17047] ACL_DENY   10.0.1.2:54323 -> 10.0.1.1:22 proto=6 rule 3
```

### JSON export

```
ironctl> show audit-log json
[
  {"ts":17045,"type":"ACL_DENY","src":"10.0.1.2","dst":"10.0.1.1","proto":6,"sport":54321,"dport":22,"detail":"rule 3"},
  {"ts":17046,"type":"ACL_DENY","src":"10.0.1.2","dst":"10.0.1.1","proto":6,"sport":54322,"dport":22,"detail":"rule 3"}
]

ironctl> show stats json
{
  "l2.rx_frames": 47,
  "l3.rx_packets": 35,
  "l3.drops.acl": 3
}
```

### Toggle audit logging

```
ironctl> audit disable
ironctl> audit enable
```

## Audit log file

Events are also written to `/tmp/ironnet_audit.log`:
```bash
cat /tmp/ironnet_audit.log
```

Format: `timestamp|event_type|src_ip|dst_ip|proto|sport|dport|detail`
