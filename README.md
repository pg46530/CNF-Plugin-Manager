[![Review Assignment Due Date](https://classroom.github.com/assets/deadline-readme-button-22041afd0340ce965d47ae6ef1cefeee28c7c493a6346c4f15d667ab976d596c.svg)](https://classroom.github.com/a/vMITKq_f)
# Lab 5: Containerised Network Functions (cNFs)

## 1. Network Topology

```
h1 \              / h4
h2 - d1 - d2 - d3 - h5
h3 /              \ h6
```

| Device | Role | Program | gRPC | Thrift |
|--------|------|---------|------|--------|
| d1 | L2 switch — LAN1 10.0.1.x | l2switch.p4 | :50051 | :9090 |
| d2 | L3 router + firewall + cNF hub | d2_fwd_firewall.p4 | :50052 | :9091 |
| d3 | L2 switch — LAN2 10.0.2.x | l2switch.p4 | :50053 | :9092 |

| Host | IP | MAC |
|------|----|-----|
| h1 | 10.0.1.1/24 | aa:00:00:00:01:01 |
| h2 | 10.0.1.2/24 | aa:00:00:00:01:02 |
| h3 | 10.0.1.3/24 | aa:00:00:00:01:03 |
| h4 | DHCP (10.0.2.x) | aa:00:00:00:02:04 |
| h5 | DHCP (10.0.2.x) | aa:00:00:00:02:05 |
| h6 | DHCP (10.0.2.x) | aa:00:00:00:02:06 |

d2 is the central node. In addition to its two LAN ports it has two cNF ports:

| d2 port | Connected to |
|---------|-------------|
| 1 | d1 (LAN1) |
| 2 | d3 (LAN2) |
| 3 | ARP proxy container |
| 4 | DHCP server container |

---

## 2. Concept: Containerised Network Functions

A **cNF** (Containerised Network Function) is a Docker container that handles a specific
network service — ARP, DHCP, DNS, etc. — attached directly to a switch port.

In traditional networks these services run on dedicated appliances or on the hosts themselves.
Here they run as containers connected to the P4 switch via a **veth pair**:

```
P4 switch (d2)                      container
  port 4 ── veth-dhcp0 ── veth-dhcp1 ── dhcp_server.py
```

A veth pair is a virtual Ethernet cable: packets sent into one end come out the other.
`run_sim.sh` creates the pair, plugs one end into d2 as a numbered port, and moves the other
end into the container's network namespace. From the container's perspective it has a normal
network interface; from d2's perspective the container is just another port.

The P4 pipeline on d2 decides which traffic goes to which cNF. ARP and DHCP packets bypass
the firewall entirely — they are redirected to the appropriate cNF port before the bloom
filter is ever consulted.

---

## 3. Given: ARP Proxy

The ARP proxy is a fully implemented cNF connected to d2 port 3. You do not need to modify
it.

**What it does:**

When h1 wants to reach h4, it looks up its routing table and sees that 10.0.2.4 is not on
its local subnet — it must go via the default gateway (10.0.1.254). h1 then ARPs: *"who has
10.0.1.254?"* ARP requests never cross a router; the ARP proxy intercepts this request and
replies with a MAC address. h1 populates its ARP cache with the gateway entry and sends frames
to d2, which routes them on to h4. The same happens in reverse when h4 ARPs for its own
gateway (10.0.2.254).

Without the ARP proxy, d2 would need a /32 forwarding entry per host to know which MAC to use
for each destination. The ARP proxy eliminates that limitation — d2 can use /24 routes and let
ARP resolution handle the rest.

---

## 4. How to Run

```bash
bash run_sim.sh
```

> `run_sim.sh` does **not** require `sudo`. Individual commands that need root (Mininet, veth
> setup) already carry `sudo` internally. You will be prompted for your password — enter it
> promptly, Mininet only waits ~10 seconds for the containers to come up.

Four terminals will open:

| Terminal | What it shows |
|----------|--------------|
| Mininet | switch logs and the Mininet CLI |
| ARP Proxy | ARP proxy container logs |
| DHCP Server | DHCP server container logs |
| Controller | P4Runtime controller logs |

Wait until the Mininet terminal prints `Ready !` before running any tests.

> **⚠ Always exit by typing `exit` in the Mininet terminal.**
> This triggers the cleanup sequence — containers are stopped, veth pairs are removed, and
> Mininet tears down the virtual network cleanly. If you close the terminal window directly
> or kill the process, the VM's network configuration may be left in a broken state.
> If that happens, a VM reboot will restore everything.

---

## 5. Phase 1 — Test the ARP Proxy (given code, static IPs)

In this phase h4/h5/h6 have static IPs. The DHCP server container is running but does nothing
yet. The goal is to verify that the ARP proxy is working before tackling the homework.

**Open terminals on h1 and h4:**

```
mininet> xterm h1 h4
```

**Check the ARP tables — they should be empty:**

```bash
# on both h1 and h4
arp -n
```

**Run an iperf test — h1 (LAN1) to h4 (LAN2):**

On h4:
```bash
iperf -s
```
On h1:
```bash
iperf -c 10.0.2.4
```

**Check the ARP tables again:**

```bash
arp -n
```

You should now see the gateway IP (10.0.1.254 on h1, 10.0.2.254 on h4) resolved to a MAC
in each host's ARP table. These entries were populated by the ARP proxy — neither host ever
sent an ARP request that crossed the LAN boundary.

---

## 6. Homework: DHCP Server

Your task is to implement a DHCP server so that h4, h5, and h6 obtain their IP addresses,
default gateway, and DNS server dynamically instead of using static configuration.

You need to modify **four files**:

---

### 6.1 `p4/d2_fwd_firewall.p4` — DHCP parsing and forwarding

The P4 pipeline must be able to identify DHCP packets and redirect them to the DHCP server
cNF (port 4). Look for the `TODO` markers in:

- The constants section — add the cNF port and DHCP port numbers
- `struct headers` — add the two new header types
- The parser — add the states needed to parse DHCP
- The `apply` block — add the DHCP forwarding logic
- The deparser — re-emit the new headers

**Parser cursor alignment**

`transport_t` is a deliberate shortcut: it extracts only the first 4 bytes of any TCP/UDP
header (srcPort + dstPort), and it works for both protocols because ports sit at the same bit
offset in both. This is fine for the firewall, which only needs the ports.

For DHCP you need to go deeper — all the way to the BOOTP/DHCP payload. But after extracting
`transport_t`, the parser cursor is still 4 bytes into the UDP header. The remaining 4 bytes
(length + checksum) are sitting in the packet buffer, unread. If you skip them and extract the
DHCP payload directly, the offsets will be wrong.

The solution is `udp_tail_t`: extract those 4 bytes into a named header so the deparser can
re-emit them and keep the packet well-formed.

**Reaching the application layer**

Parsing the full `dhcp_t` header (236 bytes) is not strictly necessary — you could detect
DHCP using port numbers alone. We parse it anyway to demonstrate that P4 can reach the
application layer and read protocol fields directly in the data plane. In this case the useful
field is `op`: 1 means client→server, 2 means server→client.

---

### 6.2 `cNF/dhcp_server/dhcp_server.yaml` — network configuration

Fill in the `???` fields. The subnet is already given. Look at the network topology to
determine the correct values for `server_ip`, `gateway`, and `dns`. Add static reservations
for any hosts that should always receive the same IP.

---

### 6.3 `cNF/dhcp_server/dhcp_server.py` — the DHCP server

Implement the three TODO functions:

- `build_pool(config)` — build the full IP pool from the subnet; mark network address,
  broadcast, server IP, and gateway as reserved; apply static reservations from the YAML
- `get_next_ip(pool, offered_pool)` — return the first available IP
- `handle_dhcp(...)` — handle Discover and Request messages

Read the protocol notes at the top of the file before starting. Pay attention to the common
pitfalls — the race condition and the INIT-REBOOT state in particular.

---

### 6.4 `mininet/my_topo.py` — switch to dynamic IP assignment

Two comment/uncomment tasks, both marked with `TODO`:

1. In the host creation section: comment out the three lines with static IPs for h4/h5/h6
   and uncomment the three lines without `ip=`.

2. In the host configuration section: comment out the six static route lines for h4/h5/h6
   and uncomment the `dhclient` loop.

---

## 7. Phase 2 — Test DHCP and ARP Proxy Together

After implementing all four files, restart the simulation:

```bash
bash run_sim.sh
```

**Verify DHCP assignment:**

In the Mininet terminal:
```
mininet> h4 ip addr show eth0
mininet> h5 ip addr show eth0
mininet> h6 ip addr show eth0
```

Each host should show a 10.0.2.x address assigned by DHCP.

Watch the DHCP server terminal — it logs every Offer and Ack.

**Test cross-LAN connectivity (same as Phase 1):**

```
mininet> xterm h1 h4
```

On h4:
```bash
iperf -s
```
On h1:
```bash
iperf -c <h4-ip>
```

Check `arp -n` on both hosts before and after — ARP proxy still resolves the remote MACs.

**Repeat with UDP:**

```bash
iperf -s -u
iperf -c <h4-ip> -u
```

