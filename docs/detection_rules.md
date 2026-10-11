# NetScope Explainable Anomaly Detection Rules Specification

## 1. Overview & Detection Philosophy

NetScope operates on **transparent, explainable heuristics** rather than opaque machine-learning classifiers. Every alert produced must be:
- **Auditable**: Traced to specific observed packet indices, timestamps, and addresses.
- **Configurable**: Thresholds and timing windows can be altered via JSON configuration without touching source code.
- **Honest & Defensive**: Communicated as an indicator requiring investigation rather than a definitive assertion of hostility.

---

## 2. Detection Rule Specifications

### Rule 1: High Packet Rate Observation (`RULE_HIGH_PACKET_RATE`)

- **Purpose**: Detects endpoints sending bursts of traffic that exceed baseline packet rates.
- **Formula / Logic**:
  Let $T_e = [t_1, t_2, \dots, t_k]$ be the sorted timestamps of packets transmitted by source endpoint $e$.
  A sliding window of width $W = \text{window\_sec}$ counts packets in $[t_{\text{left}}, t_{\text{right}}]$ such that $t_{\text{right}} - t_{\text{left}} \le W$.
  An alert triggers if:
  $$\max (\text{count}(W)) > \text{threshold}$$
- **Default Configuration**:
  - `high_packet_rate_threshold`: `50` packets
  - `high_packet_rate_window_sec`: `1.0` second
  - `high_packet_rate_policy`: `"source"`
- **Severity**: `HIGH` if observed $\ge 2 \times \text{threshold}$, else `MEDIUM`.
- **Benign False Positives**: High-throughput file downloads, local database replication, media streaming buffers.

---

### Rule 2: Destination Port Diversity (`RULE_PORT_DIVERSITY`)

- **Purpose**: Heuristic identification of vertical or horizontal port scanning and service discovery.
- **Formula / Logic**:
  For source endpoint $s$, let $E_s = \{(t_i, p_i)\}$ represent observed destination ports $p_i$ at timestamps $t_i$.
  Within sliding window $W$, determine the cardinality of unique destination ports contacted:
  $$U_s(W) = |\{p_i \mid t_{\text{start}} \le t_i \le t_{\text{start}} + W\}|$$
  An alert triggers if:
  $$\max(U_s(W)) > \text{threshold}$$
- **Default Configuration**:
  - `port_diversity_threshold`: `15` distinct ports
  - `port_diversity_window_sec`: `10.0` seconds
- **Severity**: `HIGH` if distinct ports $\ge 2 \times \text{threshold}$, else `MEDIUM`.
- **Benign False Positives**: Web browsers opening multi-origin connections, peer-to-peer torrent clients, service discovery protocols (UPnP, mDNS).

---

### Rule 3: High TCP SYN Ratio Without ACK (`RULE_SYN_WITHOUT_ACK`)

- **Purpose**: Identifies endpoints attempting connections without completing handshakes (SYN flood probes, stealth scanning).
- **Formula / Logic**:
  For source endpoint $s$, count total TCP packets $N_{\text{TCP}}$ and packets with the SYN flag set while ACK is clear:
  $$R_{\text{SYN}} = \frac{N_{\text{SYN\_NO\_ACK}}}{N_{\text{TCP}}}$$
  An alert triggers if:
  $$N_{\text{TCP}} \ge \text{syn\_min\_packets} \quad \text{and} \quad R_{\text{SYN}} \ge \text{syn\_ratio\_threshold}$$
- **Default Configuration**:
  - `syn_ratio_threshold`: `0.75` (75.0%)
  - `syn_min_packets`: `10` packets
- **Severity**: `HIGH` if ratio $\ge 0.90$, else `MEDIUM`.
- **Benign False Positives**: Asymmetric routing (return ACK packets travel over a different network interface not captured in this file), network congestion causing packet drop, connection attempts to an offline local printer.

---

### Rule 4: Traffic Volume Statistical Deviation (`RULE_VOLUME_DEVIATION`)

- **Purpose**: Flags discrete capture intervals whose byte volume deviates significantly from the capture's baseline mean.
- **Formula / Logic**:
  Divide the capture into $M$ time buckets of width $\Delta t$. Let $b_i$ be the byte count of bucket $i$.
  If $M \ge \text{min\_intervals}$ and sample standard deviation $\sigma > 0$:
  $$\mu = \frac{1}{M}\sum_{i=1}^M b_i, \quad \sigma = \sqrt{\frac{1}{M - 1}\sum_{i=1}^M (b_i - \mu)^2}$$
  Compute standard score ($Z$-score) for interval $i$:
  $$Z_i = \frac{b_i - \mu}{\sigma}$$
  An alert triggers if:
  $$Z_i > \text{volume\_deviation\_zscore}$$
- **Default Configuration**:
  - `volume_deviation_zscore`: `+2.5`
  - `volume_deviation_min_intervals`: `4` intervals
  - `volume_deviation_interval_sec`: `2.0` seconds
- **Severity**: `HIGH` if $Z \ge 4.0$, else `MEDIUM`.
- **Benign False Positives**: Scheduled backup initiation, video streaming keyframe load, software updates.

---

### Rule 5: Endpoint Traffic Concentration (`RULE_TRAFFIC_CONCENTRATION`)

- **Purpose**: Identifies network topologies where one endpoint accounts for a disproportionate majority of all capture activity.
- **Formula / Logic**:
  Let $N_{\text{total}}$ be the total packets in the capture. For each endpoint $e$ with packet volume $N_e$:
  $$C_e = \frac{N_e}{N_{\text{total}}}$$
  An alert triggers if:
  $$N_{\text{total}} \ge \text{min\_packets} \quad \text{and} \quad C_e \ge \text{threshold}$$
- **Default Configuration**:
  - `traffic_concentration_threshold`: `0.50` (50.0%)
  - `traffic_concentration_min_packets`: `30` packets
- **Severity**: `MEDIUM` if ratio $\ge 0.80$, else `LOW`.
- **Benign False Positives**: Default gateway routers, DNS forwarders, targeted packet captures focused on a single host.

---

### Rule 6: Repeated Communication Pattern (`RULE_REPEATED_COMMUNICATION`)

- **Purpose**: Identifies rapid repetitive bursts between specific source and destination pairs.
- **Formula / Logic**:
  Group packets by tuple $(src, dst, dst\_port)$. Count occurrences within window $\Delta t$.
  An alert triggers if:
  $$\max(\text{count}) > \text{threshold}$$
- **Default Configuration**:
  - `repeated_comm_threshold`: `25` packets
  - `repeated_comm_window_sec`: `5.0` seconds
- **Severity**: `MEDIUM` if count $\ge 2 \times \text{threshold}$, else `LOW`.
- **Benign False Positives**: Application keep-alives, rapid polling loops, NTP synchronization requests.
