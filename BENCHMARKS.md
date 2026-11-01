# WireGuard and OpenVPN through Tor: benchmark

> [Version française](BENCHMARKS.fr.md)

Measured on 2026-11-01 with Katakomba 4.4.3. Three tunnels were compared on the same Tor circuits:

- **IVPN OpenVPN**
- **Mullvad WireGuard**
- **IVPN WireGuard**, the control: compared with IVPN OpenVPN it isolates the protocol, and compared with Mullvad WireGuard it isolates the provider

This is a snapshot from one machine and one internet line, published so you can choose for yourself. Servers, prices and the Tor network all change.

## Summary

- **Speed does not separate them.** Across 32 circuits, all three tunnels are level within the margin of error, in Europe and outside it.
- **Connection cuts do.** When a Tor circuit dies, WireGuard kept every open connection alive (16 of 16). OpenVPN came back too, but lost every open connection (0 of 8).
- **The VPN server matters more than the protocol.** The largest gaps, up to ×12, came from one provider's server on one route, and they hit both tunnels of that provider.

| Ratios are relative to IVPN OpenVPN | IVPN OpenVPN | Mullvad WireGuard | IVPN WireGuard |
|---|---|---|---|
| Download, median ratio | reference | 1.02 [0.93–1.14] | 0.99 [0.92–1.10] |
| Upload, median ratio | reference | 0.93 [0.79–1.06] | 1.22 [0.96–1.30] |
| Web page time, median ratio (lower is faster) | reference | 0.97 [0.90–1.04] | 1.02 [0.98–1.06] |
| Open connections kept through a cut | **0/8** | **7/7** | **9/9** |
| Tunnel back after a cut, median | 3.9 s | 1.2 s | 0.44 s |
| Tunnel up from cold, median | 1.31 s | 0.41 s | 0.61 s |
| First page after mounting, median / p90 | 2.85 / 5.13 s | 2.73 / 4.94 s | 2.38 / 7.95 s |
| Useful cold mounts | 30/30 | 30/30 | 29/30 |
| One hour, successful probes | 164/164 | 170/170 | 168/168 |

Brackets are 95% bootstrap intervals. An interval containing 1 means no measurable gap.

## How to choose

Throughput is not a reason to pick one of these. The differences that matter are elsewhere:

| If you care most about | Consider |
|---|---|
| Long downloads, SSH, calls: connections that must survive a circuit change | WireGuard, with either provider |
| A fallback on the same account if WireGuard stops working | IVPN: Katakomba falls back from WireGuard to OpenVPN |
| A fleet where PCs come and go | Mullvad: Katakomba frees only dead devices (see [Fleets](#fleets)) |
| Field experience | OpenVPN has the longest history here. IVPN WireGuard has very little |

Proton was not part of this benchmark.

## Fleets

Differences in how Katakomba works with each provider. Prices and limits were read on the providers' pages on 2026-11-01; check them before you buy.

| | Mullvad | IVPN |
|---|---|---|
| Transports | WireGuard only | WireGuard and OpenVPN |
| WireGuard wrapping | udp-over-tcp, TCP 443 | VMess disguised as HTTP, TCP 80 |
| Slots per account | 5 | 5 (Standard, Plus), 10 (Pro Suite) |
| Price per account | €5 per month | $6 Standard, $10 Pro Suite per month; $60 and $100 per year |
| Slot recovery on a full account (accounts reserved for Katakomba) | Deletes only devices older than 3 weeks | Cannot list other sessions: as a last resort, resets a whole account, and its PCs register again |
| Weekly key renewal | New device, then the old one is deleted | New key on the same session |

Sources: [Mullvad pricing](https://mullvad.net/en/pricing), [IVPN plan changes, May 2026](https://www.ivpn.net/blog/ivpn-plan-changes-new-plus-tier-increased-device-limits-additional-privacy-services/).

Nothing here was tested at fleet scale. Slot recovery and key renewal were not exercised by this benchmark.

## Method

**Setup.** A dedicated Tor instance used Katakomba's torrc, except for the relay countries and `LongLivedPorts 1194,443,80`. Each tunnel ran in its own network namespace with the same OpenVPN options as the daemon and an MTU of 1320 for WireGuard. OpenVPN negotiated CHACHA20-POLY1305 every time. The target was `speed.cloudflare.com`.

**Blocks.** A block is one frozen Tor circuit (guard, middle and exit pinned with `StrictNodes`) plus one VPN location, served by a server of each provider. Measurements inside a block are not independent, so the block is the statistical unit: 32 valid blocks, each using a single Tor path.

| Region | Tor relays | VPN servers | Blocks |
|---|---|---|---|
| Europe | Europe | Europe | 8 |
| Free Tor, EU VPN | Unconstrained | Europe | 8 |
| North America | Outside Europe | United States, Canada | 9 |
| Asia-Pacific | Outside Europe, exit in the region when available | Japan, Hong Kong, Singapore, Australia | 7 |

**Performance.** In each block, in rotating order: 3 downloads of 15 s, 2 uploads of 12 s, and 2 web page loads (16 objects of 200 KB, 4 connections at a time, TLS for each). Also recorded: Tor alone on the same circuit, latency idle and under load, CPU, UDP and interface drops.

**Cuts.** The Tor circuit was closed with `CLOSECIRCUIT` during a 40 s download, 10 times per tunnel.

**Cold mounts.** 30 per tunnel, each on a new circuit.

**Endurance.** The three tunnels ran side by side for one hour on isolated circuits, with a 100 KB probe every 20 s.

**Statistics.** Each block gives a ratio between two tunnels. Medians and geometric means use the 95% bootstrap on blocks. The reported p-values come from sign-flip permutations.

## Results

### Download by region

| Region | Blocks | Mullvad WG / IVPN OpenVPN, mean (median) | IVPN WG / IVPN OpenVPN, mean (median) |
|---|---|---|---|
| Europe | 8 | 1.00 (1.09) | 1.03 (1.04) |
| Free Tor, EU VPN | 8 | 0.80 (1.01) | 1.01 (1.10) |
| North America | 9 | 1.02 (0.89) | 1.03 (0.92) |
| Asia-Pacific | 7 | 1.85 (1.38) | 1.12 (1.06) |
| **All** | 32 | 1.09 [0.85–1.39], p = 0.53 | 1.05 [0.95–1.16], p = 0.42 |
| **Outside Europe** | 16 | 1.32 [0.99–1.93], median 1.00 | 1.07 [0.92–1.28], median 0.95 |

Provider alone (Mullvad WG / IVPN WG, all blocks): mean 1.04 [0.83–1.30], median 0.99.

### Why the averages mislead

Three blocks drive the regional means. They repeated on every round, so they are not noise:

| Location | IVPN OpenVPN | IVPN WireGuard | Mullvad WireGuard | Tor alone |
|---|---|---|---|---|
| Hong Kong | 119 KB/s | 162 KB/s | 1501 KB/s | 1640 KB/s |
| Tokyo | 286 KB/s | 256 KB/s | 794 KB/s | 3183 KB/s |
| Madrid | 948 KB/s | 779 KB/s | 86 KB/s | 612 KB/s |

Both IVPN tunnels moved together each time, so the cause is the server or its route, not the protocol. Mullvad comes out ahead in the first two and far behind in the third. Without these three blocks, Mullvad WG / IVPN OpenVPN is 1.05 [0.94–1.18].

### Cost

- **CPU:** 2.2% per MB/s for OpenVPN, 3.6% to 3.9% for WireGuard. At these speeds, the median load stays at 1.4% or less.
- **Share of Tor-alone speed kept:** 0.77 for OpenVPN, 0.81 for both WireGuard tunnels.
- **Latency under load:** about 750 ms for all three.
- **UDP and interface drops:** none.

### Cuts

| | Valid cuts | Tunnel back, median (max) | Connections kept |
|---|---|---|---|
| IVPN OpenVPN | 8 of 10 | 3.9 s (6.9 s) | 0/8 |
| Mullvad WireGuard | 7 of 10 | 1.2 s (3.7 s) | 7/7 |
| IVPN WireGuard | 9 of 10 | 0.44 s (2.5 s) | 9/9 |

The WireGuard bridge reopens its connection through Tor without touching the interface, so the address and the connections inside the tunnel stay in place. OpenVPN restarts its session. It most likely gets a new address, but this was not verified.

For scale, the author's machine saw one forced break every 5 to 8 hours in real use. That figure is weak: it covers different periods and versions.

## Limits

- One machine, one line, one target. The results may not carry over to another network.
- Cuts, cold mounts and endurance used European relays only. The protocol explanation should hold elsewhere, but it was not measured.
- Upload mean ratios swing widely on a few blocks, so read the medians.
- One hour of endurance cannot reveal rare failures.
- 8 of the 32 blocks compare two different IVPN servers. On the other 24, IVPN WG / IVPN OpenVPN has a median of 1.05 [mean 1.04, 0.93–1.16].
- Katakomba's default torrc uses `LongLivedPorts 1194,443`, without the port 80 of IVPN WireGuard. The benchmark added it.
- Multi-account behaviour, device limits, Mullvad's key renewal and long-term IVPN WireGuard use were not tested.

### Discarded data

- **Blocks:** 8 first-round blocks failed because every new pinned guard was refused, probably Tor's guard sample filling up. They were the last in a shuffled order, so they do not favour slow circuits. 12 blocks were added with a fresh Tor state, weighted towards regions outside Europe.
- **Cuts:** cuts where no tunnel interruption was seen (4) and Mullvad downloads that had already finished (2) were not counted.
- **Probe failures:** a few connection resets and timeouts appeared on every tunnel. They were left out of that measurement, and most blocks kept at least one valid value per test.
- **Login:** IVPN refused one OpenVPN login during the run, cause unknown. The bench continued on another server and account.

## Data per block

Mean download in KB/s, by block. Tor alone is one measurement taken just before the tunnels, so it can be lower than a tunnel on a circuit whose speed varies.

| Region | Location | Tor alone | IVPN OpenVPN | Mullvad WG | IVPN WG | IVPN servers (OpenVPN / WG) | Mullvad server |
|---|---|---|---|---|---|---|---|
| Europe | AT | 451 | 332 | 477 | 377 | `at1` / `at2` | `at-vie-wg-003` |
| Europe | CH | 266 | 307 | 275 | 285 | `ch3` / `ch2` | `ch-zrh-wg-004` |
| Europe | ES | 77 | 38 | 17 | 33 | `es1` / `es1` | `es-mad-wg-205` |
| Europe | GB | 2622 | 2137 | 2569 | 2482 | `gb1` / `gb1` | `gb-lon-wg-005` |
| Europe | GB | 560 | 179 | 203 | 146 | `gb1` / `gb3` | `gb-lon-wg-006` |
| Europe | NL | 381 | 180 | 246 | 250 | `nl8` / `nl8` | `nl-ams-wg-202` |
| Europe | PL | 120 | 95 | 83 | 90 | `pl1` / `pl1` | `pl-waw-wg-103` |
| Europe | SE | 291 | 408 | 425 | 461 | `se1` / `se1` | `se-sto-wg-209` |
| Free Tor, EU VPN | CH | 3655 | 3747 | 3257 | 4095 | `ch1` / `ch1` | `ch-zrh-wg-503` |
| Free Tor, EU VPN | ES | 720 | 1378 | 1422 | 745 | `es1` / `es1` | `es-mad-wg-205` |
| Free Tor, EU VPN | ES | 612 | 948 | 86 | 779 | `es1` / `es1` | `es-mad-wg-204` |
| Free Tor, EU VPN | FR | 363 | 190 | 368 | 312 | `fr1` / `fr1` | `fr-par-wg-003` |
| Free Tor, EU VPN | GB | 2493 | 2375 | 2400 | 2912 | `gb1` / `gb1` | `gb-lon-wg-001` |
| Free Tor, EU VPN | IT | 468 | 320 | 339 | 375 | `it2` / `it2` | `it-mil-wg-003` |
| Free Tor, EU VPN | NL | 532 | 333 | 315 | 367 | `nl3` / `nl3` | `nl-ams-wg-202` |
| Free Tor, EU VPN | PL | 452 | 449 | 451 | 394 | `pl1` / `pl1` | `pl-waw-wg-102` |
| North America | CA | 659 | 208 | 216 | 196 | `ca-on1` / `ca-on2` | `ca-tor-wg-204` |
| North America | CA | 392 | 510 | 493 | 471 | `ca-on1` / `ca-on1` | `ca-tor-wg-001` |
| North America | CA | 60 | 54 | 42 | 50 | `ca-qc2` / `ca-qc2` | `ca-mtr-wg-306` |
| North America | US | 3258 | 1023 | 2667 | 2696 | `us-ny3` / `us-ny2` | `us-nyc-wg-606` |
| North America | US | 2372 | 1500 | 1295 | 1426 | `us-tx6` / `us-tx4` | `us-dal-wg-707` |
| North America | US | 1498 | 128 | 104 | 103 | `us-il4` / `us-il3` | `us-chi-wg-315` |
| North America | US | 969 | 933 | 743 | 754 | `us-wa2` / `us-wa2` | `us-sea-wg-402` |
| North America | US | 828 | 420 | 373 | 459 | `us-tx6` / `us-tx4` | `us-dal-wg-601` |
| North America | US | 292 | 155 | 176 | 140 | `us-ca5` / `us-ca5` | `us-lax-wg-404` |
| Asia-Pacific | AU | 103 | 100 | 91 | 71 | `au-nsw2` / `au-nsw2` | `au-syd-wg-102` |
| Asia-Pacific | HK | 1640 | 119 | 1501 | 162 | `hk3` / `hk3` | `hk-hkg-wg-201` |
| Asia-Pacific | HK | 127 | 191 | 286 | 421 | `hk2` / `hk2` | `hk-hkg-wg-201` |
| Asia-Pacific | JP | 3183 | 286 | 794 | 256 | `jp2` / `jp2` | `jp-tyo-wg-001` |
| Asia-Pacific | JP | 583 | 337 | 463 | 349 | `jp2` / `jp2` | `jp-tyo-wg-203` |
| Asia-Pacific | JP | 357 | 537 | 519 | 571 | `jp2` / `jp2` | `jp-tyo-wg-201` |
| Asia-Pacific | SG | 305 | 476 | 557 | 514 | `sg1` / `sg1` | `sg-sin-wg-103` |
