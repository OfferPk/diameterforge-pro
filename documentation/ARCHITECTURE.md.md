# DiameterForge Pro v1.0.0 — Architecture & Engineering Manual

## 1\. Executive Summary: The Backbone of 4G & 5G Telecom Signaling

The **Diameter Base Protocol (RFC 6733\)** is the standard Authentication, Authorization, and Accounting (AAA) protocol deployed across global telecom operators, replacing legacy RADIUS.

In 4G Evolved Packet Core (EPC), 5G Non-Standalone / Standalone Core, and IP Multimedia Subsystem (IMS) networks, Diameter governs all critical control-plane signaling:

1. **3GPP Gx Interface (TS 29.212)**: Connects the Policy and Charging Rules Function (PCRF) to the Packet Data Network Gateway (PGW / SMF) to push Quality of Service (QoS) rules and bandwidth limits per subscriber bearer.  
2. **3GPP Gy / Ro Interface (RFC 4006 / TS 32.299)**: Connects gateways to the Online Charging System (OCS / CHF) for real-time prepaid quota reservation via Credit-Control-Request (`CCR`) and Credit-Control-Answer (`CCA`).  
3. **3GPP S6a / S6d Interface (TS 29.272)**: Connects the Mobility Management Entity (MME) to the Home Subscriber Server (HSS) for subscriber authentication vectors (AIR/AIA) and location updates (ULR/ULA).  
4. **3GPP Cx / Dx Interface (TS 29.228)**: IMS call session control (S-CSCF / I-CSCF to HSS) for Voice over LTE (VoLTE) and Voice over New Radio (VoNR).

\+-------------------------------------------------------------+

| Version (8b) |           Message Length (24b)                |

\+-------------------------------------------------------------+

| Command Flags (R,P,E,T) |      Command Code (24b)           |

\+-------------------------------------------------------------+

|                     Application-ID (32b)                    |

\+-------------------------------------------------------------+

|                  Hop-by-Hop Identifier (32b)                |

\+-------------------------------------------------------------+

|                  End-to-End Identifier (32b)                |

\+-------------------------------------------------------------+

|   AVPs (Attribute-Value Pairs with 4-Byte Boundary Padding) |

\+-------------------------------------------------------------+

---

## 2\. GSMA FS.19 & FS.07 Roaming Security Architecture

When mobile subscribers roam abroad, their signaling traverses inter-operator **IP Exchange (IPX)** networks through **Diameter Edge Agents (DEAs)**.

Because Diameter was originally designed for trusted intra-operator domains, interconnection over IPX introduces severe security vulnerabilities documented in GSMA FS.19:

1. **Topology Exposure**: Diameter messages typically include internal node FQDNs (e.g. `mme01.region1.carrier.net`). Rogue actors use these to map core network topologies and launch targeted DoS attacks against HSS or PCRF clusters.  
   - *Defense*: DEA Topology Hiding replaces internal node names and IP addresses with generic edge aliases.  
2. **Location Tracking & Surveillance**: Attackers send unauthorized S6a `Send-Routing-Info-for-SM` or `Provide-Subscriber-Info` requests to track subscriber GPS coordinates and cell IDs.  
   - *Defense*: Category 1/2 Command-Code screening drops unauthorized location requests.  
3. **Denial of Service via `Cancel-Location`**: A malicious roaming partner can forge S6a `Cancel-Location-Request` (CLR) messages, detaching subscribers from their home network.  
   - *Defense*: Strict Origin-Realm cross-verification against authenticated SCTP/TLS peer certificates.  
4. **Mandatory AVP (M-bit) Rejection (RFC 6733 Section 4.1)**:  
   - If a Diameter agent receives an unrecognized AVP with the \$M\$ (Mandatory) bit set, it **MUST** reject the entire transaction with `DIAMETER_AVP_UNSUPPORTED` (5001).  
   - Misconfigured proprietary vendor AVPs with \$M=1\$ cause mass roaming dropouts across multi-vendor equipment.

---

## 3\. SCTP Transport & Watchdog State Machine (RFC 3539\)

Diameter mandates transport over **Stream Control Transmission Protocol (SCTP)** or TCP on port 3868:

- **SCTP Multi-Homing**: Enables a single Diameter association to span multiple physical IP paths (Primary IP on Path A, Secondary IP on Path B). Physical link cuts trigger hardware path failover in \$\< 1\\text{ second}\$ without terminating in-flight CCR/CCA billing transactions.  
- **Device Watchdog Timer (\$T\_w\$)**: Diameter peers periodically exchange Device-Watchdog-Request (`DWR`, Code 280\) and Answer (`DWA`). If no response is received within \$T\_w\$ (standard 30s), the association transitions to `SUSPECT` and traffic is dynamically rerouted to backup DRA nodes.

---

## 4\. 10-Point Zero-Trust Diameter Audit Rubric

1. **DEA Topology Hiding (12 pts)**: Mask internal FQDNs and IPs at edge boundaries.  
2. **mTLS / IPsec Interconnect Encryption (12 pts)**: Protect against IPX eavesdropping.  
3. **Command-Code Ingress Screening (10 pts)**: Block unauthorized S6a drop calls.  
4. **Origin-Realm Cross-Verification (10 pts)**: Verify peer identity against SCTP certificates.  
5. **AVP Screening & Credential Stripping (10 pts)**: Remove proprietary parameters.  
6. **SCTP Multi-Homing & Watchdog Tuning (10 pts)**: Sub-second path failover (\$T\_w \\le 30\\text{s}\$).  
7. **Control Plane Policing (CoPP) for Port 3868 (10 pts)**: Hardware rate-limiting.  
8. **Transaction ID Collision Avoidance (9 pts)**: Prevent Hop-by-Hop ID collisions.  
9. **Mandatory AVP (M-bit) Compliance (9 pts)**: Avoid 5001 errors on optional AVPs.  
10. **DOIC Overload Control (RFC 7683\) (8 pts)**: Prevent signaling storm server crashes.