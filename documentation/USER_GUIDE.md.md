# DiameterForge Pro v1.0.0 — User Guide & NetDevOps Manual

## 1\. Web Studio Quickstart

1. Open `source-code/index.html` in any modern web browser.  
2. Select an industry preset from the top bar:  
   - **Carrier Roaming DEA**: GSMA FS.19 compliant Diameter Edge Agent with topology hiding, mTLS encryption, command code screening, SCTP multi-homing, and CoPP (Grade A+).  
   - **Private Core IMS & OCS**: Enterprise private 5G / VoLTE core with 3GPP Gx policy control, FreeDiameter daemon, SCTP multi-homing, and 30s watchdog timer (Grade A).  
   - **Vulnerable IPX Interconnect**: Unencrypted Diameter, exposed internal MME/HSS identities, unfiltered S6a command codes, and single-homed SCTP transport (Grade F).  
3. Review the **Signaling & Transaction Metrics**:  
   - Verify SCTP path redundancy, watchdog timer \$T\_w\$, topology hiding status, and interconnect encryption state.  
4. Review the **10-Point Zero-Trust Diameter Security Scorecard**:  
   - Check compliance against GSMA FS.19 / FS.07 roaming guidelines and inspect automated remediation commands.  
5. Review the **RFC 6733 Binary Message Dissector**:  
   - Inspect the 196-byte Credit-Control-Request (`CCR`) message with decoded 20-byte base header, AVP 263 Session-Id, AVP 264 Origin-Host, AVP 416 CC-Request-Type, and 4-byte padding alignment.  
6. Export synthesized production configurations for **FreeDiameter**, **Open5GS hss.yaml**, **Cisco cDRA**, **Juniper Junos**, and **Prometheus**.

---

## 2\. DevSecOps CLI Tool (`diameterforge-cli.py`)

The standalone Python CLI runs on Python 3.8+ with zero external dependencies.

### 2.1 Encoding RFC 6733 Diameter Messages

\# Encode Credit-Control-Request (CCR, Command Code 272\)

python3 build/diameterforge-cli.py encode \\

  \--cmd 272 \\

  \--app-id 4 \\

  \--origin-host dra01.carrier.net \\

  \--origin-realm carrier.net \\

  \--dest-realm ocs.carrier.net \\

  \--imsi 310410123456789

Output:

\=== RFC 6733 Diameter Message Encoded (Command Code: 272\) \===

Total Bytes: 196 (Includes 20B Header \+ Padded AVPs)

Raw Hex:     010000c4c0000110000000041a2b3c4d5e6f7081000001074000002c64726130312e636172726965722e6e65743b313732383339323138323b31303435323b31000001084000001964726130312e636172726965722e6e65740000000000012840000013636172726965722e6e6574000000011b400000176f63732e636172726965722e6e657400000001024000000c00000004000001a04000000c000000010000019f4000000c00000000000000014000001733313034313031323334353637383900

Hex Dump:

0000   01 00 00 c4 c0 00 01 10 00 00 00 04 1a 2b 3c 4d    |.............+\<M|

0010   5e 6f 70 81 00 00 01 07 40 00 00 2c 64 72 61 30    |^op.....@..,dra0|

0020   31 2e 63 61 72 72 69 65 72 2e 6e 65 74 3b 31 37    |1.carrier.net;17|

0030   32 38 33 39 32 31 38 32 3b 31 30 34 35 32 3b 31    |28392182;10452;1|

...

### 2.2 Running Zero-Trust CI/CD Audits

\# Validating production DEA configuration (Exits code 0\)

python3 build/diameterforge-cli.py audit \-c build/presets/carrier-roaming-dea.json \--strict

\# Validating vulnerable IPX configuration (Exits code 1\)

python3 build/diameterforge-cli.py audit \-c build/presets/vulnerable-ipx-interconnect.json \--strict

---

## 3\. GitHub Actions CI/CD Pipeline Gate

Add this workflow to your Telecom Signaling repository (`.github/workflows/diameter-audit.yml`):

name: Zero-Trust Diameter Signaling & DEA Gate

on:

  pull\_request:

    paths:

      \- 'diameter/\*\*'

      \- 'configs/dra/\*\*'

jobs:

  diameter-audit:

    runs-on: ubuntu-latest

    steps:

      \- name: Checkout Code

        uses: actions/checkout@v4

      \- name: Set up Python

        uses: actions/setup-python@v5

        with:

          python-version: '3.11'

      \- name: Run DiameterForge Strict Audit Gate

        run: |

          python3 build/diameterforge-cli.py audit \-c build/presets/carrier-roaming-dea.json \--strict