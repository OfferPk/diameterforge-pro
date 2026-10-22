/**
 * DiameterForge Pro - 10-Point Zero-Trust Diameter & DEA Security Auditor
 * Standards & Guidelines:
 * - GSMA FS.19: Diameter Interconnect Security
 * - GSMA FS.07: Diameter Roaming Security Guidelines
 * - 3GPP TS 33.210: 3G Security - Network Domain Security (NDS/IP)
 * - RFC 6733: Diameter Base Protocol
 * - RFC 7683: Diameter Overload Indication Conveyance (DOIC)
 */

(function (root, factory) {
  if (typeof define === 'function' && define.amd) {
    define([], factory);
  } else if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.DiameterSecurityAuditor = factory();
  }
}(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  /**
   * Run 10-Point Zero-Trust Audit on Diameter Signaling Architecture
   * @param {Object} cfg - Configuration parameters
   * @returns {Object} Score, Grade, and Detailed Findings
   */
  function auditDiameterSecurity(cfg) {
    const findings = [];
    let totalScore = 0;

    // 1. DEA Topology Hiding (GSMA FS.19) (12 pts)
    const topologyHiding = !!cfg.topologyHidingEnabled;
    let topoScore = 0;
    let topoStatus = 'FAIL';
    let topoDesc = '';

    if (topologyHiding) {
      topoScore = 12;
      topoStatus = 'PASS';
      topoDesc = 'GSMA FS.19 DEA Topology Hiding enforced. Internal Origin-Host names, server IP addresses, and routing loops are masked before egressing to external IPX peers.';
    } else {
      topoScore = 0;
      topoStatus = 'CRITICAL';
      topoDesc = 'CRITICAL VULNERABILITY: Internal topology exposed! External IPX peers can map internal MME, HSS, and OCS nodes to launch targeted signaling denial-of-service.';
    }
    findings.push({
      id: 'TOPOLOGY_HIDING',
      name: 'DEA Topology Hiding & Node Identity Masking (GSMA FS.19)',
      score: topoScore,
      maxScore: 12,
      status: topoStatus,
      description: topoDesc,
      remediation: topoScore < 12 ? 'Enable topology hiding on the Diameter Edge Agent (DEA) to replace Origin-Host with generic edge aliases.' : null
    });
    totalScore += topoScore;

    // 2. Mutual TLS (mTLS) or IPsec ESP Encryption (12 pts)
    const encryptionActive = !!cfg.encryptionEnabled;
    let encScore = 0;
    let encStatus = 'FAIL';
    let encDesc = '';

    if (encryptionActive) {
      encScore = 12;
      encStatus = 'PASS';
      encDesc = 'Mutual TLS (mTLS) / IPsec ESP encryption active on SCTP/TCP port 3868. Ensures data confidentiality, cryptographic integrity, and anti-replay protection across IPX.';
    } else {
      encScore = 0;
      encStatus = 'CRITICAL';
      encDesc = 'CRITICAL DEFECT: Plaintext Diameter signaling across interconnect! Mobile subscriber IMSIs, location coordinates, and billing records are vulnerable to interception.';
    }
    findings.push({
      id: 'INTERCONNECT_ENCRYPTION',
      name: 'mTLS / IPsec Cryptographic Interconnect Protection (3GPP TS 33.210)',
      score: encScore,
      maxScore: 12,
      status: encStatus,
      description: encDesc,
      remediation: encScore < 12 ? 'Enforce TLS with mutual certificate authentication or IPsec ESP on all external Diameter SCTP associations.' : null
    });
    totalScore += encScore;

    // 3. Application-ID & Command-Code Ingress Screening (10 pts)
    const commandScreening = !!cfg.commandScreeningEnabled;
    let cmdScore = 0;
    let cmdStatus = 'PASS';
    let cmdDesc = '';

    if (commandScreening) {
      cmdScore = 10;
      cmdStatus = 'PASS';
      cmdDesc = 'Category 1 & 2 Diameter message filtering active per GSMA FS.19. Drops unauthorized commands (e.g. S6a Cancel-Location or Purge-UE) from non-authoritative partner realms.';
    } else {
      cmdScore = 0;
      cmdStatus = 'CRITICAL';
      cmdDesc = 'CRITICAL HAZARD: Unfiltered Command Codes! Rogue roaming operators can send Cancel-Location requests to kick legitimate subscribers off the cellular network.';
    }
    findings.push({
      id: 'COMMAND_CODE_SCREENING',
      name: 'Application-ID & Command-Code Ingress Screening (GSMA FS.19)',
      score: cmdScore,
      maxScore: 10,
      status: cmdStatus,
      description: cmdDesc,
      remediation: cmdScore < 10 ? 'Configure ingress access control lists on the DEA to permit only negotiated Application-IDs and command codes.' : null
    });
    totalScore += cmdScore;

    // 4. Origin-Realm & Origin-Host Spoofing Defense (10 pts)
    const realmValidation = !!cfg.realmValidationEnabled;
    let realmScore = 0;
    let realmStatus = 'PASS';
    let realmDesc = '';

    if (realmValidation) {
      realmScore = 10;
      realmStatus = 'PASS';
      realmDesc = 'Origin-Realm cross-verification enforced. DEA strictly verifies that Origin-Realm matches the authenticated SCTP association and trusted IPX certificate.';
    } else {
      realmScore = 2;
      realmStatus = 'WARN';
      realmDesc = 'Unverified Origin-Realm. An attacker connected to an IPX network can forge messages claiming to originate from foreign trusted carriers.';
    }
    findings.push({
      id: 'ORIGIN_REALM_VALIDATION',
      name: 'Origin-Realm Cross-Verification & Peer Identity Binding',
      score: realmScore,
      maxScore: 10,
      status: realmStatus,
      description: realmDesc,
      remediation: realmScore < 10 ? 'Bind ingress SCTP associations to authorized Origin-Realm white-lists.' : null
    });
    totalScore += realmScore;

    // 5. AVP Screening & Sensitive Attribute Stripping (10 pts)
    const avpScreening = !!cfg.avpScreeningEnabled;
    let avpScore = 0;
    let avpStatus = 'PASS';
    let avpDesc = '';

    if (avpScreening) {
      avpScore = 10;
      avpStatus = 'PASS';
      avpDesc = 'AVP screening active. Proprietary internal vendor AVPs are stripped, and sensitive subscriber authentication vectors are filtered from untrusted roaming partners.';
    } else {
      avpScore = 3;
      avpStatus = 'WARN';
      avpDesc = 'Unrestricted AVP transmission. Proprietary internal system parameters and sensitive location metadata leak to external peers.';
    }
    findings.push({
      id: 'AVP_SCREENING',
      name: 'AVP Screening & Subscriber Credential Stripping',
      score: avpScore,
      maxScore: 10,
      status: avpStatus,
      description: avpDesc,
      remediation: avpScore < 10 ? 'Implement AVP firewall rules on the DEA to strip unauthorized vendor attributes.' : null
    });
    totalScore += avpScore;

    // 6. Watchdog Heartbeat Tuning & SCTP Multi-Homing (10 pts)
    const sctpMultiHomed = !!cfg.sctpMultiHomed;
    const watchdogSec = parseInt(cfg.watchdogTimerSec, 10) || 30;
    let sctpScore = 0;
    let sctpStatus = 'PASS';
    let sctpDesc = '';

    if (sctpMultiHomed && watchdogSec <= 30) {
      sctpScore = 10;
      sctpStatus = 'PASS';
      sctpDesc = `SCTP Multi-Homing active with optimized ${watchdogSec}s DWR/DWA watchdog timer. Delivers sub-second path failover without dropping in-flight charging requests.`;
    } else if (sctpMultiHomed) {
      sctpScore = 7;
      sctpStatus = 'WARN';
      sctpDesc = `SCTP multi-homed, but watchdog timer (${watchdogSec}s) is sluggish. Dead peer detection may take over 60 seconds.`;
    } else {
      sctpScore = 3;
      sctpStatus = 'FAIL';
      sctpDesc = 'Single-homed transport! Physical link failure immediately severs Diameter signaling, triggering widespread billing and authentication failures.';
    }
    findings.push({
      id: 'SCTP_MULTI_HOMING',
      name: 'SCTP Multi-Homing & Watchdog Heartbeat Tuning (RFC 3539)',
      score: sctpScore,
      maxScore: 10,
      status: sctpStatus,
      description: sctpDesc,
      remediation: sctpScore < 8 ? 'Configure dual-path SCTP multi-homing and tune DWR watchdog timer to 30 seconds or less.' : null
    });
    totalScore += sctpScore;

    // 7. Control Plane Policing (CoPP) for SCTP/TCP Port 3868 (10 pts)
    const coppActive = !!cfg.coppEnabled;
    let coppScore = 0;
    let coppStatus = 'PASS';
    let coppDesc = '';

    if (coppActive) {
      coppScore = 10;
      coppStatus = 'PASS';
      coppDesc = 'Control Plane Policing (CoPP) hardware rate-limits port 3868. Shields DRA and signaling routers against volumetric TCP/SCTP SYN floods.';
    } else {
      coppScore = 0;
      coppStatus = 'FAIL';
      coppDesc = 'FAIL: No CoPP protection for port 3868! Volumetric traffic floods can overwhelm routing engine CPU and disrupt core cellular operations.';
    }
    findings.push({
      id: 'COPP_PORT_3868',
      name: 'Control Plane Policing (CoPP) for Port 3868',
      score: coppScore,
      maxScore: 10,
      status: coppStatus,
      description: coppDesc,
      remediation: coppScore < 10 ? 'Add hardware rate-limiting policer for SCTP and TCP port 3868 in edge router CoPP.' : null
    });
    totalScore += coppScore;

    // 8. Hop-by-Hop & End-to-End ID State Management (9 pts)
    const stateIsolation = !!cfg.idStateIsolationEnabled;
    let idScore = 0;
    let idStatus = 'PASS';
    let idDesc = '';

    if (stateIsolation) {
      idScore = 9;
      idStatus = 'PASS';
      idDesc = 'Isolated 32-bit Hop-by-Hop and End-to-End transaction state management. Prevents ID collisions under high TPS (Transactions Per Second).';
    } else {
      idScore = 4;
      idStatus = 'WARN';
      idDesc = 'Shared or predictable transaction ID generation. Under busy hour peak signaling, ID collision causes transaction dropouts.';
    }
    findings.push({
      id: 'TRANSACTION_ID_HYGIENE',
      name: 'Hop-by-Hop & End-to-End ID Collision Avoidance',
      score: idScore,
      maxScore: 9,
      status: idStatus,
      description: idDesc,
      remediation: idScore < 9 ? 'Configure dedicated transaction ID hashing pools across DRA processing worker threads.' : null
    });
    totalScore += idScore;

    // 9. Mandatory AVP (M-bit) Handling (9 pts)
    const mBitCompliance = !!cfg.mBitComplianceEnabled;
    let mScore = 0;
    let mStatus = 'PASS';
    let mDesc = '';

    if (mBitCompliance) {
      mScore = 9;
      mStatus = 'PASS';
      mDesc = 'RFC 6733 M-bit compliance verified. Proprietary optional AVPs leave M=0; unsupported mandatory AVPs safely trigger 5001 error answers without crashing peers.';
    } else {
      mScore = 3;
      mStatus = 'WARN';
      mDesc = 'Proprietary AVPs erroneously transmit with M=1. Causes widespread DIAMETER_AVP_UNSUPPORTED (5001) rejections across multi-vendor peers.';
    }
    findings.push({
      id: 'MBIT_COMPLIANCE',
      name: 'Mandatory AVP (M-bit) Strict Protocol Compliance (RFC 6733)',
      score: mScore,
      maxScore: 9,
      status: mStatus,
      description: mDesc,
      remediation: mScore < 9 ? 'Ensure proprietary vendor extension AVPs have M=0 (Optional) flag configured.' : null
    });
    totalScore += mScore;

    // 10. Diameter Overload Control (RFC 7683 DOIC) (8 pts)
    const doicActive = !!cfg.doicEnabled;
    let doicScore = 0;
    let doicStatus = 'PASS';
    let doicDesc = '';

    if (doicActive) {
      doicScore = 8;
      doicStatus = 'PASS';
      doicDesc = 'RFC 7683 DOIC (Diameter Overload Indication Conveyance) active. Gracefully sheds load during signaling storms, preventing catastrophic server cascading crashes.';
    } else {
      doicScore = 2;
      doicStatus = 'WARN';
      doicDesc = 'DOIC disabled. When downstream HSS or OCS reaches 100% capacity, traffic queues build up, causing mass connection timeouts.';
    }
    findings.push({
      id: 'DOIC_OVERLOAD_CONTROL',
      name: 'Diameter Overload Indication Conveyance (DOIC RFC 7683)',
      score: doicScore,
      maxScore: 8,
      status: doicStatus,
      description: doicDesc,
      remediation: doicScore < 8 ? 'Enable DOIC extension on DRA and backend application servers to throttle peer transaction volume.' : null
    });
    totalScore += doicScore;

    // Overall Grade
    let grade = 'F';
    if (totalScore >= 95) grade = 'A+';
    else if (totalScore >= 90) grade = 'A';
    else if (totalScore >= 80) grade = 'B';
    else if (totalScore >= 70) grade = 'C';
    else if (totalScore >= 60) grade = 'D';

    return {
      totalScore,
      maxScore: 100,
      percentage: totalScore,
      grade,
      passed: totalScore >= 80,
      summary: `Diameter & DEA Signaling Security Rating: Grade ${grade} (${totalScore}/100 points). ${totalScore >= 80 ? 'Production Ready.' : 'Remediation Required.'}`,
      findings
    };
  }

  return {
    auditDiameterSecurity
  };
}));
