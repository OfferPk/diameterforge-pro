/**
 * DiameterForge Pro - Web Application Controller
 */

(function () {
  'use strict';

  // Industry Presets
  const PRESETS = {
    roaming: {
      name: 'Carrier Roaming DEA (Grade A+)',
      commandCode: 272, // CCR
      appId: 4, // DCCA Gy/Ro
      originHost: 'dea01.carrier.net',
      originRealm: 'carrier.net',
      destRealm: 'roaming-ipx.net',
      peerHost: 'peer-dea.roaming-ipx.net',
      peerIp: '198.51.100.25',
      imsi: '310410123456789',
      listenIp1: '192.168.50.10',
      listenIp2: '192.168.60.10',
      watchdogTimerSec: 30,
      sctpMultiHomed: true,
      topologyHidingEnabled: true,
      encryptionEnabled: true,
      commandScreeningEnabled: true,
      realmValidationEnabled: true,
      avpScreeningEnabled: true,
      coppEnabled: true,
      idStateIsolationEnabled: true,
      mBitComplianceEnabled: true,
      doicEnabled: true
    },
    enterprise: {
      name: 'Private Core IMS & OCS (Grade A)',
      commandCode: 272,
      appId: 16777238, // 3GPP Gx
      originHost: 'pcrf01.corp.private5g',
      originRealm: 'corp.private5g',
      destRealm: 'pgw.corp.private5g',
      peerHost: 'pgw01.corp.private5g',
      peerIp: '10.200.1.10',
      imsi: '999700000000001',
      listenIp1: '10.200.1.1',
      listenIp2: '10.200.2.1',
      watchdogTimerSec: 30,
      sctpMultiHomed: true,
      topologyHidingEnabled: false, // Internal network
      encryptionEnabled: true,
      commandScreeningEnabled: true,
      realmValidationEnabled: true,
      avpScreeningEnabled: true,
      coppEnabled: true,
      idStateIsolationEnabled: true,
      mBitComplianceEnabled: true,
      doicEnabled: true
    },
    vulnerable: {
      name: 'Vulnerable IPX Interconnect (Grade F)',
      commandCode: 316, // ULR
      appId: 16777251, // S6a
      originHost: 'internal-mme01.core.net',
      originRealm: 'core.net',
      destRealm: 'untrusted-ipx.net',
      peerHost: 'unknown-peer.untrusted-ipx.net',
      peerIp: '203.0.113.88',
      imsi: '310410999999999',
      listenIp1: '192.168.1.100',
      listenIp2: '',
      watchdogTimerSec: 90,
      sctpMultiHomed: false, // Single homed!
      topologyHidingEnabled: false, // Exposed!
      encryptionEnabled: false, // Plaintext!
      commandScreeningEnabled: false,
      realmValidationEnabled: false,
      avpScreeningEnabled: false,
      coppEnabled: false,
      idStateIsolationEnabled: false,
      mBitComplianceEnabled: false,
      doicEnabled: false
    }
  };

  let activeTab = 'freediameter';

  // DOM Elements
  const elCmdCode = document.getElementById('select-command-code');
  const elAppId = document.getElementById('select-app-id');
  const elOriginHost = document.getElementById('input-origin-host');
  const elOriginRealm = document.getElementById('input-origin-realm');
  const elDestRealm = document.getElementById('input-dest-realm');
  const elImsi = document.getElementById('input-imsi');
  const elListenIp1 = document.getElementById('input-listen-ip1');
  const elListenIp2 = document.getElementById('input-listen-ip2');
  const elPeerIp = document.getElementById('input-peer-ip');
  const elWatchdogSec = document.getElementById('input-watchdog-sec');
  const elChkSctpMultihome = document.getElementById('chk-sctp-multihome');

  const elBadgeAppType = document.getElementById('badge-app-type');
  const elBadgeSctpStatus = document.getElementById('badge-sctp-status');

  const elChkTopologyHiding = document.getElementById('chk-topology-hiding');
  const elChkEncryption = document.getElementById('chk-encryption');
  const elChkCommandScreening = document.getElementById('chk-command-screening');
  const elChkRealmValidation = document.getElementById('chk-realm-validation');
  const elChkAvpScreening = document.getElementById('chk-avp-screening');
  const elChkCopp = document.getElementById('chk-copp');
  const elChkIdIsolation = document.getElementById('chk-id-isolation');
  const elChkMbitCompliance = document.getElementById('chk-mbit-compliance');
  const elChkDoic = document.getElementById('chk-doic');

  const elValWatchdogTime = document.getElementById('val-watchdog-time');
  const elValSctpPaths = document.getElementById('val-sctp-paths');
  const elValTopologyState = document.getElementById('val-topology-state');
  const elValAuthEnc = document.getElementById('val-auth-enc');

  const elScoreBanner = document.getElementById('score-banner');
  const elScoreGrade = document.getElementById('score-grade');
  const elScoreTitle = document.getElementById('score-title');
  const elScoreSummary = document.getElementById('score-summary');
  const elFindingsContainer = document.getElementById('findings-container');

  const elBadgePacketDesc = document.getElementById('badge-packet-desc');
  const elPacketHexDump = document.getElementById('packet-hex-dump');
  const elSynthOutput = document.getElementById('synth-output');
  const elBtnCopy = document.getElementById('btn-copy-config');

  function getFormConfig() {
    return {
      commandCode: parseInt(elCmdCode.value, 10) || 272,
      appId: parseInt(elAppId.value, 10) || 4,
      originHost: elOriginHost.value.trim(),
      originRealm: elOriginRealm.value.trim(),
      destRealm: elDestRealm.value.trim(),
      peerHost: 'peer-dea.roaming-ipx.net',
      peerIp: elPeerIp.value.trim(),
      imsi: elImsi.value.trim(),
      listenIp1: elListenIp1.value.trim(),
      listenIp2: elListenIp2.value.trim(),
      watchdogTimerSec: parseInt(elWatchdogSec.value, 10) || 30,
      sctpMultiHomed: elChkSctpMultihome.checked,
      topologyHidingEnabled: elChkTopologyHiding.checked,
      encryptionEnabled: elChkEncryption.checked,
      commandScreeningEnabled: elChkCommandScreening.checked,
      realmValidationEnabled: elChkRealmValidation.checked,
      avpScreeningEnabled: elChkAvpScreening.checked,
      coppEnabled: elChkCopp.checked,
      idStateIsolationEnabled: elChkIdIsolation.checked,
      mBitComplianceEnabled: elChkMbitCompliance.checked,
      doicEnabled: elChkDoic.checked
    };
  }

  function applyPreset(presetKey) {
    const p = PRESETS[presetKey];
    if (!p) return;

    elCmdCode.value = p.commandCode;
    elAppId.value = p.appId;
    elOriginHost.value = p.originHost;
    elOriginRealm.value = p.originRealm;
    elDestRealm.value = p.destRealm;
    elPeerIp.value = p.peerIp;
    elImsi.value = p.imsi;
    elListenIp1.value = p.listenIp1;
    elListenIp2.value = p.listenIp2;
    elWatchdogSec.value = p.watchdogTimerSec;
    elChkSctpMultihome.checked = p.sctpMultiHomed;

    elChkTopologyHiding.checked = p.topologyHidingEnabled;
    elChkEncryption.checked = p.encryptionEnabled;
    elChkCommandScreening.checked = p.commandScreeningEnabled;
    elChkRealmValidation.checked = p.realmValidationEnabled;
    elChkAvpScreening.checked = p.avpScreeningEnabled;
    elChkCopp.checked = p.coppEnabled;
    elChkIdIsolation.checked = p.idStateIsolationEnabled;
    elChkMbitCompliance.checked = p.mBitComplianceEnabled;
    elChkDoic.checked = p.doicEnabled;

    document.querySelectorAll('.btn-preset').forEach(b => b.classList.remove('active'));
    const btn = document.getElementById(`btn-preset-${presetKey}`);
    if (btn) btn.classList.add('active');

    updateAll();
  }

  function updateAll() {
    const cfg = getFormConfig();

    // 1. Badge Application Name
    const cmdInfo = DiameterProtocolEngine.COMMAND_CODES[cfg.commandCode] || { req: 'MSG' };
    elBadgeAppType.textContent = `${cmdInfo.req} (App: ${cfg.appId})`;

    // 2. SCTP Status Badge
    if (cfg.sctpMultiHomed) {
      elBadgeSctpStatus.textContent = 'Dual-Path Resilient';
      elBadgeSctpStatus.className = 'badge badge-green';
      elValSctpPaths.textContent = 'Dual-Path';
    } else {
      elBadgeSctpStatus.textContent = 'Single Path Hazard';
      elBadgeSctpStatus.className = 'badge badge-rose';
      elValSctpPaths.textContent = 'Single-Path';
    }

    // 3. Metrics Row
    elValWatchdogTime.textContent = `${cfg.watchdogTimerSec} sec`;
    elValTopologyState.textContent = cfg.topologyHidingEnabled ? 'Masked (FS.19)' : 'Exposed (Danger)';
    elValAuthEnc.textContent = cfg.encryptionEnabled ? 'mTLS Active' : 'Plaintext (Insecure)';

    // 4. 10-Point Zero-Trust Audit
    const audit = DiameterSecurityAuditor.auditDiameterSecurity(cfg);
    elScoreGrade.textContent = audit.grade;
    elScoreTitle.textContent = `${audit.totalScore} / ${audit.maxScore} Points (${audit.passed ? 'Passed' : 'Failed'})`;
    elScoreSummary.textContent = audit.summary;
    elScoreBanner.className = `score-badge-large ${audit.passed ? 'grade-A' : 'grade-F'}`;

    elFindingsContainer.innerHTML = '';
    audit.findings.forEach(f => {
      const item = document.createElement('div');
      item.className = `finding-item ${f.status.toLowerCase()}`;
      item.innerHTML = `
        <div class="finding-title">
          <span>${f.name}</span>
          <span style="font-family: var(--font-mono);">${f.score}/${f.maxScore} pts</span>
        </div>
        <div class="finding-desc">${f.description}</div>
        ${f.remediation ? `<div class="finding-remediation">Remediation: ${f.remediation}</div>` : ''}
      `;
      elFindingsContainer.appendChild(item);
    });

    // 5. Binary Hex Message Dissector
    const pktBytes = DiameterProtocolEngine.encodeDiameterMessage({
      commandCode: cfg.commandCode,
      appId: cfg.appId,
      originHost: cfg.originHost,
      originRealm: cfg.originRealm,
      destRealm: cfg.destRealm,
      imsi: cfg.imsi,
      isRequest: true
    });

    elBadgePacketDesc.textContent = `${cmdInfo.req} Message (${pktBytes.length} Bytes)`;
    elPacketHexDump.textContent = DiameterProtocolEngine.formatHexDump(pktBytes);

    // 6. Synthesizer Output
    renderSynthesizer(cfg);
  }

  function renderSynthesizer(cfg) {
    let code = '';
    if (activeTab === 'freediameter') {
      code = DiameterConfigSynthesizer.generateFreeDiameter(cfg);
    } else if (activeTab === 'open5gs') {
      code = DiameterConfigSynthesizer.generateOpen5GS(cfg);
    } else if (activeTab === 'cisco') {
      code = DiameterConfigSynthesizer.generateCisco(cfg);
    } else if (activeTab === 'junos') {
      code = DiameterConfigSynthesizer.generateJunos(cfg);
    } else if (activeTab === 'prom') {
      code = DiameterConfigSynthesizer.generatePrometheus(cfg);
    }
    elSynthOutput.textContent = code;
  }

  // Event Listeners
  document.getElementById('btn-preset-roaming').addEventListener('click', () => applyPreset('roaming'));
  document.getElementById('btn-preset-enterprise').addEventListener('click', () => applyPreset('enterprise'));
  document.getElementById('btn-preset-vulnerable').addEventListener('click', () => applyPreset('vulnerable'));
  document.getElementById('btn-recalculate').addEventListener('click', updateAll);

  [elCmdCode, elAppId, elOriginHost, elOriginRealm, elDestRealm, elImsi, elListenIp1, elListenIp2, elPeerIp,
   elWatchdogSec, elChkSctpMultihome,
   elChkTopologyHiding, elChkEncryption, elChkCommandScreening, elChkRealmValidation,
   elChkAvpScreening, elChkCopp, elChkIdIsolation, elChkMbitCompliance, elChkDoic
  ].forEach(input => {
    input.addEventListener('change', updateAll);
  });

  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', (e) => {
      document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
      e.target.classList.add('active');
      activeTab = e.target.getAttribute('data-tab');
      renderSynthesizer(getFormConfig());
    });
  });

  elBtnCopy.addEventListener('click', () => {
    navigator.clipboard.writeText(elSynthOutput.textContent).then(() => {
      elBtnCopy.textContent = 'Copied!';
      setTimeout(() => { elBtnCopy.textContent = 'Copy Config'; }, 2000);
    });
  });

  // Initialize
  applyPreset('roaming');
})();
