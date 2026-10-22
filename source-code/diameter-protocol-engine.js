/**
 * DiameterForge Pro - Core Protocol Engine
 * Standards & Specifications:
 * - RFC 6733: Diameter Base Protocol (Obsoletes RFC 3588)
 * - RFC 4006: Diameter Credit-Control Application (DCCA - Gy/Ro Charging)
 * - 3GPP TS 29.212: Policy and Charging Control (Gx Interface)
 * - 3GPP TS 29.272: Mobility Management Entity (MME) to HSS (S6a Interface)
 * - GSMA FS.19: Diameter Roaming Security Guidelines
 */

(function (root, factory) {
  if (typeof define === 'function' && define.amd) {
    define([], factory);
  } else if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.DiameterProtocolEngine = factory();
  }
}(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  // Diameter Command Codes (RFC 6733 / 3GPP)
  const COMMAND_CODES = {
    257: { name: 'Capabilities-Exchange', req: 'CER', ans: 'CEA' },
    280: { name: 'Device-Watchdog', req: 'DWR', ans: 'DWA' },
    282: { name: 'Disconnect-Peer', req: 'DPR', ans: 'DPA' },
    272: { name: 'Credit-Control', req: 'CCR', ans: 'CCA' },
    274: { name: 'Abort-Session', req: 'ASR', ans: 'ASA' },
    316: { name: 'Update-Location', req: 'ULR', ans: 'ULA' },
    318: { name: 'Authentication-Information', req: 'AIR', ans: 'AIA' }
  };

  // Diameter Application IDs
  const APPLICATION_IDS = {
    0: 'Diameter Common Messages (Base RFC 6733)',
    4: 'Diameter Credit Control Application (DCCA RFC 4006 - Gy/Ro)',
    16777238: '3GPP Gx (Policy Control - TS 29.212)',
    16777251: '3GPP S6a/S6d (MME to HSS - TS 29.272)',
    16777216: '3GPP Cx/Dx (IMS - TS 29.228)'
  };

  // Standard AVP Codes
  const AVP_CODES = {
    1: 'User-Name',
    258: 'Auth-Application-Id',
    263: 'Session-Id',
    264: 'Origin-Host',
    268: 'Result-Code',
    283: 'Destination-Realm',
    293: 'Destination-Host',
    296: 'Origin-Realm',
    415: 'CC-Request-Number',
    416: 'CC-Request-Type',
    443: 'Subscription-Id',
    444: 'Subscription-Id-Data',
    450: 'Subscription-Id-Type'
  };

  // Result Codes (RFC 6733 Section 7.1)
  const RESULT_CODES = {
    2001: 'DIAMETER_SUCCESS',
    2002: 'DIAMETER_LIMITED_SUCCESS',
    3001: 'DIAMETER_COMMAND_UNSUPPORTED',
    3002: 'DIAMETER_UNABLE_TO_DELIVER',
    3003: 'DIAMETER_REALM_NOT_SERVED',
    5001: 'DIAMETER_AVP_UNSUPPORTED',
    5004: 'DIAMETER_INVALID_AVP_VALUE',
    5012: 'DIAMETER_PEER_NOT_AUTHORIZED'
  };

  /**
   * Encode AVP into binary bytes with 4-byte padding alignment
   */
  function encodeAVP(code, dataBytes, opts = {}) {
    const isVendor = !!opts.vendorId;
    const isMandatory = opts.mandatory !== false;
    const isProtected = !!opts.protected;

    let flagByte = 0;
    if (isVendor) flagByte |= 0x80;
    if (isMandatory) flagByte |= 0x40;
    if (isProtected) flagByte |= 0x20;

    const headerLen = isVendor ? 12 : 8;
    const avpLen = headerLen + dataBytes.length;

    const avp = [];
    // 4 bytes AVP Code
    avp.push((code >> 24) & 0xFF, (code >> 16) & 0xFF, (code >> 8) & 0xFF, code & 0xFF);
    // 1 byte Flags
    avp.push(flagByte);
    // 3 bytes AVP Length
    avp.push((avpLen >> 16) & 0xFF, (avpLen >> 8) & 0xFF, avpLen & 0xFF);

    // Optional 4 bytes Vendor-ID
    if (isVendor) {
      const vid = opts.vendorId;
      avp.push((vid >> 24) & 0xFF, (vid >> 16) & 0xFF, (vid >> 8) & 0xFF, vid & 0xFF);
    }

    // AVP Data
    avp.push(...dataBytes);

    // Padding to 4-byte multiple
    const padding = (4 - (avp.length % 4)) % 4;
    for (let p = 0; p < padding; p++) {
      avp.push(0x00);
    }

    return avp;
  }

  function utf8ToBytes(str) {
    const bytes = [];
    for (let i = 0; i < str.length; i++) {
      const code = str.charCodeAt(i);
      bytes.push(code & 0xFF);
    }
    return bytes;
  }

  function uint32ToBytes(val) {
    return [
      (val >> 24) & 0xFF,
      (val >> 16) & 0xFF,
      (val >> 8) & 0xFF,
      val & 0xFF
    ];
  }

  /**
   * Encode Full Diameter Message (CCR / CER / ULR)
   */
  function encodeDiameterMessage(opts = {}) {
    const commandCode = opts.commandCode || 272; // 272 = CCR
    const isRequest = opts.isRequest !== false;
    const isProxiable = opts.isProxiable !== false;
    const isError = !!opts.isError;
    const isRetransmit = !!opts.isRetransmit;
    const appId = opts.appId !== undefined ? opts.appId : 4; // DCCA Gy/Ro
    const hopByHopId = opts.hopByHopId || 0x1a2b3c4d;
    const endToEndId = opts.endToEndId || 0x5e6f7081;

    const avpBytes = [];

    // 1. Session-Id (AVP 263)
    const sessionId = opts.sessionId || 'pgw01.carrier.net;1728392182;10452;1';
    avpBytes.push(...encodeAVP(263, utf8ToBytes(sessionId), { mandatory: true }));

    // 2. Origin-Host (AVP 264)
    const originHost = opts.originHost || 'pgw01.carrier.net';
    avpBytes.push(...encodeAVP(264, utf8ToBytes(originHost), { mandatory: true }));

    // 3. Origin-Realm (AVP 296)
    const originRealm = opts.originRealm || 'carrier.net';
    avpBytes.push(...encodeAVP(296, utf8ToBytes(originRealm), { mandatory: true }));

    // 4. Destination-Realm (AVP 283)
    const destRealm = opts.destRealm || 'ocs.carrier.net';
    avpBytes.push(...encodeAVP(283, utf8ToBytes(destRealm), { mandatory: true }));

    // 5. Auth-Application-Id (AVP 258)
    avpBytes.push(...encodeAVP(258, uint32ToBytes(appId), { mandatory: true }));

    // 6. CC-Request-Type (AVP 416) - 1=INITIAL_REQUEST
    if (commandCode === 272) {
      const ccType = opts.ccType || 1;
      avpBytes.push(...encodeAVP(416, uint32ToBytes(ccType), { mandatory: true }));
      // CC-Request-Number (AVP 415)
      avpBytes.push(...encodeAVP(415, uint32ToBytes(opts.ccNumber || 0), { mandatory: true }));
      // User-Name (AVP 1) - IMSI
      const imsi = opts.imsi || '310410123456789';
      avpBytes.push(...encodeAVP(1, utf8ToBytes(imsi), { mandatory: true }));
    }

    const totalLen = 20 + avpBytes.length;

    // Build 20-byte Diameter Header
    const hdr = [];
    // Byte 0: Version = 1
    hdr.push(0x01);
    // Bytes 1-3: Total Message Length (24 bits)
    hdr.push((totalLen >> 16) & 0xFF, (totalLen >> 8) & 0xFF, totalLen & 0xFF);

    // Byte 4: Command Flags (R, P, E, T)
    let flags = 0;
    if (isRequest) flags |= 0x80;
    if (isProxiable) flags |= 0x40;
    if (isError) flags |= 0x20;
    if (isRetransmit) flags |= 0x10;
    hdr.push(flags);

    // Bytes 5-7: Command Code (24 bits)
    hdr.push((commandCode >> 16) & 0xFF, (commandCode >> 8) & 0xFF, commandCode & 0xFF);

    // Bytes 8-11: Application-ID (32 bits)
    hdr.push(...uint32ToBytes(appId));

    // Bytes 12-15: Hop-by-Hop Identifier (32 bits)
    hdr.push(...uint32ToBytes(hopByHopId));

    // Bytes 16-19: End-to-End Identifier (32 bits)
    hdr.push(...uint32ToBytes(endToEndId));

    return new Uint8Array(hdr.concat(avpBytes));
  }

  /**
   * Format bytes as Wireshark-Style Hex Dump
   */
  function formatHexDump(bytes) {
    const lines = [];
    for (let i = 0; i < bytes.length; i += 16) {
      const offset = i.toString(16).padStart(4, '0');
      const chunk = Array.from(bytes.slice(i, i + 16));
      const hex = chunk.map(b => b.toString(16).padStart(2, '0')).join(' ');
      const ascii = chunk.map(b => (b >= 32 && b <= 126) ? String.fromCharCode(b) : '.').join('');
      lines.push(`${offset}   ${hex.padEnd(48, ' ')}   |${ascii}|`);
    }
    return lines.join('\n');
  }

  return {
    COMMAND_CODES,
    APPLICATION_IDS,
    AVP_CODES,
    RESULT_CODES,
    encodeAVP,
    encodeDiameterMessage,
    formatHexDump
  };
}));
