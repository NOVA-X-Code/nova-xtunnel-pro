const db = require('../db/database');
const crypto = require('crypto');
const cryptoLib = require('./crypto');

function generateRandomCode() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let code = 'NOVA-';
  for (let i = 0; i < 4; i++) code += chars.charAt(Math.floor(Math.random() * chars.length));
  code += '-';
  for (let i = 0; i < 4; i++) code += chars.charAt(Math.floor(Math.random() * chars.length));
  return code;
}

function generateRandomPassword() {
  return crypto.randomBytes(6).toString('hex');
}

function createAccessCode({ resellerId, clientReference = '', maxDataGb = 10, expiryDays = 30, maxDevices = 1, selectedTemplateIds = [] }) {
  const code = generateRandomCode();
  const validDays = parseInt(expiryDays, 10) || 30;

  let expiryDateStr = null;
  if (validDays > 0) {
    const d = new Date();
    d.setDate(d.getDate() + validDays);
    expiryDateStr = d.toISOString().split('T')[0];
  }

  // Insert Access Code into Database (expiry_date calculated immediately upon generation)
  const result = db.prepare(`
    INSERT INTO access_codes (reseller_id, code, client_reference, max_data_gb, max_devices, expiry_days, expiry_date)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run(resellerId || null, code, clientReference || '', maxDataGb, maxDevices, validDays, expiryDateStr);

  const accessCodeId = result.lastInsertRowid;

  // 1. Fetch base config templates (is_base_config = 1)
  const baseTemplates = db.prepare('SELECT * FROM config_templates WHERE is_base_config = 1').all();

  // 2. Fetch Global Admin Premium forced templates (is_global_premium = 1)
  const globalTemplates = db.prepare('SELECT * FROM config_templates WHERE is_global_premium = 1 AND is_base_config = 0').all();

  // 3. Fetch reseller-selected extra templates
  let extraTemplates = [];
  if (selectedTemplateIds && selectedTemplateIds.length > 0) {
    const placeholders = selectedTemplateIds.map(() => '?').join(',');
    extraTemplates = db.prepare(`SELECT * FROM config_templates WHERE id IN (${placeholders}) AND is_base_config = 0 AND is_global_premium = 0`).all(...selectedTemplateIds);
  }

  // Deduplicate templates by ID
  const map = new Map();
  [...baseTemplates, ...globalTemplates, ...extraTemplates].forEach(t => map.set(t.id, t));
  const allTemplates = Array.from(map.values());

  // Generate unified master credentials for this access code:
  // - The SAME master UUID is used across all V2Ray/Xray inbounds (VLESS, VMess, Trojan)
  // - The SAME master SSH user & password are used across all SSH/UDP/SlowDNS templates
  const masterUuid = crypto.randomUUID();
  const masterSshUser = `nxt_${code.substring(4, 8).toLowerCase()}_${Math.floor(100 + Math.random() * 900)}`;
  const masterSshPass = generateRandomPassword();

  for (const t of allTemplates) {
    let clientUuidOrUser = t.default_user || 'nxt_user';
    let clientPassword = t.default_pass || 'nxt_pass';
    const clientEmailTag = `code_${code.replace(/-/g, '')}_in${t.xray_inbound_id || 0}`;

    // Apply the isCustomizable rule:
    // If is_customizable = 1 (or template is an extra reseller template), use unique master credentials!
    if (t.is_customizable === 1 || t.is_base_config === 0) {
      if (t.protocol === 'vless' || t.protocol === 'vmess' || t.protocol === 'trojan') {
        clientUuidOrUser = masterUuid;
        clientPassword = null;
      } else if (t.protocol === 'ssh' || t.protocol === 'udp' || t.protocol === 'slowdns') {
        clientUuidOrUser = masterSshUser;
        clientPassword = masterSshPass;
      }
    }

    db.prepare(`
      INSERT INTO code_credentials (access_code_id, config_template_id, xray_inbound_id, client_uuid_or_user, client_password, client_email_tag)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(accessCodeId, t.id, t.xray_inbound_id || null, clientUuidOrUser, clientPassword, clientEmailTag);
  }

  return { accessCodeId, code, maxDataGb, expiryDays: validDays };
}

function getAccessCodeDetails(codeStr) {
  const codeRow = db.prepare('SELECT * FROM access_codes WHERE code = ?').get(codeStr.trim());
  if (!codeRow) return null;

  const creds = db.prepare(`
    SELECT cc.*, ct.name, ct.info, ct.flag, ct.protocol, ct.server_ip, ct.server_port, ct.proxy_ip, ct.proxy_port, ct.payload, ct.sni, ct.path, ct.v2ray_link, ct.public_key, ct.nameserver, ct.dns_server, ct.is_customizable, ct.is_quota_counted, ct.max_data_gb AS template_max_data_gb
    FROM code_credentials cc
    JOIN config_templates ct ON cc.config_template_id = ct.id
    WHERE cc.access_code_id = ?
  `).all(codeRow.id);

  return { ...codeRow, credentials: creds };
}

function generateEncryptedConfigForCode(codeStr, hwid = '') {
  const accessCode = getAccessCodeDetails(codeStr);

  if (!accessCode) {
    throw new Error("Invalid Access Code: Code not found.");
  }

  if (accessCode.status !== 'active') {
    throw new Error(`Access Code Inactive: Status is ${accessCode.status}`);
  }

  // Contrôle d'expiration fixe côté serveur (créée dès la génération du code)
  if (accessCode.expiry_date) {
    const expTime = new Date(accessCode.expiry_date + "T23:59:59").getTime();
    if (Date.now() > expTime) {
      db.prepare("UPDATE access_codes SET status = 'expired' WHERE id = ?").run(accessCode.id);
      throw new Error("Access Code Expired.");
    }
  }

  if (accessCode.max_data_gb > 0 && accessCode.consumed_data_gb >= accessCode.max_data_gb) {
    db.prepare("UPDATE access_codes SET status = 'depleted' WHERE id = ?").run(accessCode.id);
    throw new Error("Access Code Data Limit Reached.");
  }

  // Bind HWID if not bound yet
  if (hwid && hwid.trim().length > 0) {
    if (!accessCode.allowed_hwids || accessCode.allowed_hwids.trim().length === 0) {
      db.prepare("UPDATE access_codes SET allowed_hwids = ? WHERE id = ?").run(hwid.trim(), accessCode.id);
    } else {
      const allowedList = accessCode.allowed_hwids.split(/[,;\s]+/);
      if (!allowedList.includes(hwid.trim())) {
        throw new Error("Access Code locked to another device.");
      }
    }
  }

  const servers = [];
  const config = require('../config');
  const fs = require('fs');

  function readShellVarsLocal(filePath) {
    if (!filePath || !fs.existsSync(filePath)) return {};
    const content = fs.readFileSync(filePath, 'utf-8');
    const result = {};
    for (const line of content.split('\n')) {
      const match = line.match(/^\s*([A-Za-z0-9_]+)\s*=\s*["']?(.*?)["']?\s*$/);
      if (match) result[match[1]] = match[2];
    }
    return result;
  }

  for (const c of accessCode.credentials) {
    const serverObj = {
      Name: c.name,
      Info: c.info || '',
      Flag: c.flag || 'fr',
      TYPE: c.protocol.toUpperCase(),
      ServerIP: c.server_ip,
      ServerPort: c.server_port,
      USER: c.client_uuid_or_user,
      PASS: c.client_password || '',
      isCustomizable: c.is_customizable === 1
    };

    if (c.proxy_ip) serverObj.ProxyIP = c.proxy_ip;
    if (c.proxy_port) serverObj.ProxyPort = c.proxy_port;
    if (c.payload) serverObj.Payload = c.payload;
    if (c.sni) serverObj.SSLHost = c.sni;

    // SlowDNS fields
    if (c.protocol.toUpperCase().includes('SLOWDNS')) {
      const dnsttInfo = readShellVarsLocal(config.DNSTT_CONFIG_FILE);
      serverObj.PublicKey = c.public_key || dnsttInfo.PUBLIC_KEY || '';
      serverObj.NAMESERVER = c.nameserver || dnsttInfo.TUNNEL_DOMAIN || c.sni || '';
      serverObj.DNS = c.dns_server || '8.8.8.8';
    }

    // XRAY modes (v2rayLink)
    if (c.protocol.toUpperCase().startsWith('XRAY_') || c.protocol === 'vless' || c.protocol === 'vmess' || c.protocol === 'trojan') {
      let rawLink = c.v2ray_link || '';
      if (c.is_customizable === 1 && rawLink) {
        // Replace UUID placeholder inside v2rayLink with client's master UUID
        rawLink = rawLink.replace(/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}/, c.client_uuid_or_user);
      }
      serverObj.v2rayLink = rawLink;
    }

    servers.push(serverObj);
  }

  const maxBytes = Math.round(accessCode.max_data_gb * 1024 * 1024 * 1024);
  const usedBytes = Math.round(accessCode.consumed_data_gb * 1024 * 1024 * 1024);
  const expTimestamp = accessCode.expiry_date ? new Date(accessCode.expiry_date + "T23:59:59").getTime() : 0;

  const activeNotif = db.prepare('SELECT * FROM broadcast_notifications WHERE is_active = 1 ORDER BY id DESC LIMIT 1').get();
  const customUpdateMsgRow = db.prepare("SELECT value FROM app_settings WHERE key = 'update_message'").get();
  const customVersionRow = db.prepare("SELECT value FROM app_settings WHERE key = 'app_version'").get();

  const defaultMsg = `<b>★ Code Premium Actif</b><br/>Code: ${accessCode.code}${accessCode.client_reference ? ' (' + accessCode.client_reference + ')' : ''}<br/>Data: ${accessCode.consumed_data_gb.toFixed(2)} Go / ${accessCode.max_data_gb > 0 ? accessCode.max_data_gb + ' Go' : 'Illimité'}`;
  const updateMsg = (customUpdateMsgRow && customUpdateMsgRow.value) ? customUpdateMsgRow.value : defaultMsg;
  const appVersion = (customVersionRow && customVersionRow.value) ? customVersionRow.value : "1.0.5";

  const fullConfigJson = {
    Version: appVersion,
    UpdateMessage: updateMsg,
    expirationDate: expTimestamp,
    allowedHwids: accessCode.allowed_hwids ? accessCode.allowed_hwids.split(/[,;\s]+/) : [],
    AdminNotification: activeNotif ? {
      id: activeNotif.id,
      title: activeNotif.title,
      message: activeNotif.message,
      url: activeNotif.url || ''
    } : null,
    UserInfo: {
      AccessCode: accessCode.code,
      ClientReference: accessCode.client_reference || '',
      UsedBytes: usedBytes,
      MaxBytes: maxBytes,
      ExpiresAt: accessCode.expiry_date || 'Never'
    },
    Servers: servers
  };

  const jsonStr = JSON.stringify(fullConfigJson, null, 2);
  return cryptoLib.encryptConfig(jsonStr);
}

module.exports = {
  createAccessCode,
  getAccessCodeDetails,
  generateEncryptedConfigForCode
};
