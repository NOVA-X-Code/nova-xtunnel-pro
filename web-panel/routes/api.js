const express = require('express');
const crypto = require('crypto');
const accessCodes = require('../lib/accessCodes');
const db = require('../db/database');
const cryptoLib = require('../lib/crypto');
const config = require('../config');

const router = express.Router();

router.use(express.json());

const APP_HMAC_SECRET = config.APP_HMAC_SECRET || process.env.APP_HMAC_SECRET || 'NovaxSecretKey2026';

// Middleware de vérification de la signature HMAC-SHA256 de l'App NovaXTunnel
function verifyAppSignature(req, res, next) {
  const timestamp = req.headers['x-novax-timestamp'];
  const signature = req.headers['x-novax-signature'];

  if (timestamp && signature) {
    const now = Date.now();
    const reqTime = parseInt(timestamp, 10);
    if (isNaN(reqTime) || Math.abs(now - reqTime) > 10 * 60 * 1000) {
      return res.status(403).json({
        status: 'error',
        message: 'Accès refusé : Horodatage expiré.'
      });
    }

    const path = req.originalUrl || req.path;
    const dataToSign = `${timestamp}:${path}`;
    const expectedSignature = crypto
      .createHmac('sha256', APP_HMAC_SECRET)
      .update(dataToSign)
      .digest('hex');

    const sigBuffer = Buffer.from(signature, 'utf-8');
    const expectedBuffer = Buffer.from(expectedSignature, 'utf-8');

    if (sigBuffer.length !== expectedBuffer.length || !crypto.timingSafeEqual(sigBuffer, expectedBuffer)) {
      return res.status(403).json({
        status: 'error',
        message: 'Accès refusé : Signature d\'application invalide.'
      });
    }
  }

  next();
}

// Public API endpoint for NovaXTunnel Android application
router.post('/download-config', verifyAppSignature, (req, res) => {
  try {
    const { access_code, hwid } = req.body;

    // Default or Free base config request
    if (!access_code || access_code.trim().length === 0 || access_code.trim().toUpperCase() === 'DEFAULT' || access_code.trim().toUpperCase() === 'FREE') {
      const baseTemplates = db.prepare('SELECT * FROM config_templates WHERE is_base_config = 1').all();

      const globalUserRow = db.prepare("SELECT value FROM app_settings WHERE key = 'default_ssh_user'").get();
      const globalPassRow = db.prepare("SELECT value FROM app_settings WHERE key = 'default_ssh_pass'").get();
      const globalUser = (globalUserRow && globalUserRow.value) ? globalUserRow.value : 'NOSTRA';
      const globalPass = (globalPassRow && globalPassRow.value) ? globalPassRow.value : '@LaBoKingFreeSurf';

      const servers = baseTemplates.map(t => {
        const isZiVpnUdp = t.protocol.toUpperCase() === 'UDP';
        const s = {
          Name: t.name,
          Info: t.info || '',
          Flag: t.flag || 'fr',
          TYPE: t.protocol.toUpperCase(),
          ServerIP: t.server_ip,
          ServerPort: t.server_port,
          USER: isZiVpnUdp ? (t.default_pass || '@LaBoKingFreeSurf') : (t.default_user || globalUser),
          PASS: isZiVpnUdp ? '' : (t.default_pass || globalPass),
          isCustomizable: t.is_customizable === 1
        };
        if (t.proxy_ip) s.ProxyIP = t.proxy_ip;
        if (t.proxy_port) s.ProxyPort = t.proxy_port;
        if (t.payload) s.Payload = t.payload;
        if (t.sni) s.SSLHost = t.sni;
        if (t.v2ray_link) s.v2rayLink = t.v2ray_link;
        if (t.public_key) s.PublicKey = t.public_key;
        if (t.nameserver) s.NAMESERVER = t.nameserver;
        if (t.dns_server) s.DNS = t.dns_server;
        return s;
      });

      const activeNotif = db.prepare('SELECT * FROM broadcast_notifications WHERE is_active = 1 ORDER BY id DESC LIMIT 1').get();
      const customUpdateMsgRow = db.prepare("SELECT value FROM app_settings WHERE key = 'update_message'").get();
      const customVersionRow = db.prepare("SELECT value FROM app_settings WHERE key = 'app_version'").get();

      const updateMsg = (customUpdateMsgRow && customUpdateMsgRow.value)
        ? customUpdateMsgRow.value
        : "<b>★ Application NovaXTunnel à jour</b><br/>Serveurs de base chargés avec succès.";

      const appVersion = (customVersionRow && customVersionRow.value)
        ? customVersionRow.value
        : "1.0.5";

      const defaultConfigJson = {
        Version: appVersion,
        UpdateMessage: updateMsg,
        expirationDate: 0,
        allowedHwids: [],
        AdminNotification: activeNotif ? {
          id: activeNotif.id,
          title: activeNotif.title,
          message: activeNotif.message,
          url: activeNotif.url || ''
        } : null,
        UserInfo: {
          AccessCode: "FREE",
          UsedBytes: 0,
          MaxBytes: 0,
          ExpiresAt: "Never"
        },
        Servers: servers
      };

      const encryptedData = cryptoLib.encryptConfig(JSON.stringify(defaultConfigJson, null, 2));
      return res.json({
        status: 'success',
        encrypted_data: encryptedData
      });
    }

    // Access Code Premium Config Request
    const encryptedData = accessCodes.generateEncryptedConfigForCode(access_code.trim(), hwid || '');

    return res.json({
      status: 'success',
      encrypted_data: encryptedData
    });

  } catch (e) {
    return res.json({
      status: 'error',
      message: e.message
    });
  }
});

// Data Usage Reporting & Real-time Quota Enforcement Endpoint
router.post('/report-usage', verifyAppSignature, (req, res) => {
  try {
    const { access_code, hwid, bytes_used, template_id } = req.body;

    if (!access_code || access_code.trim().toUpperCase() === 'DEFAULT' || access_code.trim().toUpperCase() === 'FREE') {
      return res.json({ status: 'success', is_active: true, message: 'Free access untracked.' });
    }

    const cleanCode = access_code.trim().toUpperCase();
    const codeRow = db.prepare('SELECT * FROM access_codes WHERE UPPER(code) = ?').get(cleanCode);

    if (!codeRow) {
      return res.json({ status: 'error', is_active: false, message: 'Code Premium introuvable.' });
    }

    if (codeRow.status !== 'active') {
      return res.json({ status: codeRow.status, is_active: false, message: `Code Premium inactif (${codeRow.status}).` });
    }

    // Expiration check
    if (codeRow.expiry_date) {
      const expTime = new Date(codeRow.expiry_date + "T23:59:59").getTime();
      if (Date.now() > expTime) {
        db.prepare("UPDATE access_codes SET status = 'expired' WHERE id = ?").run(codeRow.id);
        return res.json({ status: 'expired', is_active: false, message: 'Code Premium expiré.' });
      }
    }

    // Calculate delta usage in GB
    const bytesReported = parseFloat(bytes_used) || 0;
    if (bytesReported > 0) {
      const usageGb = bytesReported / (1024 * 1024 * 1024);

      // Update consumed_data_gb for the access code
      db.prepare('UPDATE access_codes SET consumed_data_gb = consumed_data_gb + ? WHERE id = ?').run(usageGb, codeRow.id);

      // Also update cumulative consumed_data_gb on the server template
      if (template_id) {
        try {
          db.prepare('UPDATE config_templates SET consumed_data_gb = consumed_data_gb + ? WHERE id = ?').run(usageGb, template_id);
        } catch (e) {}
      }

      // If created by reseller, update reseller's total consumption as well
      if (codeRow.reseller_id) {
        db.prepare('UPDATE resellers SET data_quota_gb = MAX(0, data_quota_gb - ?) WHERE id = ? AND data_quota_gb IS NOT NULL').run(usageGb, codeRow.reseller_id);
      }
    }

    // Refresh updated row
    const updatedCode = db.prepare('SELECT * FROM access_codes WHERE id = ?').get(codeRow.id);

    // Determine effective max data limit (Template specific VS Global code limit)
    let effectiveMaxGb = updatedCode.max_data_gb;
    if (template_id) {
      const tmplRow = db.prepare('SELECT max_data_gb, consumed_data_gb, is_quota_counted FROM config_templates WHERE id = ?').get(template_id);
      if (tmplRow) {
        // Check if server template's shared global quota limit is reached
        if (tmplRow.max_data_gb > 0 && tmplRow.consumed_data_gb >= tmplRow.max_data_gb) {
          return res.json({
            status: 'depleted',
            is_active: false,
            message: 'Quota Data Global de ce serveur gratuit/partagé atteint !',
            consumed_gb: tmplRow.consumed_data_gb,
            max_gb: tmplRow.max_data_gb
          });
        }
        if (tmplRow.is_quota_counted === 0) {
          effectiveMaxGb = 0;
        } else {
          const credRow = db.prepare('SELECT template_max_data_gb FROM code_credentials WHERE access_code_id = ? AND config_template_id = ?')
            .get(updatedCode.id, template_id);
          if (credRow && credRow.template_max_data_gb > 0) {
            effectiveMaxGb = credRow.template_max_data_gb;
          }
        }
      }
    }

    // IF MAX_DATA_GB === 0 -> UNLIMITED DATA! Never disconnects!
    if (effectiveMaxGb > 0 && updatedCode.consumed_data_gb >= effectiveMaxGb) {
      db.prepare("UPDATE access_codes SET status = 'depleted' WHERE id = ?").run(updatedCode.id);
      return res.json({
        status: 'depleted',
        is_active: false,
        message: 'Quota Data Premium épuisé !',
        consumed_gb: updatedCode.consumed_data_gb,
        max_gb: effectiveMaxGb
      });
    }

    const remainingGb = effectiveMaxGb > 0 ? Math.max(0, effectiveMaxGb - updatedCode.consumed_data_gb) : -1;

    return res.json({
      status: 'success',
      is_active: true,
      consumed_gb: updatedCode.consumed_data_gb,
      max_gb: effectiveMaxGb,
      remaining_gb: remainingGb
    });

  } catch (e) {
    return res.json({ status: 'error', is_active: true, message: e.message });
  }
});

module.exports = router;
