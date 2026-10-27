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

  // Si les en-têtes d'authentification de l'App sont présents, vérifier la signature HMAC-SHA256
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
        const s = {
          Name: t.name,
          Info: t.info || '',
          Flag: t.flag || 'fr',
          TYPE: t.protocol.toUpperCase(),
          ServerIP: t.server_ip,
          ServerPort: t.server_port,
          USER: t.default_user || globalUser,
          PASS: t.default_pass || globalPass,
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

module.exports = router;
