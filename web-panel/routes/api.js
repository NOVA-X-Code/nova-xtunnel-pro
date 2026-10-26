const express = require('express');
const accessCodes = require('../lib/accessCodes');
const db = require('../db/database');
const cryptoLib = require('../lib/crypto');

const router = express.Router();

router.use(express.json());

// Public API endpoint for NovaXTunnel Android application
// Accessible via https://nxtvpn.nostra.dpdns.org/api/v1/download-config
router.post('/download-config', (req, res) => {
  try {
    const { access_code, hwid } = req.body;

    // Default or Free base config request
    if (!access_code || access_code.trim().length === 0 || access_code.trim().toUpperCase() === 'DEFAULT' || access_code.trim().toUpperCase() === 'FREE') {
      const baseTemplates = db.prepare('SELECT * FROM config_templates WHERE is_base_config = 1').all();

      const servers = baseTemplates.map(t => {
        const s = {
          Name: t.name,
          Info: t.info || '',
          Flag: t.flag || 'fr',
          TYPE: t.protocol.toUpperCase(),
          ServerIP: t.server_ip,
          ServerPort: t.server_port,
          USER: t.default_user || 'free_user',
          PASS: t.default_pass || 'free_pass',
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

      const defaultConfigJson = {
        Version: "2026.2.0",
        UpdateMessage: "<b>★ Application NovaXTunnel à jour</b><br/>Serveurs de base chargés avec succès.",
        expirationDate: 0,
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
    return res.status(400).json({
      status: 'error',
      message: e.message
    });
  }
});

module.exports = router;
