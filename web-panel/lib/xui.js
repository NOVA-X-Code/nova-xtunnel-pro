const Database = require('better-sqlite3');
const fs = require('fs');
const http = require('http');
const https = require('https');
const { execSync } = require('child_process');

function findXuiDbPath() {
  const paths = [
    '/etc/x-ui/x-ui.db',
    '/etc/x-ui-english/x-ui.db',
    '/usr/local/x-ui/db/x-ui.db',
    '/var/lib/x-ui/x-ui.db'
  ];
  for (const p of paths) {
    if (fs.existsSync(p)) return p;
  }
  return null;
}

function getXuiApiCredentials() {
  const db = require('../db/database');
  let xuiUrl = 'http://127.0.0.1:2053';
  let xuiUser = 'admin';
  let xuiPass = 'admin';

  try {
    const urlRow = db.prepare("SELECT value FROM app_settings WHERE key = 'xui_url'").get();
    const userRow = db.prepare("SELECT value FROM app_settings WHERE key = 'xui_username'").get();
    const passRow = db.prepare("SELECT value FROM app_settings WHERE key = 'xui_password'").get();

    if (urlRow && urlRow.value) xuiUrl = urlRow.value.trim();
    if (userRow && userRow.value) xuiUser = userRow.value.trim();
    if (passRow && passRow.value) xuiPass = passRow.value.trim();
  } catch (e) {}

  return { xuiUrl, xuiUser, xuiPass };
}

async function addClientViaXuiApi(inboundId, clientUuid, emailTag, maxDataGb = 0, expiryDateStr = null) {
  const { xuiUrl, xuiUser, xuiPass } = getXuiApiCredentials();
  if (!xuiUrl || !inboundId) return false;

  try {
    const baseUrlClean = xuiUrl.replace(/\/$/, '');
    const loginUrl = new URL(`${baseUrlClean}/login`);
    const postData = `username=${encodeURIComponent(xuiUser)}&password=${encodeURIComponent(xuiPass)}`;

    const isHttps = loginUrl.protocol === 'https:';
    const transport = isHttps ? https : http;

    // 1. Perform HTTP Login to 3X-UI
    const loginCookie = await new Promise((resolve) => {
      const opts = {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Content-Length': Buffer.byteLength(postData)
        },
        timeout: 5000
      };
      if (isHttps) opts.rejectUnauthorized = false;

      const req = transport.request(loginUrl, opts, (res) => {
        const cookies = res.headers['set-cookie'];
        if (cookies && cookies.length > 0) {
          resolve(cookies.join('; '));
        } else {
          resolve(null);
        }
      });
      req.on('error', () => resolve(null));
      req.on('timeout', () => { req.destroy(); resolve(null); });
      req.write(postData);
      req.end();
    });

    if (!loginCookie) return false;

    // 2. Call /panel/api/inbounds/addClient
    const addClientUrl = new URL(`${baseUrlClean}/panel/api/inbounds/addClient`);
    const expMs = expiryDateStr ? new Date(expiryDateStr + "T23:59:59").getTime() : 0;
    const totalBytes = maxDataGb > 0 ? Math.round(maxDataGb * 1024 * 1024 * 1024) : 0;

    const payload = JSON.stringify({
      id: parseInt(inboundId, 10),
      settings: JSON.stringify({
        clients: [{
          id: clientUuid,
          email: emailTag,
          limitIp: 0,
          totalGB: totalBytes,
          expiryTime: expMs,
          enable: true,
          tgId: "",
          subId: ""
        }]
      })
    });

    const apiSuccess = await new Promise((resolve) => {
      const opts = {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Cookie': loginCookie,
          'Content-Length': Buffer.byteLength(payload)
        },
        timeout: 5000
      };
      if (isHttps) opts.rejectUnauthorized = false;

      const req = transport.request(addClientUrl, opts, (res) => {
        let body = '';
        res.on('data', chunk => body += chunk);
        res.on('end', () => {
          try {
            const parsed = JSON.parse(body);
            resolve(Boolean(parsed && parsed.success));
          } catch (e) {
            resolve(false);
          }
        });
      });
      req.on('error', () => resolve(false));
      req.on('timeout', () => { req.destroy(); resolve(false); });
      req.write(payload);
      req.end();
    });

    return apiSuccess;
  } catch (e) {
    return false;
  }
}

function addClientToXuiInbound(inboundId, clientUuid, emailTag, maxDataGb = 0, expiryDateStr = null) {
  const dbPath = findXuiDbPath();
  if (!dbPath || !inboundId) return false;

  // Try HTTP API sync first if credentials/URL work
  addClientViaXuiApi(inboundId, clientUuid, emailTag, maxDataGb, expiryDateStr).catch(() => {});

  try {
    // Stop x-ui process temporarily to prevent memory cache overwrite
    try { execSync('systemctl stop x-ui 2>/dev/null', { stdio: 'ignore' }); } catch (e) {}

    const xuiDb = new Database(dbPath);
    // Find inbound by database ID or port number
    let row = xuiDb.prepare('SELECT id, settings FROM inbounds WHERE id = ?').get(inboundId);
    if (!row) {
      row = xuiDb.prepare('SELECT id, settings FROM inbounds WHERE port = ?').get(inboundId);
    }

    if (!row) {
      xuiDb.close();
      try { execSync('systemctl start x-ui 2>/dev/null', { stdio: 'ignore' }); } catch (e) {}
      return false;
    }

    const realInboundId = row.id;

    let settingsObj = {};
    try { settingsObj = JSON.parse(row.settings); } catch (e) { settingsObj = {}; }
    if (!Array.isArray(settingsObj.clients)) {
      settingsObj.clients = [];
    }

    const expMs = expiryDateStr ? new Date(expiryDateStr + "T23:59:59").getTime() : 0;
    const totalBytes = maxDataGb > 0 ? Math.round(maxDataGb * 1024 * 1024 * 1024) : 0;

    const newClientObj = {
      id: clientUuid,
      email: emailTag,
      limitIp: 0,
      totalGB: totalBytes,
      expiryTime: expMs,
      enable: true,
      tgId: "",
      subId: ""
    };

    const existingIndex = settingsObj.clients.findIndex(c => c.id === clientUuid || c.email === emailTag);
    if (existingIndex >= 0) {
      settingsObj.clients[existingIndex] = newClientObj;
    } else {
      settingsObj.clients.push(newClientObj);
    }

    const updatedSettingsJson = JSON.stringify(settingsObj);
    xuiDb.prepare('UPDATE inbounds SET settings = ? WHERE id = ?').run(updatedSettingsJson, realInboundId);

    // Insert or update 3X-UI's client_traffics table for statistics tracking & web panel display
    try {
      const trafficRow = xuiDb.prepare('SELECT id FROM client_traffics WHERE email = ?').get(emailTag);
      if (trafficRow) {
        xuiDb.prepare('UPDATE client_traffics SET inbound_id = ?, total = ?, expiry_time = ?, enable = 1 WHERE email = ?')
          .run(realInboundId, totalBytes, expMs, emailTag);
      } else {
        xuiDb.prepare('INSERT INTO client_traffics (inbound_id, enable, email, up, down, expiry_time, total) VALUES (?, 1, ?, 0, 0, ?, ?)')
          .run(realInboundId, emailTag, expMs, totalBytes);
      }
    } catch (e) {}

    xuiDb.close();

    // Start x-ui service so it loads the updated database fresh into memory
    try { execSync('systemctl start x-ui 2>/dev/null || systemctl restart x-ui 2>/dev/null', { stdio: 'ignore' }); } catch (e) {}
    return true;
  } catch (e) {
    console.log('3X-UI Sync Note:', e.message);
    try { execSync('systemctl start x-ui 2>/dev/null', { stdio: 'ignore' }); } catch (err) {}
    return false;
  }
}

function getClientTrafficFromXui(emailTag) {
  const dbPath = findXuiDbPath();
  if (!dbPath || !emailTag) return null;

  try {
    const xuiDb = new Database(dbPath);
    const row = xuiDb.prepare('SELECT email, up, down, total, expiry_time FROM client_traffics WHERE email = ?').get(emailTag);
    xuiDb.close();
    if (!row) return null;
    return {
      email: row.email,
      up: row.up || 0,
      down: row.down || 0,
      total: row.total || 0,
      expiryTime: row.expiry_time || 0
    };
  } catch (e) {
    return null;
  }
}

function removeClientFromXuiInbound(inboundId, emailTag) {
  const dbPath = findXuiDbPath();
  if (!dbPath || !emailTag) return false;

  try {
    try { execSync('systemctl stop x-ui 2>/dev/null', { stdio: 'ignore' }); } catch (e) {}

    const xuiDb = new Database(dbPath);

    if (inboundId) {
      let row = xuiDb.prepare('SELECT id, settings FROM inbounds WHERE id = ?').get(inboundId);
      if (!row) {
        row = xuiDb.prepare('SELECT id, settings FROM inbounds WHERE port = ?').get(inboundId);
      }
      if (row) {
        let settingsObj = {};
        try { settingsObj = JSON.parse(row.settings); } catch (e) {}
        if (Array.isArray(settingsObj.clients)) {
          settingsObj.clients = settingsObj.clients.filter(c => c.email !== emailTag);
          xuiDb.prepare('UPDATE inbounds SET settings = ? WHERE id = ?').run(JSON.stringify(settingsObj), row.id);
        }
      }
    }

    try { xuiDb.prepare('DELETE FROM client_traffics WHERE email = ?').run(emailTag); } catch (e) {}
    xuiDb.close();

    try { execSync('systemctl start x-ui 2>/dev/null || systemctl restart x-ui 2>/dev/null', { stdio: 'ignore' }); } catch (e) {}
    return true;
  } catch (e) {
    try { execSync('systemctl start x-ui 2>/dev/null', { stdio: 'ignore' }); } catch (err) {}
    return false;
  }
}

module.exports = {
  addClientToXuiInbound,
  getClientTrafficFromXui,
  removeClientFromXuiInbound,
  findXuiDbPath
};
