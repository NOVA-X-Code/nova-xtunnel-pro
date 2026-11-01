const Database = require('better-sqlite3');
const fs = require('fs');
const http = require('http');
const https = require('https');

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

function getXuiConfig() {
  const db = require('../db/database');
  let xuiUrl = '';
  let xuiUser = '';
  let xuiPass = '';

  try {
    const urlRow = db.prepare("SELECT value FROM app_settings WHERE key = 'xui_url'").get();
    const userRow = db.prepare("SELECT value FROM app_settings WHERE key = 'xui_username'").get();
    const passRow = db.prepare("SELECT value FROM app_settings WHERE key = 'xui_password'").get();

    if (urlRow && urlRow.value) xuiUrl = urlRow.value.trim();
    if (userRow && userRow.value) xuiUser = userRow.value.trim();
    if (passRow && passRow.value) xuiPass = passRow.value.trim();
  } catch (e) {}

  // Auto-detect port, webBasePath and admin credentials from 3X-UI SQLite database if empty
  const dbPath = findXuiDbPath();
  let autoPort = '2053';
  let autoBasePath = '';
  let autoUser = 'admin';
  let autoPass = 'admin';

  if (dbPath && fs.existsSync(dbPath)) {
    try {
      const xuiDb = new Database(dbPath, { readonly: true });
      const rows = xuiDb.prepare('SELECT key, value FROM settings').all();
      rows.forEach(r => {
        if (r.key === 'webPort' && r.value) autoPort = r.value.trim();
        if (r.key === 'webBasePath' && r.value) autoBasePath = r.value.trim();
      });

      const userRow = xuiDb.prepare('SELECT username, password FROM users LIMIT 1').get();
      if (userRow) {
        if (userRow.username) autoUser = userRow.username.trim();
        if (userRow.password) autoPass = userRow.password.trim();
      }
      xuiDb.close();
    } catch (e) {}
  }

  let finalUrl = xuiUrl || `http://127.0.0.1:${autoPort}`;
  if (!xuiUrl && autoBasePath) {
    if (!autoBasePath.startsWith('/')) autoBasePath = '/' + autoBasePath;
    finalUrl = `http://127.0.0.1:${autoPort}${autoBasePath}`;
  }

  const finalUser = xuiUser || autoUser;
  const finalPass = xuiPass || autoPass;

  return { xuiUrl: finalUrl.replace(/\/$/, ''), xuiUser: finalUser, xuiPass: finalPass };
}

async function loginToXui(xuiUrl, xuiUser, xuiPass) {
  try {
    const loginUrl = new URL(`${xuiUrl}/login`);
    const postData = `username=${encodeURIComponent(xuiUser)}&password=${encodeURIComponent(xuiPass)}`;

    const isHttps = loginUrl.protocol === 'https:';
    const transport = isHttps ? https : http;

    return await new Promise((resolve) => {
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
  } catch (e) {
    return null;
  }
}

async function addClientToXuiInbound(inboundId, clientUuid, emailTag, maxDataGb = 0, expiryDateStr = null) {
  const { xuiUrl, xuiUser, xuiPass } = getXuiConfig();
  if (!xuiUrl || !inboundId) return false;

  try {
    const cookie = await loginToXui(xuiUrl, xuiUser, xuiPass);
    if (!cookie) {
      console.log('3X-UI Login failed for:', xuiUrl);
      return false;
    }

    const isHttps = xuiUrl.startsWith('https:');
    const transport = isHttps ? https : http;

    const addClientUrl = new URL(`${xuiUrl}/panel/api/inbounds/addClient`);
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

    const result = await new Promise((resolve) => {
      const opts = {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Cookie': cookie,
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

    return result;
  } catch (e) {
    console.log('3X-UI addClient error:', e.message);
    return false;
  }
}

async function removeClientFromXuiInbound(inboundId, emailTag) {
  const { xuiUrl, xuiUser, xuiPass } = getXuiConfig();
  if (!xuiUrl || !emailTag) return false;

  try {
    const cookie = await loginToXui(xuiUrl, xuiUser, xuiPass);
    if (!cookie) return false;

    const isHttps = xuiUrl.startsWith('https:');
    const transport = isHttps ? https : http;

    const detachUrl = new URL(`${xuiUrl}/panel/api/clients/${encodeURIComponent(emailTag)}/detach`);
    const payload = JSON.stringify({
      inboundIds: inboundId ? [parseInt(inboundId, 10)] : []
    });

    return await new Promise((resolve) => {
      const opts = {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Cookie': cookie,
          'Content-Length': Buffer.byteLength(payload)
        },
        timeout: 5000
      };
      if (isHttps) opts.rejectUnauthorized = false;

      const req = transport.request(detachUrl, opts, (res) => {
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
  } catch (e) {
    return false;
  }
}

async function getClientTrafficFromXui(emailTag) {
  const { xuiUrl, xuiUser, xuiPass } = getXuiConfig();
  if (!xuiUrl || !emailTag) return null;

  try {
    const cookie = await loginToXui(xuiUrl, xuiUser, xuiPass);
    if (!cookie) return null;

    const isHttps = xuiUrl.startsWith('https:');
    const transport = isHttps ? https : http;

    const trafficUrl = new URL(`${xuiUrl}/panel/api/clients/traffic/${encodeURIComponent(emailTag)}`);

    return await new Promise((resolve) => {
      const opts = {
        method: 'GET',
        headers: {
          'Accept': 'application/json',
          'Cookie': cookie
        },
        timeout: 5000
      };
      if (isHttps) opts.rejectUnauthorized = false;

      const req = transport.request(trafficUrl, opts, (res) => {
        let body = '';
        res.on('data', chunk => body += chunk);
        res.on('end', () => {
          try {
            const parsed = JSON.parse(body);
            if (parsed && parsed.success && parsed.obj) {
              resolve(parsed.obj);
            } else {
              resolve(null);
            }
          } catch (e) {
            resolve(null);
          }
        });
      });
      req.on('error', () => resolve(null));
      req.on('timeout', () => { req.destroy(); resolve(null); });
      req.end();
    });
  } catch (e) {
    return null;
  }
}

module.exports = {
  addClientToXuiInbound,
  removeClientFromXuiInbound,
  getClientTrafficFromXui,
  findXuiDbPath,
  getXuiConfig
};
