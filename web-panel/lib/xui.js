const Database = require('better-sqlite3');
const fs = require('fs');
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

function addClientToXuiInbound(inboundId, clientUuid, emailTag, maxDataGb = 0, expiryDateStr = null) {
  const dbPath = findXuiDbPath();
  if (!dbPath || !inboundId) return false;

  try {
    const xuiDb = new Database(dbPath);
    const row = xuiDb.prepare('SELECT settings FROM inbounds WHERE id = ?').get(inboundId);
    if (!row) {
      xuiDb.close();
      return false;
    }

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
    xuiDb.prepare('UPDATE inbounds SET settings = ? WHERE id = ?').run(updatedSettingsJson, inboundId);
    xuiDb.close();

    try { execSync('systemctl restart x-ui 2>/dev/null || x-ui restart 2>/dev/null', { stdio: 'ignore' }); } catch (e) {}
    return true;
  } catch (e) {
    console.log('3X-UI Sync Note:', e.message);
    return false;
  }
}

module.exports = {
  addClientToXuiInbound,
  findXuiDbPath
};
