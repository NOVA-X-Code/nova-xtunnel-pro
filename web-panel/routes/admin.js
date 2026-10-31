const express = require('express');
const bcrypt = require('bcryptjs');
const db = require('../db/database');
const quota = require('../lib/quota');
const clientsLib = require('../lib/clients');
const audit = require('../lib/audit');
const connectionInfo = require('../lib/connectionInfo');
const config = require('../config');
const { requireAdmin } = require('../middleware/auth');

const router = express.Router();
router.use(requireAdmin);

function actorFrom(req) {
  return { type: 'admin', name: req.session.username };
}

router.get('/', (req, res) => {
  const resellers = db.prepare('SELECT * FROM resellers ORDER BY created_at DESC').all();
  const enriched = resellers.map((r) => ({ ...r, stats: quota.getResellerStats(r) }));
  const activity = audit.recent(null, 10);
  res.render('admin/dashboard', {
    resellers: enriched, protocols: config.PROTOCOLS, activity,
    error: req.query.error, success: req.query.success
  });
});

router.get('/activity', (req, res) => {
  const activity = audit.recent(null, 300);
  res.render('activity', { activity, backUrl: '/admin' });
});

router.post('/resellers', (req, res) => {
  try {
    const { username, password, max_users, data_quota_gb, expiry_date, notes } = req.body;
    const protocols = [].concat(req.body.protocols || []);
    const canCreateCodes = (req.body.can_create_codes === '1' || req.body.can_create_codes === 'on') ? 1 : 0;
    const canCreateClients = (req.body.can_create_clients === '1' || req.body.can_create_clients === 'on') ? 1 : 0;
    if (!username || !password) throw new Error('Nom d\'utilisateur et mot de passe requis.');

    const hash = bcrypt.hashSync(password, 10);
    const info = db.prepare(`
      INSERT INTO resellers (username, password_hash, data_quota_gb, max_users, protocols, expiry_date, notes, can_create_codes, can_create_clients)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      username,
      hash,
      data_quota_gb === '' ? null : parseFloat(data_quota_gb),
      parseInt(max_users, 10) || 10,
      JSON.stringify(protocols),
      expiry_date || null,
      notes || '',
      canCreateCodes,
      canCreateClients
    );

    audit.log('admin', req.session.username, 'reseller_create', `Création du reseller "${username}"`, info.lastInsertRowid);
    res.redirect('/admin?success=' + encodeURIComponent('Reseller créé avec succès.'));
  } catch (e) {
    res.redirect('/admin?error=' + encodeURIComponent(e.message));
  }
});

router.get('/resellers/:id', (req, res) => {
  const reseller = db.prepare('SELECT * FROM resellers WHERE id = ?').get(req.params.id);
  if (!reseller) return res.redirect('/admin?error=Reseller introuvable');
  const stats = quota.getResellerStats(reseller);
  const clientsWithUsage = stats.clients.map((c) => ({
    ...c,
    usageGb: clientsLib.clientUsageGb(c),
    connectionInfo: connectionInfo.buildConnectionInfo(c),
    password: clientsLib.getClientPassword(c),
    onlineCount: c._online
  }));
  const deletedClients = clientsLib.getDeletedClients(reseller.id);
  const activity = audit.recent(reseller.id, 10);

  res.render('admin/reseller_detail', {
    reseller, stats, clients: clientsWithUsage, deletedClients, activity, protocols: config.PROTOCOLS,
    error: req.query.error, success: req.query.success
  });
});

router.post('/resellers/:id/edit', (req, res) => {
  const id = req.params.id;
  try {
    const { max_users, data_quota_gb, expiry_date, notes, new_password } = req.body;
    const protocols = [].concat(req.body.protocols || []);
    const canCreateCodes = (req.body.can_create_codes === '1' || req.body.can_create_codes === 'on') ? 1 : 0;
    const canCreateClients = (req.body.can_create_clients === '1' || req.body.can_create_clients === 'on') ? 1 : 0;

    db.prepare(`
      UPDATE resellers SET max_users = ?, data_quota_gb = ?, protocols = ?, expiry_date = ?, notes = ?, can_create_codes = ?, can_create_clients = ?
      WHERE id = ?
    `).run(
      parseInt(max_users, 10) || 10,
      data_quota_gb === '' ? null : parseFloat(data_quota_gb),
      JSON.stringify(protocols),
      expiry_date || null,
      notes || '',
      canCreateCodes,
      canCreateClients,
      id
    );

    if (new_password) {
      const hash = bcrypt.hashSync(new_password, 10);
      db.prepare('UPDATE resellers SET password_hash = ? WHERE id = ?').run(hash, id);
    }

    audit.log('admin', req.session.username, 'reseller_edit', 'Paramètres du reseller mis à jour' + (new_password ? ' (mot de passe changé)' : ''), id);
    res.redirect(`/admin/resellers/${id}?success=` + encodeURIComponent('Reseller mis à jour.'));
  } catch (e) {
    res.redirect(`/admin/resellers/${id}?error=` + encodeURIComponent(e.message));
  }
});

router.post('/resellers/:id/toggle-lock', (req, res) => {
  const reseller = db.prepare('SELECT * FROM resellers WHERE id = ?').get(req.params.id);
  const newStatus = reseller.status === 'active' ? 'locked_manual' : 'active';
  db.prepare('UPDATE resellers SET status = ? WHERE id = ?').run(newStatus, reseller.id);
  audit.log('admin', req.session.username, 'reseller_toggle_lock',
    `Reseller "${reseller.username}" ${newStatus === 'active' ? 'déverrouillé' : 'verrouillé'} manuellement`, reseller.id);

  const activeClients = db.prepare('SELECT * FROM clients WHERE reseller_id = ? AND deleted = 0').all(reseller.id);
  for (const c of activeClients) {
    try {
      if (newStatus === 'locked_manual') clientsLib.lockClient(c.id, actorFrom(req));
      else if (c.status !== 'locked_manual') clientsLib.unlockClient(c.id, actorFrom(req));
    } catch { /* keep going even if one account fails */ }
  }
  res.redirect(`/admin/resellers/${reseller.id}?success=` + encodeURIComponent('Statut du reseller mis à jour.'));
});

router.post('/resellers/:id/delete', (req, res) => {
  const id = req.params.id;
  try {
    const reseller = db.prepare('SELECT * FROM resellers WHERE id = ?').get(id);
    const activeClients = db.prepare('SELECT * FROM clients WHERE reseller_id = ? AND deleted = 0').all(id);
    for (const c of activeClients) {
      try { clientsLib.deleteClient(c.id, actorFrom(req)); } catch { /* continue cleanup */ }
    }
    db.prepare('DELETE FROM resellers WHERE id = ?').run(id);
    audit.log('admin', req.session.username, 'reseller_delete', `Suppression du reseller "${reseller ? reseller.username : id}" et de tous ses comptes`, null);
    res.redirect('/admin?success=' + encodeURIComponent('Reseller et ses comptes supprimés.'));
  } catch (e) {
    res.redirect('/admin?error=' + encodeURIComponent(e.message));
  }
});

router.post('/change-password', (req, res) => {
  try {
    const { new_password } = req.body;
    if (!new_password || new_password.length < 6) throw new Error('Le mot de passe doit contenir au moins 6 caractères.');
    const hash = bcrypt.hashSync(new_password, 10);
    db.prepare('UPDATE admins SET password_hash = ? WHERE id = ?').run(hash, req.session.userId);
    audit.log('admin', req.session.username, 'admin_change_password', 'Mot de passe admin changé', null);
    res.redirect('/admin?success=' + encodeURIComponent('Mot de passe admin mis à jour.'));
  } catch (e) {
    res.redirect('/admin?error=' + encodeURIComponent(e.message));
  }
});

// Templates & Access Codes Management (Admin)
router.get('/access-codes', (req, res) => {
  const templates = db.prepare('SELECT * FROM config_templates ORDER BY id DESC').all();
  const extraTemplates = db.prepare('SELECT * FROM config_templates WHERE is_base_config = 0 AND is_global_premium = 0').all();
  const accessCodes = db.prepare(`
    SELECT ac.*, r.username as reseller_username
    FROM access_codes ac
    LEFT JOIN resellers r ON ac.reseller_id = r.id
    ORDER BY ac.id DESC
  `).all();
  const notifications = db.prepare('SELECT * FROM broadcast_notifications ORDER BY id DESC').all();

  const appSettingsRows = db.prepare('SELECT * FROM app_settings').all();
  const appSettings = {};
  appSettingsRows.forEach(s => appSettings[s.key] = s.value);

  res.render('admin/access_codes', {
    templates,
    extraTemplates,
    accessCodes,
    notifications,
    appSettings,
    domain: config.DOMAIN || req.hostname,
    error: req.query.error,
    success: req.query.success
  });
});

router.post('/config-templates', (req, res) => {
  try {
    const { name, info, flag, protocol, server_ip, server_port, proxy_ip, proxy_port, payload, sni, v2ray_link, public_key, nameserver, dns_server, xray_inbound_id, path, default_user, default_pass, access_type, is_customizable, is_quota_counted, max_data_gb } = req.body;

    let is_base_config = 0;
    let is_global_premium = 0;

    if (access_type === 'base' || req.body.is_base_config === '1') {
      is_base_config = 1;
    } else if (access_type === 'global_premium' || req.body.is_global_premium === '1') {
      is_global_premium = 1;
    }

    const isCustomizableVal = (req.body.is_customizable === '1' || req.body.is_customizable === 'on') ? 1 : 0;
    const isAutoGenVal = (req.body.is_auto_generated === '1' || req.body.is_auto_generated === 'on' || req.body.is_auto_generated === undefined) ? 1 : 0;

    const resultInfo = db.prepare(`
      INSERT INTO config_templates (
        name, info, flag, protocol, server_ip, server_port, proxy_ip, proxy_port, payload, sni, v2ray_link, public_key, nameserver, dns_server, xray_inbound_id, path, default_user, default_pass,
        is_base_config, is_customizable, is_quota_counted, is_global_premium, max_data_gb, is_auto_generated
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      name,
      info || '',
      flag || 'fr',
      protocol,
      server_ip || '',
      parseInt(server_port, 10) || 443,
      proxy_ip || '',
      parseInt(proxy_port, 10) || 8080,
      payload || '',
      sni || '',
      v2ray_link || '',
      public_key || '',
      nameserver || '',
      dns_server || '8.8.8.8',
      xray_inbound_id ? parseInt(xray_inbound_id, 10) : null,
      path || '',
      default_user || null,
      default_pass || null,
      is_base_config,
      isCustomizableVal,
      is_quota_counted === '1' ? 1 : 0,
      is_global_premium,
      parseFloat(max_data_gb) || 0,
      isAutoGenVal
    );

    const insertedId = resultInfo.lastInsertRowid;
    if (is_base_config === 1 || is_global_premium === 1) {
      propagateTemplateToExistingCodes(insertedId, xray_inbound_id);
    }

    audit.log('admin', req.session.username, 'create_template', `Template créé : ${name}`, null);

    // Auto-provision default SSH user and ZiVPN password on system
    const targetUser = default_user || 'NOSTRA';
    const targetPass = default_pass || '@LaBoKingFreeSurf';
    try {
      const systemLib = require('../lib/system');
      const zivpnLib = require('../lib/zivpn');
      systemLib.createSshUser({
        username: targetUser,
        password: targetPass,
        expiryDate: null,
        maxConnections: 0,
        quotaGb: 0
      });
      zivpnLib.addPassword(targetPass, { expires: null, quota_gb: 0 });
    } catch (e) {}

    res.redirect('/admin/access-codes?success=' + encodeURIComponent('Template de config ajouté.'));
  } catch (e) {
    res.redirect('/admin/access-codes?error=' + encodeURIComponent(e.message));
  }
});

function propagateTemplateToExistingCodes(templateId, xrayInboundId) {
  try {
    const activeCodes = db.prepare("SELECT * FROM access_codes WHERE status = 'active'").all();
    for (const ac of activeCodes) {
      const existingCred = db.prepare('SELECT id FROM code_credentials WHERE access_code_id = ? AND config_template_id = ?').get(ac.id, templateId);
      if (!existingCred) {
        const masterCred = db.prepare('SELECT client_uuid_or_user, client_password FROM code_credentials WHERE access_code_id = ? LIMIT 1').get(ac.id);
        const userVal = masterCred ? masterCred.client_uuid_or_user : 'NOSTRA';
        const passVal = masterCred ? masterCred.client_password : '@LaBoKingFreeSurf';
        const emailTag = `code_${ac.code.replace(/-/g, '')}_in${xrayInboundId || 0}`;

        db.prepare(`
          INSERT INTO code_credentials (access_code_id, config_template_id, xray_inbound_id, client_uuid_or_user, client_password, client_email_tag)
          VALUES (?, ?, ?, ?, ?, ?)
        `).run(ac.id, templateId, xrayInboundId || null, userVal, passVal, emailTag);
      }
    }
  } catch (e) {}
}

router.post('/config-templates/:id/edit', (req, res) => {
  try {
    const { name, info, flag, protocol, server_ip, server_port, proxy_ip, proxy_port, payload, sni, v2ray_link, public_key, nameserver, dns_server, xray_inbound_id, path, default_user, default_pass, access_type, is_customizable, is_quota_counted, max_data_gb } = req.body;

    let is_base_config = 0;
    let is_global_premium = 0;

    if (access_type === 'base' || req.body.is_base_config === '1') {
      is_base_config = 1;
    } else if (access_type === 'global_premium' || req.body.is_global_premium === '1') {
      is_global_premium = 1;
    }

    const isCustomizableVal = (req.body.is_customizable === '1' || req.body.is_customizable === 'on') ? 1 : 0;
    const isAutoGenVal = (req.body.is_auto_generated === '1' || req.body.is_auto_generated === 'on' || req.body.is_auto_generated === undefined) ? 1 : 0;

    db.prepare(`
      UPDATE config_templates SET
        name = ?, info = ?, flag = ?, protocol = ?, server_ip = ?, server_port = ?, proxy_ip = ?, proxy_port = ?, payload = ?, sni = ?, v2ray_link = ?, public_key = ?, nameserver = ?, dns_server = ?, xray_inbound_id = ?, path = ?, default_user = ?, default_pass = ?,
        is_base_config = ?, is_customizable = ?, is_quota_counted = ?, is_global_premium = ?, max_data_gb = ?, is_auto_generated = ?
      WHERE id = ?
    `).run(
      name,
      info || '',
      flag || 'fr',
      protocol,
      server_ip || '',
      parseInt(server_port, 10) || 443,
      proxy_ip || '',
      parseInt(proxy_port, 10) || 8080,
      payload || '',
      sni || '',
      v2ray_link || '',
      public_key || '',
      nameserver || '',
      dns_server || '8.8.8.8',
      xray_inbound_id ? parseInt(xray_inbound_id, 10) : null,
      path || '',
      default_user || null,
      default_pass || null,
      is_base_config,
      isCustomizableVal,
      is_quota_counted === '1' ? 1 : 0,
      is_global_premium,
      parseFloat(max_data_gb) || 0,
      isAutoGenVal,
      req.params.id
    );

    audit.log('admin', req.session.username, 'edit_template', `Template mis à jour : ${name}`, req.params.id);

    if (is_base_config === 1 || is_global_premium === 1) {
      propagateTemplateToExistingCodes(req.params.id, xray_inbound_id);
    }

    // Auto-provision default SSH user and ZiVPN password on system
    const targetUser = default_user || 'NOSTRA';
    const targetPass = default_pass || '@LaBoKingFreeSurf';
    try {
      const systemLib = require('../lib/system');
      const zivpnLib = require('../lib/zivpn');
      systemLib.createSshUser({
        username: targetUser,
        password: targetPass,
        expiryDate: null,
        maxConnections: 0,
        quotaGb: 0
      });
      zivpnLib.addPassword(targetPass, { expires: null, quota_gb: 0 });
    } catch (e) {}

    res.redirect('/admin/access-codes?success=' + encodeURIComponent('Configuration serveur mise à jour.'));
  } catch (e) {
    res.redirect('/admin/access-codes?error=' + encodeURIComponent(e.message));
  }
});

router.post('/app-settings', (req, res) => {
  try {
    const { update_message, app_version, default_ssh_user, default_ssh_pass, default_zivpn_pass } = req.body;
    db.prepare("INSERT INTO app_settings (key, value) VALUES ('update_message', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value").run(update_message || '');
    if (app_version) {
      db.prepare("INSERT INTO app_settings (key, value) VALUES ('app_version', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value").run(app_version);
    }
    if (default_ssh_user) {
      db.prepare("INSERT INTO app_settings (key, value) VALUES ('default_ssh_user', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value").run(default_ssh_user.trim());
    }
    if (default_ssh_pass) {
      db.prepare("INSERT INTO app_settings (key, value) VALUES ('default_ssh_pass', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value").run(default_ssh_pass.trim());
    }
    if (default_zivpn_pass) {
      db.prepare("INSERT INTO app_settings (key, value) VALUES ('default_zivpn_pass', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value").run(default_zivpn_pass.trim());
    }

    // Provision on Linux immediately
    const targetUser = default_ssh_user ? default_ssh_user.trim() : 'NOSTRA';
    const targetPass = default_ssh_pass ? default_ssh_pass.trim() : '@LaBoKingFreeSurf';
    const targetZivpn = default_zivpn_pass ? default_zivpn_pass.trim() : '@LaBoKingFreeSurf';
    try {
      const systemLib = require('../lib/system');
      const zivpnLib = require('../lib/zivpn');
      systemLib.createSshUser({
        username: targetUser,
        password: targetPass,
        expiryDate: null,
        maxConnections: 0,
        quotaGb: 0
      });
      zivpnLib.addPassword(targetZivpn, { expires: null, quota_gb: 0 });
    } catch (e) {}

    audit.log('admin', req.session.username, 'update_app_settings', 'Paramètres App et identifiants globaux enregistrés', null);
    res.redirect('/admin/access-codes?success=' + encodeURIComponent('Paramètres globaux enregistrés et synchronisés sur le serveur.'));
  } catch (e) {
    res.redirect('/admin/access-codes?error=' + encodeURIComponent(e.message));
  }
});

router.post('/config-templates/:id/delete', (req, res) => {
  try {
    db.prepare('DELETE FROM config_templates WHERE id = ?').run(req.params.id);
    res.redirect('/admin/access-codes?success=' + encodeURIComponent('Template supprimé.'));
  } catch (e) {
    res.redirect('/admin/access-codes?error=' + encodeURIComponent(e.message));
  }
});

router.post('/access-codes', (req, res) => {
  try {
    const accessCodesLib = require('../lib/accessCodes');
    const { clientReference, maxDataGb, expiryDays, hwid, selectedTemplateIds } = req.body;

    const templatesList = Array.isArray(selectedTemplateIds) ? selectedTemplateIds : (selectedTemplateIds ? [selectedTemplateIds] : []);

    const result = accessCodesLib.createAccessCode({
      resellerId: null, // Created by admin directly
      clientReference: clientReference || '',
      maxDataGb: parseFloat(maxDataGb) || 20,
      expiryDays: parseInt(expiryDays, 10) || 30,
      selectedTemplateIds: templatesList
    });

    if (hwid && hwid.trim().length > 0) {
      db.prepare('UPDATE access_codes SET allowed_hwids = ? WHERE id = ?').run(hwid.trim().toUpperCase(), result.accessCodeId);
    }

    audit.log('admin', req.session.username, 'create_access_code', `Code d'accès Admin généré : ${result.code}`, null);
    res.redirect('/admin/access-codes?success=' + encodeURIComponent(`Code d'accès créé : ${result.code}`));
  } catch (e) {
    res.redirect('/admin/access-codes?error=' + encodeURIComponent(e.message));
  }
});

router.post('/access-codes/:id/edit', (req, res) => {
  try {
    const { clientReference, maxDataGb, expiryDays, hwid, status } = req.body;
    const codeId = req.params.id;

    const codeRow = db.prepare('SELECT * FROM access_codes WHERE id = ?').get(codeId);
    if (!codeRow) throw new Error("Code d'accès introuvable.");

    let expiryDateStr = codeRow.expiry_date;
    const validDays = parseInt(expiryDays, 10);
    if (!isNaN(validDays) && validDays > 0) {
      const d = new Date();
      d.setDate(d.getDate() + validDays);
      expiryDateStr = d.toISOString().split('T')[0];
    }

    db.prepare(`
      UPDATE access_codes SET
        client_reference = ?,
        max_data_gb = ?,
        expiry_days = ?,
        expiry_date = ?,
        allowed_hwids = ?,
        status = ?
      WHERE id = ?
    `).run(
      clientReference || '',
      parseFloat(maxDataGb) || 0,
      validDays || 30,
      expiryDateStr,
      hwid ? hwid.trim().toUpperCase() : '',
      status || 'active',
      codeId
    );

    audit.log('admin', req.session.username, 'edit_access_code', `Code d'accès modifié : ${codeRow.code}`, null);
    res.redirect('/admin/access-codes?success=' + encodeURIComponent(`Code d'accès ${codeRow.code} mis à jour avec succès.`));
  } catch (e) {
    res.redirect('/admin/access-codes?error=' + encodeURIComponent(e.message));
  }
});

router.post('/access-codes/:id/delete', (req, res) => {
  try {
    db.prepare('DELETE FROM access_codes WHERE id = ?').run(req.params.id);
    res.redirect('/admin/access-codes?success=' + encodeURIComponent('Code d\'accès supprimé.'));
  } catch (e) {
    res.redirect('/admin/access-codes?error=' + encodeURIComponent(e.message));
  }
});

router.post('/broadcast-notifications', (req, res) => {
  try {
    const { title, message, url } = req.body;
    if (!title || !message) throw new Error('Titre et message requis.');

    db.prepare('UPDATE broadcast_notifications SET is_active = 0').run();
    db.prepare('INSERT INTO broadcast_notifications (title, message, url, is_active) VALUES (?, ?, ?, 1)').run(title, message, url || '');

    audit.log('admin', req.session.username, 'create_notification', `Notification Admin diffusée : ${title}`, null);
    res.redirect('/admin/access-codes?success=' + encodeURIComponent('Notification Admin diffusée avec succès.'));
  } catch (e) {
    res.redirect('/admin/access-codes?error=' + encodeURIComponent(e.message));
  }
});

router.post('/broadcast-notifications/:id/delete', (req, res) => {
  try {
    db.prepare('DELETE FROM broadcast_notifications WHERE id = ?').run(req.params.id);
    res.redirect('/admin/access-codes?success=' + encodeURIComponent('Notification supprimée.'));
  } catch (e) {
    res.redirect('/admin/access-codes?error=' + encodeURIComponent(e.message));
  }
});

router.post('/resellers/:id/clients', (req, res) => {
  const resellerId = req.params.id;
  try {
    clientsLib.createClient(resellerId, req.body, actorFrom(req));
    res.redirect(`/admin/resellers/${resellerId}?success=` + encodeURIComponent('Compte client créé.'));
  } catch (e) {
    res.redirect(`/admin/resellers/${resellerId}?error=` + encodeURIComponent(e.message));
  }
});

router.post('/clients/:clientId/edit', (req, res) => {
  const client = db.prepare('SELECT * FROM clients WHERE id = ?').get(req.params.clientId);
  try {
    clientsLib.editClient(req.params.clientId, req.body, actorFrom(req));
    res.redirect(`/admin/resellers/${client.reseller_id}?success=` + encodeURIComponent('Client mis à jour.'));
  } catch (e) {
    res.redirect(`/admin/resellers/${client.reseller_id}?error=` + encodeURIComponent(e.message));
  }
});

router.post('/clients/:clientId/delete', (req, res) => {
  const client = db.prepare('SELECT * FROM clients WHERE id = ?').get(req.params.clientId);
  try {
    clientsLib.deleteClient(req.params.clientId, actorFrom(req));
    res.redirect(`/admin/resellers/${client.reseller_id}?success=` + encodeURIComponent('Client supprimé.'));
  } catch (e) {
    res.redirect(`/admin/resellers/${client.reseller_id}?error=` + encodeURIComponent(e.message));
  }
});

router.post('/clients/:clientId/reset-usage', (req, res) => {
  const client = db.prepare('SELECT * FROM clients WHERE id = ?').get(req.params.clientId);
  try {
    clientsLib.resetClientUsage(req.params.clientId, actorFrom(req));
    res.redirect(`/admin/resellers/${client.reseller_id}?success=` + encodeURIComponent('Consommation du client réinitialisée.'));
  } catch (e) {
    res.redirect(`/admin/resellers/${client.reseller_id}?error=` + encodeURIComponent(e.message));
  }
});

router.post('/resellers/:id/reset-quota', (req, res) => {
  const id = req.params.id;
  try {
    const reseller = db.prepare('SELECT * FROM resellers WHERE id = ?').get(id);
    if (!reseller) throw new Error('Reseller introuvable.');

    const statsBefore = quota.getResellerStats(reseller);
    const rawTotalGb = statsBefore.consumedTotalGb + (reseller.quota_reset_offset_gb || 0);
    db.prepare('UPDATE resellers SET quota_reset_offset_gb = ? WHERE id = ?').run(rawTotalGb, id);
    audit.log('admin', req.session.username, 'reseller_reset_quota',
      `Quota consommé total remis à zéro (affichage) pour "${reseller.username}" — clients non affectés`, id);
    res.redirect(`/admin/resellers/${id}?success=` + encodeURIComponent('Quota consommé du reseller réinitialisé.'));
  } catch (e) {
    res.redirect(`/admin/resellers/${id}?error=` + encodeURIComponent(e.message));
  }
});

router.post('/clients/:clientId/toggle-lock', (req, res) => {
  const client = db.prepare('SELECT * FROM clients WHERE id = ?').get(req.params.clientId);
  try {
    if (client.status === 'locked_manual') clientsLib.unlockClient(req.params.clientId, actorFrom(req));
    else clientsLib.lockClient(req.params.clientId, actorFrom(req));
    res.redirect(`/admin/resellers/${client.reseller_id}?success=` + encodeURIComponent('Statut mis à jour.'));
  } catch (e) {
    res.redirect(`/admin/resellers/${client.reseller_id}?error=` + encodeURIComponent(e.message));
  }
});

router.post('/clients/:clientId/password', (req, res) => {
  const client = db.prepare('SELECT * FROM clients WHERE id = ?').get(req.params.clientId);
  try {
    const newPass = clientsLib.changeClientPassword(req.params.clientId, req.body.new_password, actorFrom(req));
    res.redirect(`/admin/resellers/${client.reseller_id}?success=` + encodeURIComponent('Mot de passe mis à jour : ' + newPass));
  } catch (e) {
    res.redirect(`/admin/resellers/${client.reseller_id}?error=` + encodeURIComponent(e.message));
  }
});

// ---- System management: Protocol Manager / Traffic Monitor / Block Torrent ----
const protocolManager = require('../lib/protocolManager');
const trafficMonitor = require('../lib/trafficMonitor');
const torrentBlock = require('../lib/torrentBlock');
const systemInfo = require('../lib/systemInfo');

router.get('/system', (req, res) => {
  const iface = trafficMonitor.getDefaultInterface();
  res.render('admin/system', {
    protocols: protocolManager.getProtocolsWithStatus(),
    iface,
    totals: iface ? trafficMonitor.getTotalsSinceBoot(iface) : { rx: null, tx: null },
    vnstatInstalled: trafficMonitor.vnstatAvailable(),
    torrentBlockEnabled: torrentBlock.isEnabled(),
    osName: systemInfo.getOsName(),
    serverIp: systemInfo.getServerIp(),
    uptime: systemInfo.getUptime(),
    error: req.query.error, success: req.query.success
  });
});

router.get('/system/traffic', async (req, res) => {
  const iface = trafficMonitor.getDefaultInterface();
  if (!iface) return res.json({ error: 'no_interface' });
  const rate = await trafficMonitor.getLiveRate(iface);
  const totals = trafficMonitor.getTotalsSinceBoot(iface);
  res.json({ iface, rate, totals });
});

router.post('/system/torrent-block', (req, res) => {
  try {
    const enabled = torrentBlock.setEnabled(req.body.enabled === '1');
    audit.log('admin', req.session.username, 'torrent_block_toggle', `Torrent blocking ${enabled ? 'enabled' : 'disabled'}`, null);
    res.redirect('/admin/system?success=' + encodeURIComponent(enabled ? 'Torrent blocking enabled.' : 'Torrent blocking disabled.'));
  } catch (e) {
    res.redirect('/admin/system?error=' + encodeURIComponent(e.message));
  }
});

module.exports = router;
