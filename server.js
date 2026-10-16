'use strict';
// VOGT ELECTIONS - serveur (base Turso / libSQL)
const express = require('express');
const cookieParser = require('cookie-parser');
const nodemailer = require('nodemailer');
const { createClient } = require('@libsql/client');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

try { fs.readFileSync(path.join(__dirname, '.env'), 'utf8').split('\n').forEach(l => {
  const m = l.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*)\s*$/); if (m && !(m[1] in process.env)) process.env[m[1]] = m[2].replace(/^["']|["']$/g, '');
}); } catch (e) { /* pas de .env */ }

const C = {
  port: +process.env.PORT || 3000,
  secret: process.env.SECRET || 'CHANGE_ME_' + crypto.randomBytes(8).toString('hex'),
  bdeKeys: (process.env.BDE_KEYS || 'bde-demo').split(',').map(s => s.trim()).filter(Boolean),
  ghostKey: process.env.GHOST_KEY || 'ghost-demo',
  eligible: +process.env.ELIGIBLE_VOTERS || 1000,
  maxChanges: +process.env.MAX_CHANGES || 3,
  allowedDomain: (process.env.ALLOWED_DOMAIN || '').toLowerCase(),
  secure: process.env.COOKIE_SECURE === '1',
  adminBreakdown: process.env.ADMIN_SHOW_BREAKDOWN === '1',
  publicCounts: process.env.SHOW_PUBLIC_COUNTS === '1',
  devShowCode: process.env.DEV_SHOW_CODE === '1',
  brevoKey: (process.env.BREVO_API_KEY || '').trim(),
  brevoUrl: process.env.BREVO_API_URL || 'https://api.brevo.com/v3/smtp/email',
  from: process.env.MAIL_FROM || 'VOGT ELECTIONS <no-reply@vogt-elections.local>',
};
const smtpOK = !!process.env.SMTP_HOST;
const mailer = smtpOK && !process.env.BREVO_API_KEY ? nodemailer.createTransport({
  host: process.env.SMTP_HOST, port: +process.env.SMTP_PORT || 587, secure: process.env.SMTP_SECURE === '1', connectionTimeout: 10000, greetingTimeout: 10000, socketTimeout: 15000,
  auth: process.env.SMTP_USER ? { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS } : undefined,
}) : null;

// ---------- base de données : Turso (distant) ou fichier local pour les tests ----------
const client = createClient({ url: process.env.TURSO_DATABASE_URL || 'file:' + path.join(__dirname, 'vogt.db'), authToken: process.env.TURSO_AUTH_TOKEN });
const wrap = (x) => ({
  async all(sql, args = []) { const r = await x.execute({ sql, args }); return r.rows.map(row => ({ ...row })); },
  async get(sql, args = []) { return (await this.all(sql, args))[0]; },
  async run(sql, args = []) { const r = await x.execute({ sql, args }); return { id: Number(r.lastInsertRowid), changes: r.rowsAffected }; },
});
const db = wrap(client);
async function tx(fn) { const t = await client.transaction('write'); try { const r = await fn(wrap(t)); await t.commit(); return r; } catch (e) { await t.rollback(); throw e; } finally { t.close(); } }
const count = async (d, sql, args = []) => (await d.get(sql, args)).n;

const SCHEMA = `
CREATE TABLE IF NOT EXISTS otp (email_h TEXT PRIMARY KEY, code_h TEXT, exp INTEGER, tries INTEGER DEFAULT 0, sent INTEGER);
CREATE TABLE IF NOT EXISTS sessions (tok TEXT PRIMARY KEY, kind TEXT, email_h TEXT, label TEXT, exp INTEGER);
CREATE TABLE IF NOT EXISTS elections (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, reg_open INTEGER, reg_close INTEGER, vote_open INTEGER, vote_close INTEGER, eligible INTEGER, created INTEGER, by TEXT);
CREATE TABLE IF NOT EXISTS candidates (id INTEGER PRIMARY KEY AUTOINCREMENT, election_id INTEGER, email_h TEXT, name TEXT, role TEXT, klass TEXT, bio TEXT, promises TEXT, qa TEXT,
  photo TEXT, video_pitch TEXT, video_full TEXT, pitch_dur REAL, full_dur REAL, dur_checked INTEGER DEFAULT 0, status TEXT DEFAULT 'pending', note TEXT, created INTEGER, updated INTEGER, UNIQUE(election_id, email_h));
CREATE TABLE IF NOT EXISTS photos (candidate_id INTEGER PRIMARY KEY, data BLOB);
CREATE TABLE IF NOT EXISTS votes (id INTEGER PRIMARY KEY AUTOINCREMENT, election_id INTEGER, email_h TEXT, label TEXT, candidate_id INTEGER, changes INTEGER DEFAULT 0, status TEXT DEFAULT 'valid', reason TEXT,
  fp TEXT, device_id TEXT, ip TEXT, ua TEXT, created INTEGER, updated INTEGER, UNIQUE(election_id, email_h));
CREATE INDEX IF NOT EXISTS v_fp ON votes(fp); CREATE INDEX IF NOT EXISTS v_dev ON votes(device_id); CREATE INDEX IF NOT EXISTS v_ip ON votes(ip);
CREATE TABLE IF NOT EXISTS quarantine (id INTEGER PRIMARY KEY AUTOINCREMENT, election_id INTEGER, fp TEXT, device_id TEXT, ip TEXT, created INTEGER, note TEXT);
CREATE TABLE IF NOT EXISTS feed (id INTEGER PRIMARY KEY AUTOINCREMENT, election_id INTEGER, ts INTEGER, kind TEXT);
CREATE TABLE IF NOT EXISTS audit (id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER, actor TEXT, action TEXT, target TEXT);`;

const hmac = (s) => crypto.createHmac('sha256', C.secret).update(String(s)).digest('hex');
const now = () => Date.now();
const rnd = (n) => crypto.randomBytes(n).toString('hex');
const safeEq = (a, b) => crypto.timingSafeEqual(Buffer.from(hmac(a)), Buffer.from(hmac(b)));

function normEmail(e) {
  e = String(e || '').trim().toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(e) || e.length > 120) return null;
  let [l, d] = e.split('@');
  l = l.split('+')[0];
  if (d === 'gmail.com' || d === 'googlemail.com') { l = l.replace(/\./g, ''); d = 'gmail.com'; }
  if (C.allowedDomain && d !== C.allowedDomain) return { bad: 'domain' };
  return { norm: l + '@' + d, local: l, raw: e };
}
const labelOf = (local) => /^\d{2}[a-z]\d{3,5}$/i.test(local) ? local.toUpperCase() : local.slice(0, 2) + '***' + local.slice(-1);
const hits = new Map();
function limit(key, max, ms) {
  const t = now(), a = (hits.get(key) || []).filter(x => t - x < ms);
  if (a.length >= max) { hits.set(key, a); return false; }
  a.push(t); hits.set(key, a); return true;
}
setInterval(() => { const t = now(); for (const [k, a] of hits) if (!a.some(x => t - x < 3600e3)) hits.delete(k); }, 600e3).unref();

const audit = (actor, action, target) => db.run('INSERT INTO audit(ts,actor,action,target) VALUES(?,?,?,?)', [now(), actor, action, target || '']);
const feed = (d, eid, kind) => d.run('INSERT INTO feed(election_id,ts,kind) VALUES(?,?,?)', [eid, now(), kind]);

async function init() {
  const cols = await db.all('PRAGMA table_info(votes)');
  if (cols.length && !cols.some(c => c.name === 'election_id')) await client.executeMultiple('DROP TABLE votes; DROP TABLE quarantine; DROP TABLE feed;');
  await client.executeMultiple(SCHEMA);
  if (process.env.SEED_DEMO === '1' && !(await db.get('SELECT 1 AS x FROM elections'))) {
    const t = now(), D = 864e5;
    const eid = (await db.run('INSERT INTO elections(name,reg_open,reg_close,vote_open,vote_close,eligible,created,by) VALUES(?,?,?,?,?,?,?,?)', ['VOGT ELECTIONS 2026 (démo)', t - 14 * D, t - D, t - 3600e3, t + 7 * D, C.eligible, t, 'seed'])).id;
    for (const c of JSON.parse(fs.readFileSync(path.join(__dirname, 'candidates.json'), 'utf8')))
      await db.run('INSERT INTO candidates(election_id,name,role,klass,bio,promises,qa,photo,video_pitch,video_full,pitch_dur,full_dur,dur_checked,status,created,updated) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
        [eid, c.name, c.role, c.klass, c.bio, JSON.stringify(c.promises), JSON.stringify(c.qa), c.photo, c.videoPitch, c.videoFull, 30, c.videoFull ? 134 : null, 1, 'approved', t, t]);
  }
}

// ---------- élections ----------
const election = (id) => db.get('SELECT * FROM elections WHERE id=?', [+id]);
function phase(e, t = now()) {
  if (t >= e.vote_close) return 'closed';
  if (t >= e.vote_open) return 'voting';
  if (t >= e.reg_open && t < e.reg_close) return 'registration';
  return t < e.reg_open ? 'upcoming' : 'between';
}
const fmtDur = (s) => s ? Math.floor(s / 60) + ':' + String(Math.round(s % 60)).padStart(2, '0') : null;
const vidOK = (f) => !!f && (/^(yt|drive):/.test(f) || fs.existsSync(path.join(__dirname, 'public', f.replace(/^\//, ''))));
const pubCand = (c) => ({ id: c.id, name: c.name, role: c.role, klass: c.klass, bio: c.bio, promises: JSON.parse(c.promises || '[]'), qa: JSON.parse(c.qa || '[]'), photo: c.photo,
  videoPitch: c.video_pitch, videoFull: c.video_full, pitchDur: fmtDur(c.pitch_dur), fullDur: fmtDur(c.full_dur), videoPitchOk: vidOK(c.video_pitch), videoFullOk: vidOK(c.video_full) });
const approved = (eid) => db.all("SELECT * FROM candidates WHERE election_id=? AND status='approved' ORDER BY id", [eid]);
const elShape = (e) => ({ id: e.id, name: e.name, reg_open: e.reg_open, reg_close: e.reg_close, vote_open: e.vote_open, vote_close: e.vote_close, eligible: e.eligible, phase: phase(e) });
function parseElection(b) {
  const name = String(b.name || '').trim();
  const d = ['reg_open', 'reg_close', 'vote_open', 'vote_close'].map(k => Math.floor(+b[k]));
  if (name.length < 3 || name.length > 80) return { error: 'Nom : 3 à 80 caractères.' };
  if (d.some(x => !Number.isFinite(x) || x < 1e12)) return { error: 'Dates invalides.' };
  if (!(d[0] < d[1] && d[1] <= d[2] && d[2] < d[3])) return { error: 'Ordre attendu : ouverture des candidatures < fermeture des candidatures ≤ ouverture du vote < fermeture du vote.' };
  return { name, reg_open: d[0], reg_close: d[1], vote_open: d[2], vote_close: d[3], eligible: Math.max(1, Math.floor(+b.eligible) || C.eligible) };
}

const app = express();
const ah = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(e => { console.error(e); if (!res.headersSent) res.status(500).json({ error: 'Erreur serveur. Réessaie.' }); });
app.set('trust proxy', process.env.TRUST_PROXY === '1');
app.disable('x-powered-by');
app.use(express.json({ limit: '400kb' }));
app.use(cookieParser());
app.use((req, res, next) => { res.set({ 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer', 'X-Frame-Options': 'SAMEORIGIN' }); next(); });
app.use(express.static(path.join(__dirname, 'public'), { extensions: ['html'] }));
app.get('/api/health', (q, r) => r.json({ ok: true }));
app.get('/candidat', (q, r) => r.sendFile(path.join(__dirname, 'public/index.html')));
app.get('/admin', (q, r) => r.sendFile(path.join(__dirname, 'public/admin.html')));
app.get('/ghost', (q, r) => { r.set('X-Robots-Tag', 'noindex'); r.sendFile(path.join(__dirname, 'public/ghost.html')); });
app.get('/photo/:id', ah(async (req, res) => {
  const p = await db.get('SELECT data FROM photos WHERE candidate_id=?', [+req.params.id]);
  if (!p) return res.status(404).end();
  res.set({ 'Content-Type': 'image/jpeg', 'Cache-Control': 'public, max-age=86400' }).send(Buffer.from(p.data));
}));

const cname = (kind) => kind === 'student' ? 'vs' : kind === 'admin' ? 'va' : 'vg';
const session = async (req, kind) => { const tok = req.cookies[cname(kind)]; return tok ? (await db.get('SELECT * FROM sessions WHERE tok=? AND kind=? AND exp>?', [hmac(tok), kind, now()])) || null : null; };
async function newSession(res, kind, email_h, label, hours) {
  const tok = rnd(24);
  await db.run('INSERT INTO sessions VALUES(?,?,?,?,?)', [hmac(tok), kind, email_h || null, label || null, now() + hours * 3600e3]);
  res.cookie(cname(kind), tok, { httpOnly: true, sameSite: 'strict', secure: C.secure, maxAge: hours * 3600e3, path: '/' });
}
const needStudent = ah(async (q, r, n) => { const s = await session(q, 'student'); if (!s) return r.status(401).json({ error: 'Session expirée. Recommence avec ton email.' }); q.s = s; n(); });
const needAdmin = ah(async (q, r, n) => { const g = await session(q, 'ghost'); if (!g && !(await session(q, 'admin'))) return r.status(401).json({ error: 'auth' }); q.role = g ? 'ghost' : 'bde'; n(); });
const needGhost = ah(async (q, r, n) => { if (!(await session(q, 'ghost'))) return r.status(401).json({ error: 'auth' }); n(); });


// ---------- envoi du code : API Brevo (HTTPS, marche sur l'offre gratuite de Render) ou SMTP ----------
function parseFrom(f) { const m = String(f).match(/^\s*"?([^"<]*?)"?\s*<([^>]+)>\s*$/); return m ? { name: m[1].trim() || 'VOGT ELECTIONS', email: m[2].trim() } : { name: 'VOGT ELECTIONS', email: String(f).trim() }; }
const mailHtml = (code) => `<div style="font-family:Arial,sans-serif;background:#FBF4E6;padding:28px"><div style="max-width:380px;margin:auto;background:#fff;border-radius:18px;padding:28px;text-align:center"><div style="color:#E8590C;font-size:12px;letter-spacing:1px">VOGT HIGH TECH 2026</div><h2 style="margin:14px 0 6px">Ton code</h2><div style="font-size:44px;font-weight:700;letter-spacing:10px;color:#E8590C;margin:14px 0">${code}</div><p style="color:#666;font-size:13px">Valable 10 minutes. Ne le partage avec personne.</p></div></div>`;
async function sendCode(to, code) {
  const subject = 'Ton code VOGT : ' + code, text = `Ton code : ${code}\n\nIl est valable 10 minutes. Ne le partage avec personne.`;
  if (C.brevoKey) {
    const ctl = new AbortController(), timer = setTimeout(() => ctl.abort(), 15000);
    try {
      const r = await fetch(C.brevoUrl, { method: 'POST', signal: ctl.signal, headers: { 'api-key': C.brevoKey, 'content-type': 'application/json', accept: 'application/json' },
        body: JSON.stringify({ sender: parseFrom(C.from), to: [{ email: to }], subject, htmlContent: mailHtml(code), textContent: text }) });
      if (!r.ok) throw new Error('Brevo API ' + r.status + ' ' + (await r.text()).slice(0, 300));
    } finally { clearTimeout(timer); }
  } else if (mailer) {
    await mailer.sendMail({ from: C.from, to, subject, text, html: mailHtml(code) });
  } else console.log(`[DEV] code pour ${to} : ${code}  (aucun service d'email configuré, rien n'est envoyé)`);
}

// ---------- email OTP ----------
app.post('/api/otp/request', ah(async (req, res) => {
  const e = normEmail(req.body.email);
  if (!e) return res.status(400).json({ error: 'Email invalide.' });
  if (e.bad) return res.status(400).json({ error: 'Utilise ton email étudiant (@' + C.allowedDomain + ').' });
  if (!limit('ip:' + req.ip, 12, 600e3) || !limit('em:' + e.norm, 3, 600e3)) return res.status(429).json({ error: 'Trop de demandes. Réessaie dans quelques minutes.' });
  const eh = hmac(e.norm), code = String(crypto.randomInt(0, 10000)).padStart(4, '0');
  await db.run('INSERT OR REPLACE INTO otp VALUES(?,?,?,0,?)', [eh, hmac(eh + ':' + code), now() + 10 * 60e3, now()]);
  try { await sendCode(e.raw, code); }
  catch (err) { console.error('EMAIL:', err.message); return res.status(502).json({ error: "L'email n'a pas pu être envoyé. Réessaie dans une minute." }); }
  res.json({ ok: true, ...(C.devShowCode && !mailer && !C.brevoKey ? { devCode: code } : {}) });
}));
app.post('/api/otp/verify', ah(async (req, res) => {
  const e = normEmail(req.body.email), code = String(req.body.code || '');
  if (!e || e.bad || !/^\d{4}$/.test(code)) return res.status(400).json({ error: 'Code invalide.' });
  if (!limit('vip:' + req.ip, 30, 600e3)) return res.status(429).json({ error: 'Trop de tentatives.' });
  const eh = hmac(e.norm), o = await db.get('SELECT * FROM otp WHERE email_h=?', [eh]);
  if (!o || o.exp < now()) return res.status(400).json({ error: 'Code expiré. Demande un nouveau code.' });
  if (o.tries >= 5) { await db.run('DELETE FROM otp WHERE email_h=?', [eh]); return res.status(429).json({ error: "Trop d'essais. Demande un nouveau code." }); }
  if (!crypto.timingSafeEqual(Buffer.from(o.code_h), Buffer.from(hmac(eh + ':' + code)))) { await db.run('UPDATE otp SET tries=tries+1 WHERE email_h=?', [eh]); return res.status(400).json({ error: 'Mauvais code.' }); }
  await db.run('DELETE FROM otp WHERE email_h=?', [eh]);
  await newSession(res, 'student', eh, labelOf(e.local), 6);
  res.json({ ok: true });
}));
app.get('/api/me', ah(async (req, res) => res.json({ in: !!(await session(req, 'student')) })));
app.post('/api/logout', (req, res) => { ['vs', 'va', 'vg'].forEach(n => res.clearCookie(n)); res.json({ ok: true }); });

// ---------- appareil ----------
const cleanFp = (s) => (typeof s === 'string' && /^[a-f0-9]{16,128}$/.test(s)) ? s : null;
const cleanDev = (s) => (typeof s === 'string' && /^[a-zA-Z0-9-]{16,64}$/.test(s)) ? s : null;
function orClause(fp, dev) { const w = [], a = []; if (fp) { w.push('fp=?'); a.push(fp); } if (dev) { w.push('device_id=?'); a.push(dev); } return [w.join(' OR '), a]; }
async function deviceHit(d, eid, fp, dev, eh) { const [w, a] = orClause(fp, dev); return w ? d.all(`SELECT * FROM votes WHERE election_id=? AND (${w}) AND email_h<>?`, [eid, ...a, eh]) : []; }
async function quarantined(d, eid, fp, dev) { const [w, a] = orClause(fp, dev); return w ? !!(await d.get(`SELECT 1 AS x FROM quarantine WHERE election_id=? AND (${w})`, [eid, ...a])) : false; }

async function myState(eid, eh) {
  const v = await db.get('SELECT * FROM votes WHERE election_id=? AND email_h=?', [eid, eh]);
  if (!v) return { voted: false };
  const c = await db.get('SELECT name FROM candidates WHERE id=?', [v.candidate_id]);
  return { voted: true, candidateId: v.candidate_id, candidateName: c ? c.name : '?', changesLeft: Math.max(0, C.maxChanges - v.changes), status: v.status };
}
const myCand = async (eid, eh) => (await db.get('SELECT status,note,name FROM candidates WHERE election_id=? AND email_h=?', [eid, eh])) || null;

app.get('/api/elections', needStudent, ah(async (req, res) => {
  const list = await db.all('SELECT * FROM elections ORDER BY vote_open DESC');
  res.json({ label: req.s.label, elections: await Promise.all(list.map(async e => ({ ...elShape(e),
    voted: !!(await db.get('SELECT 1 AS x FROM votes WHERE election_id=? AND email_h=?', [e.id, req.s.email_h])), candidacy: ((await myCand(e.id, req.s.email_h)) || {}).status || null }))) });
}));
app.get('/api/elections/:id', needStudent, ah(async (req, res) => {
  const e = await election(req.params.id); if (!e) return res.status(404).json({ error: 'Élection introuvable.' });
  const counts = (C.publicCounts || phase(e) === 'closed') ? Object.fromEntries((await db.all("SELECT candidate_id c,COUNT(*) n FROM votes WHERE election_id=? AND status='valid' GROUP BY candidate_id", [e.id])).map(r => [r.c, r.n])) : null;
  res.json({ election: elShape(e), maxChanges: C.maxChanges, me: await myState(e.id, req.s.email_h), myCandidacy: await myCand(e.id, req.s.email_h),
    candidates: (await approved(e.id)).map(c => ({ ...pubCand(c), votes: counts ? (counts[c.id] || 0) : undefined })) });
}));

// ---------- vote ----------
app.post('/api/vote', needStudent, ah(async (req, res) => {
  const e = await election(req.body.electionId);
  if (!e) return res.status(400).json({ error: 'Élection inconnue.' });
  if (phase(e) !== 'voting') return res.status(403).json({ error: "Le vote n'est pas ouvert pour cette élection." });
  const c = await db.get("SELECT * FROM candidates WHERE id=? AND election_id=? AND status='approved'", [+req.body.candidateId, e.id]);
  if (!c) return res.status(400).json({ error: 'Candidat inconnu.' });
  const fp = cleanFp(req.body.fp), dev = cleanDev(req.body.deviceId);
  if (!fp || !dev) return res.status(400).json({ error: 'Appareil non reconnu. Recharge la page.' });
  const eh = req.s.email_h, ip = req.ip, ua = String(req.headers['user-agent'] || '').slice(0, 250), eid = e.id;
  let r;
  try {
    r = await tx(async (d) => {
      const ins = (status, reason) => d.run('INSERT INTO votes(election_id,email_h,label,candidate_id,status,reason,fp,device_id,ip,ua,created,updated) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)', [eid, eh, req.s.label, c.id, status, reason, fp, dev, ip, ua, now(), now()]);
      const mine = await d.get('SELECT * FROM votes WHERE election_id=? AND email_h=?', [eid, eh]);
      if (await quarantined(d, eid, fp, dev)) {
        if (!mine) await ins('suspect', 'appareil en quarantaine');
        await feed(d, eid, 'rejected');
        return { code: 403, body: { error: 'Cet appareil est en quarantaine. Contacte le BDE.', blocked: true } };
      }
      const others = await deviceHit(d, eid, fp, dev, eh);
      if (others.length) {
        await d.run('INSERT INTO quarantine(election_id,fp,device_id,ip,created,note) VALUES(?,?,?,?,?,?)', [eid, fp, dev, ip, now(), 'deux emails sur un même téléphone']);
        if (mine) await d.run("UPDATE votes SET status='suspect',reason='fingerprint identical',updated=? WHERE id=?", [now(), mine.id]); else await ins('suspect', 'fingerprint identical');
        for (const o of others) if (o.status === 'valid') await d.run("UPDATE votes SET status='suspect',reason='fingerprint identical',updated=? WHERE id=?", [now(), o.id]);
        await feed(d, eid, 'rejected');
        return { code: 403, body: { error: 'Un autre vote a déjà été fait depuis ce téléphone. Appareil placé en quarantaine.', blocked: true } };
      }
      if (!mine) { await ins('valid', null); await feed(d, eid, 'validated'); return { code: 200, body: { ok: true, first: true } }; }
      if (mine.status !== 'valid') return { code: 403, body: { error: 'Ton vote est en vérification par le comité.', blocked: true } };
      if (mine.candidate_id === c.id) return { code: 200, body: { ok: true, same: true } };
      if (mine.changes >= C.maxChanges) return { code: 403, body: { error: `Tu as utilisé tes ${C.maxChanges} changements.` } };
      await d.run('UPDATE votes SET candidate_id=?,changes=changes+1,updated=? WHERE id=?', [c.id, now(), mine.id]);
      await feed(d, eid, 'changed'); return { code: 200, body: { ok: true, changed: true } };
    });
  } catch (err) { console.error(err); return res.status(409).json({ error: 'Vote simultané détecté. Réessaie.' }); }
  res.status(r.code).json({ ...r.body, me: await myState(eid, eh) });
}));

// ---------- candidatures (photo stockée dans la base, vidéo = lien YouTube / Drive) ----------
const txt = (v, min, max) => { v = String(v == null ? '' : v).trim(); return v.length >= min && v.length <= max ? v : null; };
function parseVideo(u) {
  u = String(u || '').trim(); let m;
  if ((m = u.match(/^https?:\/\/(?:www\.|m\.)?(?:youtube\.com\/(?:watch\?(?:[^#]*&)?v=|shorts\/|embed\/)|youtu\.be\/)([A-Za-z0-9_-]{11})/))) return 'yt:' + m[1];
  if ((m = u.match(/^https?:\/\/drive\.google\.com\/file\/d\/([A-Za-z0-9_-]{10,})/))) return 'drive:' + m[1];
  return null;
}
function parsePhoto(s) {
  const m = String(s || '').match(/^data:image\/jpeg;base64,([A-Za-z0-9+/=]+)$/); if (!m) return null;
  const b = Buffer.from(m[1], 'base64');
  return (b.length > 500 && b.length <= 250e3 && b[0] === 0xFF && b[1] === 0xD8 && b[2] === 0xFF) ? b : null;
}
app.post('/api/candidacy', needStudent, ah(async (req, res) => {
  const d = req.body || {}, e = await election(d.electionId);
  if (!e) return res.status(400).json({ error: 'Élection inconnue.' });
  if (phase(e) !== 'registration') return res.status(403).json({ error: "Les candidatures ne sont pas ouvertes pour cette élection." });
  if (!limit('cand:' + req.s.email_h, 8, 3600e3)) return res.status(429).json({ error: "Trop d'envois. Réessaie plus tard." });
  const old = await db.get('SELECT * FROM candidates WHERE election_id=? AND email_h=?', [e.id, req.s.email_h]);
  if (old && old.status === 'approved') return res.status(403).json({ error: 'Ta candidature est déjà validée.' });
  const name = txt(d.name, 2, 60), role = txt(d.role, 2, 50), klass = txt(d.klass || 'x', 1, 30), bio = txt(d.bio, 20, 800);
  if (!name || !role || !bio) return res.status(400).json({ error: 'Nom, poste et bio (20 caractères minimum) sont obligatoires.' });
  const promises = (Array.isArray(d.promises) ? d.promises : []).slice(0, 5).map(p => [txt(p[0], 1, 40), txt(p[1], 1, 120)]).filter(p => p[0] && p[1]);
  if (!promises.length) return res.status(400).json({ error: 'Ajoute au moins une promesse.' });
  const qa = (Array.isArray(d.qa) ? d.qa : []).slice(0, 2).map(p => [txt(p[0], 1, 120), txt(p[1], 1, 200)]).filter(p => p[0] && p[1]);
  let video = old && old.video_pitch;
  if (d.videoUrl) { video = parseVideo(d.videoUrl); if (!video) return res.status(400).json({ error: 'Lien vidéo : colle un lien YouTube ou Google Drive.' }); }
  if (!video) return res.status(400).json({ error: 'Ajoute le lien de ta vidéo de 30 s (YouTube ou Google Drive).' });
  let photo = null;
  if (d.photo) { photo = parsePhoto(d.photo); if (!photo) return res.status(400).json({ error: 'Photo invalide (JPG, 250 Ko max).' }); }
  else if (!old || !old.photo) return res.status(400).json({ error: 'La photo est obligatoire.' });
  let id = old && old.id;
  if (old) await db.run("UPDATE candidates SET name=?,role=?,klass=?,bio=?,promises=?,qa=?,video_pitch=?,pitch_dur=NULL,dur_checked=0,updated=?,status='pending',note=NULL WHERE id=?", [name, role, klass, bio, JSON.stringify(promises), JSON.stringify(qa), video, now(), id]);
  else id = (await db.run("INSERT INTO candidates(election_id,email_h,name,role,klass,bio,promises,qa,video_pitch,created,updated,status) VALUES(?,?,?,?,?,?,?,?,?,?,?,'pending')", [e.id, req.s.email_h, name, role, klass, bio, JSON.stringify(promises), JSON.stringify(qa), video, now(), now()])).id;
  if (photo) { await db.run('INSERT OR REPLACE INTO photos(candidate_id,data) VALUES(?,?)', [id, photo]); await db.run('UPDATE candidates SET photo=? WHERE id=?', ['/photo/' + id + '?v=' + now(), id]); }
  await audit('candidat', 'candidature envoyée', e.name + ' • ' + name);
  res.json({ ok: true, myCandidacy: await myCand(e.id, req.s.email_h) });
}));

// ---------- BDE / Ghost : élections et candidatures ----------
app.post('/api/admin/login', ah(async (req, res) => {
  if (!limit('al:' + req.ip, 8, 600e3)) return res.status(429).json({ error: "Trop d'essais." });
  if (C.bdeKeys.some(x => safeEq(x, String(req.body.key || '')))) { await newSession(res, 'admin', null, 'bde', 12); return res.json({ ok: true }); }
  res.status(401).json({ error: 'Clé incorrecte.' });
}));
const FEED_LABEL = { validated: 'Ballot validé', changed: 'Vote modifié', rejected: 'Rejeté — doublon détecté' };
app.get('/api/admin/elections', needAdmin, ah(async (req, res) => {
  const list = await db.all('SELECT * FROM elections ORDER BY vote_open DESC');
  res.json({ role: req.role, elections: await Promise.all(list.map(async e => ({ ...elShape(e),
    votes: await count(db, "SELECT COUNT(*) n FROM votes WHERE election_id=? AND status='valid'", [e.id]), pending: await count(db, "SELECT COUNT(*) n FROM candidates WHERE election_id=? AND status='pending'", [e.id]) }))) });
}));
app.post('/api/admin/elections', needAdmin, ah(async (req, res) => {
  const p = parseElection(req.body); if (p.error) return res.status(400).json(p);
  const r = await db.run('INSERT INTO elections(name,reg_open,reg_close,vote_open,vote_close,eligible,created,by) VALUES(?,?,?,?,?,?,?,?)', [p.name, p.reg_open, p.reg_close, p.vote_open, p.vote_close, p.eligible, now(), req.role]);
  await audit(req.role, 'créer élection', p.name); res.json({ ok: true, id: r.id });
}));
app.put('/api/admin/elections/:id', needAdmin, ah(async (req, res) => {
  const e = await election(req.params.id); if (!e) return res.status(404).json({ error: 'introuvable' });
  const p = parseElection(req.body); if (p.error) return res.status(400).json(p);
  const hasVotes = (await count(db, 'SELECT COUNT(*) n FROM votes WHERE election_id=?', [e.id])) > 0;
  if (hasVotes && req.role !== 'ghost' && (p.vote_open !== e.vote_open || p.vote_close !== e.vote_close)) return res.status(403).json({ error: 'Des votes existent déjà : les dates de vote sont verrouillées (le Ghost peut les modifier).' });
  await db.run('UPDATE elections SET name=?,reg_open=?,reg_close=?,vote_open=?,vote_close=?,eligible=? WHERE id=?', [p.name, p.reg_open, p.reg_close, p.vote_open, p.vote_close, p.eligible, e.id]);
  await audit(req.role, 'modifier élection', p.name); res.json({ ok: true });
}));
app.get('/api/admin/stats', needAdmin, ah(async (req, res) => {
  const e = await election(req.query.election); if (!e) return res.status(404).json({ error: 'introuvable' });
  const valid = await count(db, "SELECT COUNT(*) n FROM votes WHERE election_id=? AND status='valid'", [e.id]);
  const out = { role: req.role, election: elShape(e), votes: valid, participation: Math.round(valid / e.eligible * 1000) / 10, invalids: await count(db, "SELECT COUNT(*) n FROM votes WHERE election_id=? AND status='invalid'", [e.id]), updated: now(),
    recent: (await db.all('SELECT id,ts,kind FROM feed WHERE election_id=? ORDER BY id DESC LIMIT 12', [e.id])).map(f => ({ id: 80000 + f.id, ts: f.ts, label: FEED_LABEL[f.kind] || f.kind, rejected: f.kind === 'rejected' })) };
  if (C.adminBreakdown || phase(e) === 'closed') out.breakdown = await Promise.all((await approved(e.id)).map(async c => ({ name: c.name, votes: await count(db, "SELECT COUNT(*) n FROM votes WHERE status='valid' AND candidate_id=?", [c.id]) })));
  res.json(out);
}));
app.get('/api/admin/candidacies', needAdmin, ah(async (req, res) => {
  const e = await election(req.query.election); if (!e) return res.status(404).json({ error: 'introuvable' });
  res.json({ phase: phase(e), list: (await db.all("SELECT * FROM candidates WHERE election_id=? ORDER BY CASE status WHEN 'pending' THEN 0 WHEN 'approved' THEN 1 ELSE 2 END, id", [e.id])).map(c => ({ ...pubCand(c), status: c.status, note: c.note, durChecked: !!c.dur_checked })) });
}));
const decide = (status) => ah(async (req, res) => {
  const c = await db.get('SELECT * FROM candidates WHERE id=?', [+req.params.id]); if (!c) return res.status(404).json({ error: 'introuvable' });
  const e = await election(c.election_id);
  if (['voting', 'closed'].includes(phase(e))) return res.status(403).json({ error: 'Le vote a commencé : les candidatures sont figées.' });
  const note = status === 'rejected' ? (txt(req.body.note, 0, 200) || null) : null;
  await db.run('UPDATE candidates SET status=?,note=?,updated=? WHERE id=?', [status, note, now(), c.id]);
  await audit(req.role, status === 'approved' ? 'valider candidature' : 'refuser candidature', e.name + ' • ' + c.name); res.json({ ok: true });
});
app.post('/api/admin/candidacies/:id/approve', needAdmin, decide('approved'));
app.post('/api/admin/candidacies/:id/reject', needAdmin, decide('rejected'));

// ---------- Ghost / quarantaine ----------
app.post('/api/ghost/login', ah(async (req, res) => {
  if (!limit('gl:' + req.ip, 5, 600e3)) return res.status(429).json({ error: "Trop d'essais." });
  if (safeEq(C.ghostKey, String(req.body.key || ''))) { await newSession(res, 'ghost', null, 'ghost', 8); await audit('ghost', 'connexion', req.ip); return res.json({ ok: true }); }
  res.status(401).json({ error: 'Refusé.' });
}));
const shape = async (v) => ({ id: v.id, label: v.label, status: v.status, reason: v.reason, election: ((await election(v.election_id)) || {}).name,
  candidate: ((await db.get('SELECT name FROM candidates WHERE id=?', [v.candidate_id])) || {}).name, ipCount: await count(db, 'SELECT COUNT(*) n FROM votes WHERE ip=?', [v.ip]) });
app.get('/api/ghost/overview', needGhost, ah(async (req, res) => {
  const q = String(req.query.q || '').trim().toUpperCase();
  const sus = (await db.all("SELECT * FROM votes WHERE status='suspect' ORDER BY updated DESC")).filter(v => !q || v.label.includes(q));
  res.json({ suspects: await count(db, "SELECT COUNT(*) n FROM votes WHERE status='suspect'"), invalids: await count(db, "SELECT COUNT(*) n FROM votes WHERE status='invalid'"), admins: C.bdeKeys.length,
    list: await Promise.all(sus.map(shape)), found: q ? await Promise.all((await db.all("SELECT * FROM votes WHERE label LIKE ? AND status<>'suspect' LIMIT 10", ['%' + q + '%'])).map(shape)) : [] });
}));
app.get('/api/ghost/proof/:id', needGhost, ah(async (req, res) => {
  const v = await db.get('SELECT * FROM votes WHERE id=?', [+req.params.id]); if (!v) return res.status(404).json({ error: 'introuvable' });
  const same = await db.all('SELECT id,label,status FROM votes WHERE id<>? AND election_id=? AND (fp=? OR device_id=?)', [v.id, v.election_id, v.fp, v.device_id]);
  const sameIp = await db.all('SELECT id,label,status FROM votes WHERE id<>? AND ip=?', [v.id, v.ip]);
  await audit('ghost', 'voir preuve', v.label);
  res.json({ label: v.label, status: v.status, reason: v.reason, fp: v.fp.slice(0, 16) + '…', device: v.device_id.slice(0, 8) + '…', ip: v.ip, ua: v.ua, created: v.created, updated: v.updated, sameDevice: same, sameIp });
}));
async function setStatus(id, status, action) {
  const v = await db.get('SELECT * FROM votes WHERE id=?', [id]); if (!v) return false;
  await db.run('UPDATE votes SET status=?,updated=? WHERE id=?', [status, now(), id]);
  if (status === 'valid') await db.run('DELETE FROM quarantine WHERE election_id=? AND (fp=? OR device_id=?)', [v.election_id, v.fp, v.device_id]);
  await audit('ghost', action, v.label); return true;
}
app.post('/api/ghost/invalidate/:id', needGhost, ah(async (q, r) => r.json({ ok: await setStatus(+q.params.id, 'invalid', 'invalider') })));
app.post('/api/ghost/restore/:id', needGhost, ah(async (q, r) => r.json({ ok: await setStatus(+q.params.id, 'valid', 'restaurer') })));
app.post('/api/ghost/force', needGhost, ah(async (req, res) => {
  const m = String(req.body.matricule || '').trim().toUpperCase(), rows = [];
  if (m) for (const v of await db.all('SELECT * FROM votes WHERE label=?', [m])) { const e = await election(v.election_id); if (e && phase(e) === 'voting') rows.push(v); }
  if (!rows.length) return res.status(404).json({ error: 'Matricule introuvable dans une élection en cours.' });
  for (const v of rows) await setStatus(v.id, 'invalid', 'FORCER INVALIDE');
  res.json({ ok: true, count: rows.length });
}));
app.get('/api/ghost/logs', needGhost, ah(async (q, r) => r.json({ logs: await db.all('SELECT * FROM audit ORDER BY id DESC LIMIT 100') })));
app.get('/api/ghost/settings', needGhost, ah(async (q, r) => r.json({ eligible: C.eligible, maxChanges: C.maxChanges, domain: C.allowedDomain || 'tous', smtp: smtpOK || !!C.brevoKey, admins: C.bdeKeys.length, quarantinedDevices: await count(db, 'SELECT COUNT(*) n FROM quarantine') })));

init().then(() => app.listen(C.port, () => {
  console.log(`VOGT ELECTIONS sur http://localhost:${C.port}   (admin: /admin   ghost: /ghost)`);
  console.log(process.env.TURSO_DATABASE_URL ? '✔ Base : Turso' : '⚠ Base locale (fichier vogt.db). Pour Turso : définis TURSO_DATABASE_URL et TURSO_AUTH_TOKEN.');
  console.log(C.brevoKey ? '✔ Emails : API Brevo' : smtpOK ? '✔ Emails : SMTP (bloqué sur Render gratuit : utilise BREVO_API_KEY)' : '⚠ Aucun service d\'email : les codes sont affichés ici, rien n\'est envoyé.');
  if (!process.env.SECRET) console.log('⚠ SECRET non défini : définis-le, sinon les votes existants ne seront plus reconnus après un redémarrage.');
})).catch(e => { console.error('Init base impossible :', e.message); process.exit(1); });
