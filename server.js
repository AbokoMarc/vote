'use strict';
// VOGT ELECTIONS 2026 - serveur
const express = require('express');
const cookieParser = require('cookie-parser');
const multer = require('multer');
const { execFile } = require('child_process');
const nodemailer = require('nodemailer');
const Database = require('better-sqlite3');
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
  from: process.env.MAIL_FROM || 'VOGT ELECTIONS <no-reply@vogt-elections.local>',
};
const smtpOK = !!process.env.SMTP_HOST;
const mailer = smtpOK ? nodemailer.createTransport({
  host: process.env.SMTP_HOST, port: +process.env.SMTP_PORT || 587,
  secure: process.env.SMTP_SECURE === '1',
  auth: process.env.SMTP_USER ? { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS } : undefined,
}) : null;

const db = new Database(process.env.DB_PATH || path.join(__dirname, 'vogt.db'));
db.pragma('journal_mode = WAL');
{
  const cols = db.prepare('PRAGMA table_info(votes)').all();
  if (cols.length && !cols.some(c => c.name === 'election_id')) db.exec('DROP TABLE votes; DROP TABLE quarantine; DROP TABLE feed;');
}
db.exec(`
CREATE TABLE IF NOT EXISTS otp (email_h TEXT PRIMARY KEY, code_h TEXT, exp INTEGER, tries INTEGER DEFAULT 0, sent INTEGER);
CREATE TABLE IF NOT EXISTS sessions (tok TEXT PRIMARY KEY, kind TEXT, email_h TEXT, label TEXT, exp INTEGER);
CREATE TABLE IF NOT EXISTS elections (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, reg_open INTEGER, reg_close INTEGER, vote_open INTEGER, vote_close INTEGER, eligible INTEGER, created INTEGER, by TEXT);
CREATE TABLE IF NOT EXISTS candidates (id INTEGER PRIMARY KEY AUTOINCREMENT, election_id INTEGER, email_h TEXT, name TEXT, role TEXT, klass TEXT, bio TEXT, promises TEXT, qa TEXT,
  photo TEXT, video_pitch TEXT, video_full TEXT, pitch_dur REAL, full_dur REAL, dur_checked INTEGER DEFAULT 0, status TEXT DEFAULT 'pending', note TEXT, created INTEGER, updated INTEGER,
  UNIQUE(election_id, email_h));
CREATE TABLE IF NOT EXISTS votes (
  id INTEGER PRIMARY KEY AUTOINCREMENT, election_id INTEGER, email_h TEXT, label TEXT, candidate_id INTEGER,
  changes INTEGER DEFAULT 0, status TEXT DEFAULT 'valid', reason TEXT,
  fp TEXT, device_id TEXT, ip TEXT, ua TEXT, created INTEGER, updated INTEGER, UNIQUE(election_id, email_h));
CREATE INDEX IF NOT EXISTS v_fp ON votes(fp); CREATE INDEX IF NOT EXISTS v_dev ON votes(device_id); CREATE INDEX IF NOT EXISTS v_ip ON votes(ip);
CREATE TABLE IF NOT EXISTS quarantine (id INTEGER PRIMARY KEY AUTOINCREMENT, election_id INTEGER, fp TEXT, device_id TEXT, ip TEXT, created INTEGER, note TEXT);
CREATE TABLE IF NOT EXISTS feed (id INTEGER PRIMARY KEY AUTOINCREMENT, election_id INTEGER, ts INTEGER, kind TEXT);
CREATE TABLE IF NOT EXISTS audit (id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER, actor TEXT, action TEXT, target TEXT);
`);

const hmac = (s) => crypto.createHmac('sha256', C.secret).update(String(s)).digest('hex');
const now = () => Date.now();
const rnd = (n) => crypto.randomBytes(n).toString('hex');
const safeEq = (a, b) => { const x = Buffer.from(hmac(a)), y = Buffer.from(hmac(b)); return crypto.timingSafeEqual(x, y); };

function normEmail(e) {
  e = String(e || '').trim().toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(e) || e.length > 120) return null;
  let [l, d] = e.split('@');
  l = l.split('+')[0];                                   // alias +tag
  if (d === 'gmail.com' || d === 'googlemail.com') { l = l.replace(/\./g, ''); d = 'gmail.com'; }
  if (C.allowedDomain && d !== C.allowedDomain) return { bad: 'domain' };
  return { norm: l + '@' + d, local: l, raw: e };
}
const labelOf = (local) => /^\d{2}[a-z]\d{3,5}$/i.test(local) ? local.toUpperCase() : local.slice(0, 2) + '***' + local.slice(-1);

// ---------- limites de débit ----------
const hits = new Map();
function limit(key, max, ms) {
  const t = now(), a = (hits.get(key) || []).filter(x => t - x < ms);
  if (a.length >= max) { hits.set(key, a); return false; }
  a.push(t); hits.set(key, a); return true;
}
setInterval(() => { const t = now(); for (const [k, a] of hits) if (!a.some(x => t - x < 3600e3)) hits.delete(k); }, 600e3).unref();

const audit = (actor, action, target) => db.prepare('INSERT INTO audit(ts,actor,action,target) VALUES(?,?,?,?)').run(now(), actor, action, target || '');
const feed = (eid, kind) => db.prepare('INSERT INTO feed(election_id,ts,kind) VALUES(?,?,?)').run(eid, now(), kind);

// ---------- seed : une élection de démonstration ----------
if (!db.prepare('SELECT 1 FROM elections').get()) {
  const t = now(), D = 864e5;
  const eid = db.prepare('INSERT INTO elections(name,reg_open,reg_close,vote_open,vote_close,eligible,created,by) VALUES(?,?,?,?,?,?,?,?)').run('VOGT ELECTIONS 2026', t - 14 * D, t - D, t - 3600e3, t + 7 * D, C.eligible, t, 'seed').lastInsertRowid;
  const seed = JSON.parse(fs.readFileSync(path.join(__dirname, 'candidates.json'), 'utf8'));
  for (const c of seed) db.prepare('INSERT INTO candidates(election_id,name,role,klass,bio,promises,qa,photo,video_pitch,video_full,pitch_dur,full_dur,dur_checked,status,created,updated) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)')
    .run(eid, c.name, c.role, c.klass, c.bio, JSON.stringify(c.promises), JSON.stringify(c.qa), c.photo, c.videoPitch, c.videoFull, 30, c.videoFull ? 134 : null, 1, 'approved', t, t);
}

// ---------- élections ----------
const election = (id) => db.prepare('SELECT * FROM elections WHERE id=?').get(+id);
function phase(e, t = now()) {
  if (t >= e.vote_close) return 'closed';
  if (t >= e.vote_open) return 'voting';
  if (t >= e.reg_open && t < e.reg_close) return 'registration';
  return t < e.reg_open ? 'upcoming' : 'between';
}
const fmtDur = (s) => s ? Math.floor(s / 60) + ':' + String(Math.round(s % 60)).padStart(2, '0') : null;
const fileOK = (f) => !!f && fs.existsSync(path.join(__dirname, 'public', f.replace(/^\//, '')));
const pubCand = (c) => ({ id: c.id, name: c.name, role: c.role, klass: c.klass, bio: c.bio, promises: JSON.parse(c.promises || '[]'), qa: JSON.parse(c.qa || '[]'), photo: c.photo,
  videoPitch: c.video_pitch, videoFull: c.video_full, pitchDur: fmtDur(c.pitch_dur), fullDur: fmtDur(c.full_dur), videoPitchOk: fileOK(c.video_pitch), videoFullOk: fileOK(c.video_full) });
const approved = (eid) => db.prepare("SELECT * FROM candidates WHERE election_id=? AND status='approved' ORDER BY id").all(eid);
const elShape = (e) => ({ id: e.id, name: e.name, reg_open: e.reg_open, reg_close: e.reg_close, vote_open: e.vote_open, vote_close: e.vote_close, eligible: e.eligible, phase: phase(e) });
function parseElection(b) {
  const name = String(b.name || '').trim();
  const d = ['reg_open', 'reg_close', 'vote_open', 'vote_close'].map(k => Math.floor(+b[k]));
  if (name.length < 3 || name.length > 80) return { error: 'Nom : 3 à 80 caractères.' };
  if (d.some(x => !Number.isFinite(x) || x < 1e12)) return { error: 'Dates invalides.' };
  if (!(d[0] < d[1] && d[1] <= d[2] && d[2] < d[3])) return { error: "Ordre attendu : ouverture des candidatures < fermeture des candidatures ≤ ouverture du vote < fermeture du vote." };
  const eligible = Math.max(1, Math.floor(+b.eligible) || C.eligible);
  return { name, reg_open: d[0], reg_close: d[1], vote_open: d[2], vote_close: d[3], eligible };
}

const app = express();
app.set('trust proxy', process.env.TRUST_PROXY === '1');
app.disable('x-powered-by');
app.use(express.json({ limit: '30kb' }));
app.use(cookieParser());
app.use((req, res, next) => { res.set({ 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer', 'X-Frame-Options': 'DENY' }); next(); });
app.use(express.static(path.join(__dirname, 'public'), { extensions: ['html'] }));
app.get('/admin', (q, r) => r.sendFile(path.join(__dirname, 'public/admin.html')));
app.get('/ghost', (q, r) => { r.set('X-Robots-Tag', 'noindex'); r.sendFile(path.join(__dirname, 'public/ghost.html')); });

const cname = (kind) => kind === 'student' ? 'vs' : kind === 'admin' ? 'va' : 'vg';
const ck = (res, name, val, days) => res.cookie(name, val, { httpOnly: true, sameSite: 'strict', secure: C.secure, maxAge: days * 864e5, path: '/' });
function session(req, kind) {
  const tok = req.cookies[cname(kind)];
  if (!tok) return null;
  return db.prepare('SELECT * FROM sessions WHERE tok=? AND kind=? AND exp>?').get(hmac(tok), kind, now()) || null;
}
function newSession(res, kind, email_h, label, hours) {
  const tok = rnd(24);
  db.prepare('INSERT INTO sessions VALUES(?,?,?,?,?)').run(hmac(tok), kind, email_h || null, label || null, now() + hours * 3600e3);
  ck(res, cname(kind), tok, hours / 24);
}
const needStudent = (q, r, n) => { const s = session(q, 'student'); if (!s) return r.status(401).json({ error: 'Session expirée. Recommence avec ton email.' }); q.s = s; n(); };
const needAdmin = (q, r, n) => { const g = session(q, 'ghost'); if (!g && !session(q, 'admin')) return r.status(401).json({ error: 'auth' }); q.role = g ? 'ghost' : 'bde'; n(); };
const needGhost = (q, r, n) => { const s = session(q, 'ghost'); if (!s) return r.status(401).json({ error: 'auth' }); q.g = s; n(); };

// ---------- email OTP ----------
app.post('/api/otp/request', async (req, res) => {
  const e = normEmail(req.body.email);
  if (!e) return res.status(400).json({ error: 'Email invalide.' });
  if (e.bad) return res.status(400).json({ error: 'Utilise ton email étudiant (@' + C.allowedDomain + ').' });
  if (!limit('ip:' + req.ip, 12, 600e3) || !limit('em:' + e.norm, 3, 600e3)) return res.status(429).json({ error: 'Trop de demandes. Réessaie dans quelques minutes.' });
  const eh = hmac(e.norm), code = String(crypto.randomInt(0, 10000)).padStart(4, '0');
  db.prepare('INSERT OR REPLACE INTO otp VALUES(?,?,?,0,?)').run(eh, hmac(eh + ':' + code), now() + 10 * 60e3, now());
  try {
    if (mailer) {
      await mailer.sendMail({
        from: C.from, to: e.raw, subject: 'Ton code VOGT ELECTIONS : ' + code,
        text: `Ton code : ${code}\n\nIl est valable 10 minutes. Ne le partage avec personne.`,
        html: `<div style="font-family:Arial,sans-serif;background:#FBF4E6;padding:28px"><div style="max-width:380px;margin:auto;background:#fff;border-radius:18px;padding:28px;text-align:center"><div style="color:#C2410C;font-size:12px;letter-spacing:1px">VOGT ELECTIONS</div><h2 style="margin:14px 0 6px">Ton code</h2><div style="font-size:44px;font-weight:700;letter-spacing:10px;color:#C2410C;margin:14px 0">${code}</div><p style="color:#666;font-size:13px">Valable 10 minutes. Ne le partage avec personne.</p></div></div>`,
      });
    } else console.log(`[DEV] code pour ${e.raw} : ${code}  (SMTP non configuré, aucun email envoyé)`);
  } catch (err) { console.error('SMTP:', err.message); return res.status(502).json({ error: "L'email n'a pas pu être envoyé. Réessaie." }); }
  res.json({ ok: true, ...(C.devShowCode && !mailer ? { devCode: code } : {}) });
});
app.post('/api/otp/verify', (req, res) => {
  const e = normEmail(req.body.email), code = String(req.body.code || '');
  if (!e || e.bad || !/^\d{4}$/.test(code)) return res.status(400).json({ error: 'Code invalide.' });
  if (!limit('vip:' + req.ip, 30, 600e3)) return res.status(429).json({ error: 'Trop de tentatives.' });
  const eh = hmac(e.norm), o = db.prepare('SELECT * FROM otp WHERE email_h=?').get(eh);
  if (!o || o.exp < now()) return res.status(400).json({ error: 'Code expiré. Demande un nouveau code.' });
  if (o.tries >= 5) { db.prepare('DELETE FROM otp WHERE email_h=?').run(eh); return res.status(429).json({ error: "Trop d'essais. Demande un nouveau code." }); }
  if (!crypto.timingSafeEqual(Buffer.from(o.code_h), Buffer.from(hmac(eh + ':' + code)))) { db.prepare('UPDATE otp SET tries=tries+1 WHERE email_h=?').run(eh); return res.status(400).json({ error: 'Mauvais code.' }); }
  db.prepare('DELETE FROM otp WHERE email_h=?').run(eh);
  newSession(res, 'student', eh, labelOf(e.local), 6);
  res.json({ ok: true });
});
app.get('/api/me', (req, res) => res.json({ in: !!session(req, 'student') }));
app.post('/api/logout', (req, res) => { ['vs', 'va', 'vg'].forEach(n => res.clearCookie(n)); res.json({ ok: true }); });

// ---------- appareil ----------
const cleanFp = (s) => (typeof s === 'string' && /^[a-f0-9]{16,128}$/.test(s)) ? s : null;
const cleanDev = (s) => (typeof s === 'string' && /^[a-zA-Z0-9-]{16,64}$/.test(s)) ? s : null;
function orClause(fp, dev) { const w = [], a = []; if (fp) { w.push('fp=?'); a.push(fp); } if (dev) { w.push('device_id=?'); a.push(dev); } return [w.join(' OR '), a]; }
function deviceHit(eid, fp, dev, eh) { const [w, a] = orClause(fp, dev); return w ? db.prepare(`SELECT * FROM votes WHERE election_id=? AND (${w}) AND email_h<>?`).all(eid, ...a, eh) : []; }
function quarantined(eid, fp, dev) { const [w, a] = orClause(fp, dev); return w ? !!db.prepare(`SELECT 1 FROM quarantine WHERE election_id=? AND (${w})`).get(eid, ...a) : false; }

function myState(eid, eh) {
  const v = db.prepare('SELECT * FROM votes WHERE election_id=? AND email_h=?').get(eid, eh);
  if (!v) return { voted: false };
  const c = db.prepare('SELECT name FROM candidates WHERE id=?').get(v.candidate_id);
  return { voted: true, candidateId: v.candidate_id, candidateName: c ? c.name : '?', changesLeft: Math.max(0, C.maxChanges - v.changes), status: v.status };
}
const myCand = (eid, eh) => { const c = db.prepare('SELECT status,note,name FROM candidates WHERE election_id=? AND email_h=?').get(eid, eh); return c || null; };

app.get('/api/elections', needStudent, (req, res) => {
  res.json({ label: req.s.label, elections: db.prepare('SELECT * FROM elections ORDER BY vote_open DESC').all().map(e => ({ ...elShape(e), voted: !!db.prepare('SELECT 1 FROM votes WHERE election_id=? AND email_h=?').get(e.id, req.s.email_h), candidacy: (myCand(e.id, req.s.email_h) || {}).status || null })) });
});
app.get('/api/elections/:id', needStudent, (req, res) => {
  const e = election(req.params.id); if (!e) return res.status(404).json({ error: 'Élection introuvable.' });
  const counts = (C.publicCounts || phase(e) === 'closed') ? Object.fromEntries(db.prepare("SELECT candidate_id c,COUNT(*) n FROM votes WHERE election_id=? AND status='valid' GROUP BY candidate_id").all(e.id).map(r => [r.c, r.n])) : null;
  res.json({ election: elShape(e), maxChanges: C.maxChanges, me: myState(e.id, req.s.email_h), myCandidacy: myCand(e.id, req.s.email_h),
    candidates: approved(e.id).map(c => ({ ...pubCand(c), votes: counts ? (counts[c.id] || 0) : undefined })) });
});

// ---------- vote ----------
app.post('/api/vote', needStudent, (req, res) => {
  const e = election(req.body.electionId);
  if (!e) return res.status(400).json({ error: 'Élection inconnue.' });
  if (phase(e) !== 'voting') return res.status(403).json({ error: 'Le vote n\'est pas ouvert pour cette élection.' });
  const c = db.prepare("SELECT * FROM candidates WHERE id=? AND election_id=? AND status='approved'").get(+req.body.candidateId, e.id);
  if (!c) return res.status(400).json({ error: 'Candidat inconnu.' });
  const fp = cleanFp(req.body.fp), dev = cleanDev(req.body.deviceId);
  if (!fp || !dev) return res.status(400).json({ error: 'Appareil non reconnu. Recharge la page.' });
  const eh = req.s.email_h, ip = req.ip, ua = String(req.headers['user-agent'] || '').slice(0, 250), eid = e.id;
  const ins = (status, reason) => db.prepare('INSERT INTO votes(election_id,email_h,label,candidate_id,status,reason,fp,device_id,ip,ua,created,updated) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)').run(eid, eh, req.s.label, c.id, status, reason, fp, dev, ip, ua, now(), now());
  const tx = db.transaction(() => {
    const mine = db.prepare('SELECT * FROM votes WHERE election_id=? AND email_h=?').get(eid, eh);
    if (quarantined(eid, fp, dev)) {
      if (!mine) ins('suspect', 'appareil en quarantaine');
      feed(eid, 'rejected');
      return { code: 403, body: { error: 'Cet appareil est en quarantaine. Contacte le BDE.', blocked: true } };
    }
    const others = deviceHit(eid, fp, dev, eh);
    if (others.length) {
      db.prepare('INSERT INTO quarantine(election_id,fp,device_id,ip,created,note) VALUES(?,?,?,?,?,?)').run(eid, fp, dev, ip, now(), 'deux emails sur un même téléphone');
      if (mine) db.prepare("UPDATE votes SET status='suspect',reason='fingerprint identical',updated=? WHERE id=?").run(now(), mine.id); else ins('suspect', 'fingerprint identical');
      for (const o of others) if (o.status === 'valid') db.prepare("UPDATE votes SET status='suspect',reason='fingerprint identical',updated=? WHERE id=?").run(now(), o.id);
      feed(eid, 'rejected');
      return { code: 403, body: { error: 'Un autre vote a déjà été fait depuis ce téléphone. Appareil placé en quarantaine.', blocked: true } };
    }
    if (!mine) { ins('valid', null); feed(eid, 'validated'); return { code: 200, body: { ok: true, first: true } }; }
    if (mine.status !== 'valid') return { code: 403, body: { error: 'Ton vote est en vérification par le comité.', blocked: true } };
    if (mine.candidate_id === c.id) return { code: 200, body: { ok: true, same: true } };
    if (mine.changes >= C.maxChanges) return { code: 403, body: { error: `Tu as utilisé tes ${C.maxChanges} changements.` } };
    db.prepare('UPDATE votes SET candidate_id=?,changes=changes+1,updated=? WHERE id=?').run(c.id, now(), mine.id);
    feed(eid, 'changed'); return { code: 200, body: { ok: true, changed: true } };
  });
  const r = tx();
  res.status(r.code).json({ ...r.body, me: myState(eid, eh) });
});

// ---------- candidatures ----------
const UP = path.join(__dirname, 'public', 'uploads');
fs.mkdirSync(path.join(UP, 'tmp'), { recursive: true });
const upload = multer({ dest: path.join(UP, 'tmp'), limits: { fileSize: 40e6, files: 2, fields: 5 } });
const sniff = (f) => { const b = Buffer.alloc(12); const fd = fs.openSync(f, 'r'); fs.readSync(fd, b, 0, 12, 0); fs.closeSync(fd);
  if (b[0] === 0xFF && b[1] === 0xD8 && b[2] === 0xFF) return ['image', 'jpg'];
  if (b.slice(0, 4).equals(Buffer.from([0x89, 0x50, 0x4E, 0x47]))) return ['image', 'png'];
  if (b.slice(0, 4).toString() === 'RIFF' && b.slice(8, 12).toString() === 'WEBP') return ['image', 'webp'];
  if (b.slice(4, 8).toString() === 'ftyp') return ['video', 'mp4'];
  if (b.slice(0, 4).equals(Buffer.from([0x1A, 0x45, 0xDF, 0xA3]))) return ['video', 'webm'];
  return null; };
const probe = (f) => new Promise(r => execFile('ffprobe', ['-v', 'error', '-show_entries', 'format=duration', '-of', 'csv=p=0', f], { timeout: 8000 }, (err, out) => r(err ? null : (parseFloat(out) || null))));
const txt = (v, min, max) => { v = String(v == null ? '' : v).trim(); return v.length >= min && v.length <= max ? v : null; };

app.post('/api/candidacy', needStudent, (req, res, next) => upload.fields([{ name: 'photo', maxCount: 1 }, { name: 'video', maxCount: 1 }])(req, res, (err) => err ? res.status(400).json({ error: 'Fichier refusé (vidéo 40 Mo max).' }) : next()), async (req, res) => {
  const files = [].concat(...Object.values(req.files || {}));
  const clean = () => files.forEach(f => fs.rm(f.path, () => {}));
  const fail = (code, error) => { clean(); return res.status(code).json({ error }); };
  try {
    let d; try { d = JSON.parse(req.body.data); } catch (e) { return fail(400, 'Données invalides.'); }
    const e = election(d.electionId);
    if (!e) return fail(400, 'Élection inconnue.');
    if (phase(e) !== 'registration') return fail(403, "Les candidatures ne sont pas ouvertes pour cette élection.");
    if (!limit('cand:' + req.s.email_h, 5, 3600e3)) return fail(429, 'Trop d\'envois. Réessaie plus tard.');
    const old = db.prepare('SELECT * FROM candidates WHERE election_id=? AND email_h=?').get(e.id, req.s.email_h);
    if (old && old.status === 'approved') return fail(403, 'Ta candidature est déjà validée.');
    const name = txt(d.name, 2, 60), role = txt(d.role, 2, 50), klass = txt(d.klass || 'x', 1, 30), bio = txt(d.bio, 20, 800);
    if (!name || !role || !bio) return fail(400, 'Nom, poste et bio (20 caractères minimum) sont obligatoires.');
    const promises = (Array.isArray(d.promises) ? d.promises : []).slice(0, 5).map(p => [txt(p[0], 1, 40), txt(p[1], 1, 120)]).filter(p => p[0] && p[1]);
    if (!promises.length) return fail(400, 'Ajoute au moins une promesse.');
    const qa = (Array.isArray(d.qa) ? d.qa : []).slice(0, 2).map(p => [txt(p[0], 1, 120), txt(p[1], 1, 200)]).filter(p => p[0] && p[1]);
    const ph = (req.files.photo || [])[0], vd = (req.files.video || [])[0];
    if ((!old || !old.photo) && !ph) return fail(400, 'La photo est obligatoire.');
    if ((!old || !old.video_pitch) && !vd) return fail(400, 'La vidéo de présentation (30 s) est obligatoire.');
    let photo = old && old.photo, video = old && old.video_pitch, dur = old && old.pitch_dur, checked = old ? old.dur_checked : 0;
    const put = (f, ext) => { const n = '/uploads/' + rnd(12) + '.' + ext; fs.renameSync(f.path, path.join(__dirname, 'public', n)); return n; };
    if (ph) { const k = sniff(ph.path); if (!k || k[0] !== 'image' || ph.size > 5e6) return fail(400, 'Photo : JPG, PNG ou WebP, 5 Mo max.'); photo = put(ph, k[1]); }
    if (vd) {
      const k = sniff(vd.path); if (!k || k[0] !== 'video') return fail(400, 'Vidéo : MP4 ou WebM uniquement.');
      const real = await probe(vd.path), claimed = Math.min(+d.videoSeconds || 0, 600);
      if (real && real > 31) return fail(400, `Ta vidéo dure ${Math.round(real)} s. Maximum : 30 s.`);
      if (!real && claimed > 31) return fail(400, 'Ta vidéo dépasse 30 s.');
      dur = real || claimed || null; checked = real ? 1 : 0; video = put(vd, k[1]);
    }
    const args = [name, role, klass, bio, JSON.stringify(promises), JSON.stringify(qa), photo, video, dur, checked, now()];
    if (old) db.prepare("UPDATE candidates SET name=?,role=?,klass=?,bio=?,promises=?,qa=?,photo=?,video_pitch=?,pitch_dur=?,dur_checked=?,updated=?,status='pending',note=NULL WHERE id=?").run(...args, old.id);
    else db.prepare("INSERT INTO candidates(name,role,klass,bio,promises,qa,photo,video_pitch,pitch_dur,dur_checked,created,updated,election_id,email_h,status) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,'pending')").run(...args, now(), e.id, req.s.email_h);
    audit('candidat', 'candidature envoyée', e.name + ' • ' + name);
    res.json({ ok: true, myCandidacy: myCand(e.id, req.s.email_h) });
  } catch (err) { console.error(err); fail(500, 'Erreur serveur.'); }
});

// ---------- BDE / Ghost : élections et candidatures ----------
app.post('/api/admin/login', (req, res) => {
  if (!limit('al:' + req.ip, 8, 600e3)) return res.status(429).json({ error: "Trop d'essais." });
  if (C.bdeKeys.some(x => safeEq(x, String(req.body.key || '')))) { newSession(res, 'admin', null, 'bde', 12); return res.json({ ok: true }); }
  res.status(401).json({ error: 'Clé incorrecte.' });
});
const FEED_LABEL = { validated: 'Ballot validé', changed: 'Vote modifié', rejected: 'Rejeté — doublon détecté' };
const count = (sql, ...a) => db.prepare(sql).get(...a).n;
app.get('/api/admin/elections', needAdmin, (req, res) => res.json({ role: req.role, elections: db.prepare('SELECT * FROM elections ORDER BY vote_open DESC').all().map(e => ({ ...elShape(e),
  votes: count("SELECT COUNT(*) n FROM votes WHERE election_id=? AND status='valid'", e.id), pending: count("SELECT COUNT(*) n FROM candidates WHERE election_id=? AND status='pending'", e.id) })) }));
app.post('/api/admin/elections', needAdmin, (req, res) => {
  const p = parseElection(req.body); if (p.error) return res.status(400).json(p);
  const id = db.prepare('INSERT INTO elections(name,reg_open,reg_close,vote_open,vote_close,eligible,created,by) VALUES(?,?,?,?,?,?,?,?)').run(p.name, p.reg_open, p.reg_close, p.vote_open, p.vote_close, p.eligible, now(), req.role).lastInsertRowid;
  audit(req.role, 'créer élection', p.name); res.json({ ok: true, id });
});
app.put('/api/admin/elections/:id', needAdmin, (req, res) => {
  const e = election(req.params.id); if (!e) return res.status(404).json({ error: 'introuvable' });
  const p = parseElection(req.body); if (p.error) return res.status(400).json(p);
  const hasVotes = count('SELECT COUNT(*) n FROM votes WHERE election_id=?', e.id) > 0;
  if (hasVotes && req.role !== 'ghost' && (p.vote_open !== e.vote_open || p.vote_close !== e.vote_close)) return res.status(403).json({ error: 'Des votes existent déjà : seules les dates de vote sont verrouillées (le Ghost peut les modifier).' });
  db.prepare('UPDATE elections SET name=?,reg_open=?,reg_close=?,vote_open=?,vote_close=?,eligible=? WHERE id=?').run(p.name, p.reg_open, p.reg_close, p.vote_open, p.vote_close, p.eligible, e.id);
  audit(req.role, 'modifier élection', p.name); res.json({ ok: true });
});
app.get('/api/admin/stats', needAdmin, (req, res) => {
  const e = election(req.query.election); if (!e) return res.status(404).json({ error: 'introuvable' });
  const valid = count("SELECT COUNT(*) n FROM votes WHERE election_id=? AND status='valid'", e.id);
  const out = { role: req.role, election: elShape(e), votes: valid, participation: Math.round(valid / e.eligible * 1000) / 10, invalids: count("SELECT COUNT(*) n FROM votes WHERE election_id=? AND status='invalid'", e.id), updated: now(),
    recent: db.prepare('SELECT id,ts,kind FROM feed WHERE election_id=? ORDER BY id DESC LIMIT 12').all(e.id).map(f => ({ id: 80000 + f.id, ts: f.ts, label: FEED_LABEL[f.kind] || f.kind, rejected: f.kind === 'rejected' })) };
  if (C.adminBreakdown || phase(e) === 'closed') out.breakdown = approved(e.id).map(c => ({ name: c.name, votes: count("SELECT COUNT(*) n FROM votes WHERE status='valid' AND candidate_id=?", c.id) }));
  res.json(out);
});
app.get('/api/admin/candidacies', needAdmin, (req, res) => {
  const e = election(req.query.election); if (!e) return res.status(404).json({ error: 'introuvable' });
  res.json({ phase: phase(e), list: db.prepare("SELECT * FROM candidates WHERE election_id=? ORDER BY CASE status WHEN 'pending' THEN 0 WHEN 'approved' THEN 1 ELSE 2 END, id").all(e.id).map(c => ({ ...pubCand(c), status: c.status, note: c.note, durChecked: !!c.dur_checked })) });
});
function decide(status) { return (req, res) => {
  const c = db.prepare('SELECT * FROM candidates WHERE id=?').get(+req.params.id); if (!c) return res.status(404).json({ error: 'introuvable' });
  const e = election(c.election_id);
  if (phase(e) === 'voting' || phase(e) === 'closed') return res.status(403).json({ error: 'Le vote a commencé : les candidatures sont figées.' });
  const note = status === 'rejected' ? (txt(req.body.note, 0, 200) || null) : null;
  db.prepare('UPDATE candidates SET status=?,note=?,updated=? WHERE id=?').run(status, note, now(), c.id);
  audit(req.role, status === 'approved' ? 'valider candidature' : 'refuser candidature', e.name + ' • ' + c.name); res.json({ ok: true });
}; }
app.post('/api/admin/candidacies/:id/approve', needAdmin, decide('approved'));
app.post('/api/admin/candidacies/:id/reject', needAdmin, decide('rejected'));

// ---------- Ghost / quarantaine ----------
app.post('/api/ghost/login', (req, res) => {
  if (!limit('gl:' + req.ip, 5, 600e3)) return res.status(429).json({ error: "Trop d'essais." });
  if (safeEq(C.ghostKey, String(req.body.key || ''))) { newSession(res, 'ghost', null, 'ghost', 8); audit('ghost', 'connexion', req.ip); return res.json({ ok: true }); }
  res.status(401).json({ error: 'Refusé.' });
});
const shape = (v) => ({ id: v.id, label: v.label, status: v.status, reason: v.reason, election: (election(v.election_id) || {}).name,
  candidate: (db.prepare('SELECT name FROM candidates WHERE id=?').get(v.candidate_id) || {}).name,
  ipCount: count('SELECT COUNT(*) n FROM votes WHERE ip=?', v.ip) });
app.get('/api/ghost/overview', needGhost, (req, res) => {
  const q = String(req.query.q || '').trim().toUpperCase();
  res.json({ suspects: count("SELECT COUNT(*) n FROM votes WHERE status='suspect'"), invalids: count("SELECT COUNT(*) n FROM votes WHERE status='invalid'"), admins: C.bdeKeys.length,
    list: db.prepare("SELECT * FROM votes WHERE status='suspect' ORDER BY updated DESC").all().filter(v => !q || v.label.includes(q)).map(shape),
    found: q ? db.prepare("SELECT * FROM votes WHERE label LIKE ? AND status<>'suspect' LIMIT 10").all('%' + q + '%').map(shape) : [] });
});
app.get('/api/ghost/proof/:id', needGhost, (req, res) => {
  const v = db.prepare('SELECT * FROM votes WHERE id=?').get(+req.params.id); if (!v) return res.status(404).json({ error: 'introuvable' });
  const same = db.prepare('SELECT id,label,status FROM votes WHERE id<>? AND election_id=? AND (fp=? OR device_id=?)').all(v.id, v.election_id, v.fp, v.device_id);
  const sameIp = db.prepare('SELECT id,label,status FROM votes WHERE id<>? AND ip=?').all(v.id, v.ip);
  audit('ghost', 'voir preuve', v.label);
  res.json({ label: v.label, status: v.status, reason: v.reason, fp: v.fp.slice(0, 16) + '…', device: v.device_id.slice(0, 8) + '…', ip: v.ip, ua: v.ua, created: v.created, updated: v.updated, sameDevice: same, sameIp });
});
function setStatus(id, status, action) {
  const v = db.prepare('SELECT * FROM votes WHERE id=?').get(id); if (!v) return false;
  db.prepare('UPDATE votes SET status=?,updated=? WHERE id=?').run(status, now(), id);
  if (status === 'valid') db.prepare('DELETE FROM quarantine WHERE election_id=? AND (fp=? OR device_id=?)').run(v.election_id, v.fp, v.device_id);
  audit('ghost', action, v.label); return true;
}
app.post('/api/ghost/invalidate/:id', needGhost, (q, r) => r.json({ ok: setStatus(+q.params.id, 'invalid', 'invalider') }));
app.post('/api/ghost/restore/:id', needGhost, (q, r) => r.json({ ok: setStatus(+q.params.id, 'valid', 'restaurer') }));
app.post('/api/ghost/force', needGhost, (req, res) => {
  const m = String(req.body.matricule || '').trim().toUpperCase();
  const rows = m ? db.prepare('SELECT * FROM votes WHERE label=?').all(m).filter(v => { const e = election(v.election_id); return e && phase(e) === 'voting'; }) : [];
  if (!rows.length) return res.status(404).json({ error: 'Matricule introuvable dans une élection en cours.' });
  rows.forEach(v => setStatus(v.id, 'invalid', 'FORCER INVALIDE')); res.json({ ok: true, count: rows.length });
});
app.get('/api/ghost/logs', needGhost, (q, r) => r.json({ logs: db.prepare('SELECT * FROM audit ORDER BY id DESC LIMIT 100').all() }));
app.get('/api/ghost/settings', needGhost, (q, r) => r.json({ eligible: C.eligible, maxChanges: C.maxChanges, domain: C.allowedDomain || 'tous', smtp: smtpOK, admins: C.bdeKeys.length, quarantinedDevices: count('SELECT COUNT(*) n FROM quarantine') }));

app.listen(C.port, () => {
  console.log(`VOGT ELECTIONS sur http://localhost:${C.port}   (admin: /admin   ghost: /ghost)`);
  if (!smtpOK) console.log('⚠  SMTP non configuré : les codes sont affichés ici, aucun email réel envoyé. Voir README.');
  if (!process.env.SECRET) console.log('⚠  SECRET non défini : définis-le dans .env, sinon les votes existants ne seront plus reconnus après un redémarrage.');
});
