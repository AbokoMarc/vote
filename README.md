# VOGT ELECTIONS - hébergement 100 % gratuit (Render + Turso)

Pages : `/` étudiant · `/admin` BDE · `/ghost` quarantaine (URL non liée).

## 1. Base de données Turso (gratuit)
1. Crée un compte sur https://turso.tech puis une base (ex. `vogt`). Choisis une région en Europe (Frankfurt ou Paris).
2. Récupère l'URL (`libsql://vogt-xxxx.turso.io`) et crée un **token d'accès** (dashboard, ou CLI : `turso db show vogt --url` et `turso db tokens create vogt`).
3. Les tables se créent toutes seules au premier démarrage.

## 2. Emails (gratuit)
**Important : Render bloque le SMTP (ports 25, 465, 587) sur l'offre gratuite.** Utilise l'API Brevo : crée une clé API (Brevo > SMTP et API > Clés API > Générer) et mets-la dans `BREVO_API_KEY`, avec `MAIL_FROM=VOGT HIGH TECH <ton-adresse-verifiee>`. Les variables SMTP_* ne servent alors plus.
Photo du campus : dépose un fichier `public/campus.jpg` (format paysage). Sans fichier, une illustration est affichée.
(Ancienne méthode SMTP, hors Render gratuit :)
Prends un service SMTP gratuit (Brevo, Resend, Mailjet...). Vérifie l'adresse d'expéditeur chez eux et note leur limite d'envois par jour.
Variables : SMTP_HOST, SMTP_PORT (587), SMTP_USER, SMTP_PASS, MAIL_FROM.
Sans SMTP, le code s'affiche dans les logs (mode test uniquement).

## 3. Serveur Render (gratuit)
1. Mets le dossier sur GitHub (dépôt privé). `.gitignore` exclut déjà `.env` et `node_modules`.
2. Sur https://render.com : New > Blueprint (il lit `render.yaml`) ou New > Web Service (build `npm install`, start `npm start`, offre Free).
3. Renseigne les variables : TURSO_DATABASE_URL, TURSO_AUTH_TOKEN, BDE_KEYS, GHOST_KEY, SMTP_*, MAIL_FROM, ELIGIBLE_VOTERS. `SECRET` est généré automatiquement : ne le change jamais ensuite.
4. Ouvre l'adresse `https://xxx.onrender.com`.

### Limite du gratuit : la mise en veille
Render met le service en veille après 15 min sans visite et le réveil prend environ une minute. Pour l'éviter le jour du vote, crée un moniteur gratuit (UptimeRobot ou cron-job.org) qui appelle `https://xxx.onrender.com/api/health` toutes les 5 minutes. Vérifie les quotas d'heures gratuites de Render pour ton compte.

## Photos et vidéos
Un hébergeur gratuit n'a pas de disque durable, donc :
- La **photo** est réduite dans le navigateur (480 px) puis stockée dans Turso.
- La **vidéo** (30 s) est un **lien YouTube (non répertorié) ou Google Drive**, intégré dans l'app. Le serveur ne peut pas mesurer la durée : le BDE regarde la vidéo avant de valider.
- Les vidéos de démonstration de `public/videos` sont de simples fichiers du dépôt.

## Test en local
`npm install`, `cp .env.example .env`, `npm start` (SEED_DEMO=1 crée une élection de démonstration ; en ligne laisse 0 et crée tes élections dans /admin). Sans variables TURSO_*, un fichier `vogt.db` local est utilisé.

## Élections, sécurité (rappel)
- Plusieurs élections, chacune avec 4 dates appliquées par le serveur. Dates de vote verrouillées pour le BDE dès le premier vote.
- Code email à 4 chiffres : 10 min, 5 essais, hashé. Emails jamais stockés (hash seulement).
- 1 téléphone = 1 vote par élection (empreinte + identifiant persistant) : doublon = quarantaine, votes "suspects" non comptés jusqu'à décision du Ghost.
- Limite : une empreinte n'est pas infaillible (faux positifs possibles, contournement par un autre navigateur). Utilise ALLOWED_DOMAIN pour n'accepter que les emails de l'école.
