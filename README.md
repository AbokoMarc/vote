# VOGT ELECTIONS 2026

## Lancer
0. Si tu mets à jour une ancienne version : supprime `vogt.db` (le schéma a changé).
1. Installer Node.js 20+ (https://nodejs.org)
2. `npm install`
3. `cp .env.example .env` puis remplir (SECRET, SMTP_*, BDE_KEYS, GHOST_KEY, ELIGIBLE_VOTERS)
4. `npm start` puis ouvrir http://localhost:3000

Pages : `/` étudiant, `/admin` BDE (lecture seule), `/ghost` quarantaine (URL non liée).

## Emails réels
Sans SMTP_HOST, le code s'affiche seulement dans la console (mode test, aucun email envoyé).
Gmail : activer la validation en 2 étapes, créer un "mot de passe d'application", puis
SMTP_HOST=smtp.gmail.com, SMTP_PORT=587, SMTP_USER=ton@gmail.com, SMTP_PASS=mot de passe d'application.
Alternatives : Brevo, Resend, Mailjet (SMTP).

## Élections multiples
- Admin BDE (`/admin`) et Ghost (`/ghost`, onglet Élections) peuvent créer plusieurs élections, chacune avec 4 dates : ouverture/fermeture des candidatures, ouverture/fermeture du vote.
- Les dates sont appliquées par le serveur : impossible de candidater ou de voter hors fenêtre.
- Une fois les premiers votes reçus, seul le Ghost peut modifier les dates de vote. Dès que le vote ouvre, les candidatures sont figées.
- Un même téléphone peut voter dans deux élections différentes, mais pas deux fois dans la même.
- Les résultats par candidat s'affichent à l'admin seulement après la clôture du vote.
- L'élection de démonstration est créée au premier lancement à partir de `candidates.json`. Supprime-la ou ignore-la ensuite.

## Candidatures
Un étudiant vérifié par email envoie sa candidature (bio, 1 à 5 promesses, photo, vidéo de 30 s max). Elle reste "en attente" jusqu'à validation par le BDE ou le Ghost, qui peuvent la valider ou la refuser avec un motif. La durée de la vidéo est vérifiée côté serveur si `ffprobe` (paquet ffmpeg) est installé, sinon seulement côté navigateur : l'admin voit alors "durée non vérifiée" et regarde la vidéo avant de valider. Les fichiers sont dans `public/uploads`.

## Candidats, photos, vidéos (élection de démonstration)
- Textes : `candidates.json`
- Photos : remplacer `public/photos/*.svg` (ou mettre des .jpg et changer le chemin dans le JSON)
- Vidéos : remplacer `public/videos/<id>-pitch.mp4` (30 s) et `<id>-full.mp4` (optionnel). Les vidéos fournies sont des placeholders.
- Un bouton vidéo n'apparaît que si le fichier existe.

## Sécurité
- Code 4 chiffres : valable 10 min, 5 essais max, 3 envois / 10 min / email, stocké hashé.
- Emails jamais stockés : seulement un hash (HMAC). Le matricule vu par le Ghost vient de la partie avant @ (ex. 21g0201).
- 1 téléphone = 1 vote : empreinte (canvas, WebGL, audio, polices, écran, CPU, fuseau) + identifiant persistant.
  Un second email sur le même téléphone met l'appareil en quarantaine et les deux votes passent "suspect" (non comptés) jusqu'à décision du Ghost.
- Limite connue : une empreinte n'est pas infaillible. Deux téléphones identiques peuvent se ressembler, et un étudiant malin peut changer de navigateur. Le Ghost peut restaurer les faux positifs. Pour durcir : ALLOWED_DOMAIN (emails de l'école uniquement).
- En production : HTTPS, COOKIE_SECURE=1, TRUST_PROXY=1 derrière un proxy.
