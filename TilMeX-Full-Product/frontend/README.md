# TilMeX Full Product

A single-folder Node.js application with the Instagram-inspired TilMeX interface, social feed, stories, Explore, Reels, favourites, profiles, private messaging, WebRTC audio/video call signalling, and a self-contained offline 8-ball pool game.

## What is included
- Registration and login using **display name + password only**. No email or phone number is requested.
- Passwords are bcrypt-hashed; rate limits, JWT authentication and security headers remain enabled.
- Social feed with posts, image/video/audio media, likes, comments, follows and saved favourites.
- Profile editing and profile photo updates.
- Realtime private messages and online presence using Socket.IO.
- Voice/video call signalling using WebRTC. Calls require HTTPS/localhost, a camera/microphone and an internet connection; STUN is used for NAT traversal.
- Self-contained 8-ball billiards with AI, local 2-player and tournament modes, animated balls/table, score tracking, sound effects and generated background music.
- PWA service worker caches the game. When connectivity is lost after the app has been cached, it opens the billiards game; offline reloads fall back to the cached game.
- All frontend and backend files are in this one folder. There is no `public` directory.

## Run locally on Windows
1. Install Node.js 18 or newer.
2. Extract this folder.
3. Copy `.env.example` to `.env`. For local use, change `NODE_ENV=production` to `NODE_ENV=development` (or remove that line).
4. Open Command Prompt in this folder and run `npm install`.
5. Run `npm start` and open `http://localhost:3000`.
6. Keep the app open online once so the service worker can cache the offline game. Then test by disconnecting the network and refreshing.

## Deploy
This is a Node.js + Express + Socket.IO + SQLite app. **Do not use Netlify Drop**; static-only hosting will not run this backend or preserve its database. A `render.yaml` deployment blueprint is included for a Node web service with a persistent disk.

Set `NODE_ENV=production`, keep the generated `JWT_SECRET` and `SESSION_SECRET`, and use persistent paths for both `DB_PATH` and `SESSION_DB_DIR`. HTTPS and WebSocket support are required. Keep a single instance when using SQLite; use PostgreSQL and shared object storage for a multi-instance/high-scale deployment. Review the hosting plan and persistent-disk charges before confirming deployment.

## Offline behavior
The first visit must be online so the service worker can install and cache the shell and `offline-pool.html`. Afterwards, loss of connectivity automatically navigates to the cached game when the service worker controls the page; navigation/reload while offline is also served the cached pool game. Clearing browser site data removes the cache. Registration, feed, messages, uploads and calls still need the server and an internet connection.

## Authentication
Display names are unique without case sensitivity (1–50 characters). Passwords accept 6–72 characters; shorter passwords are easier to guess, so a longer passphrase is safer. Existing accounts in your old database are not included in this archive; back up and migrate your database if you need to preserve them.

## Validation and limitations
Run `npm run check` and `node offline-assets.test.js`. The JavaScript syntax and offline game asset checks are included. This archive has not been deployed to your hosting account or live-tested with real user registrations, cameras, microphones or multi-user traffic. You must deploy it with the required environment variables and persistent disk, then verify those live flows on the HTTPS domain. WebRTC calling can require a TURN server for networks where STUN alone cannot establish a peer connection.
