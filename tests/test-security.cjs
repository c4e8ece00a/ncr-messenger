const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.join(__dirname, '..');

const security = fs.readFileSync(path.join(root, 'lib', 'security.js'), 'utf8');
const auth = fs.readFileSync(path.join(root, 'api', 'auth.js'), 'utf8');
const messages = fs.readFileSync(path.join(root, 'api', 'messages.js'), 'utf8');
const send = fs.readFileSync(path.join(root, 'api', 'send.js'), 'utf8');
const app = fs.readFileSync(path.join(root, 'public', 'app.js'), 'utf8');
const vercel = JSON.parse(fs.readFileSync(path.join(root, 'vercel.json'), 'utf8'));

assert.match(auth, /@node-rs\/argon2/);
assert.match(auth, /argon2id/);
assert.match(security, /HttpOnly; Secure; SameSite=Strict/);
assert.match(messages, /requireSession/);
assert.doesNotMatch(messages, /req\.query\?\.username/);
assert.match(send, /requireSession/);
assert.doesNotMatch(send, /body\.sender/);
assert.match(app, /api\/messages/);
assert.doesNotMatch(app, /apiGetMessages\(username\)/);
assert.match(vercel.headers[0].headers.find(h => h.key === 'Strict-Transport-Security').value, /max-age=31536000/);
assert.match(security, /X-Content-Type-Options/);
assert.match(security, /Content-Security-Policy/);

console.log('Security static checks: OK');
