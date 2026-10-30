const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const CryptoJS = require('crypto-js');
const fs = require('fs');
const path = require('path');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 3000;

// --- ANAHTARLAR ---
const JWT_SECRET = '75N6Wtyf4KtOgv1CQ6ici1rZz30pBxsHGxSYw9JcDPn';
const ENCRYPTION_KEY = 'd0ec01759c5c3498b69340e0343bbdf3e5830faed6beca2389339800debb6990';
const key = CryptoJS.enc.Hex.parse(ENCRYPTION_KEY);

const DB_FILE = path.join(__dirname, 'data.enc');
const UPLOAD_DIR = path.join(__dirname, 'uploads');

if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR);

// ---------- Şifreli JSON Veritabanı ----------
function loadDB() {
  if (!fs.existsSync(DB_FILE)) return { users: [], projects: [], files: [], captchas: {}, appData: [] };
  try {
    const encrypted = fs.readFileSync(DB_FILE, 'utf8');
    const decrypted = CryptoJS.AES.decrypt(encrypted, key, { mode: CryptoJS.mode.ECB, padding: CryptoJS.pad.Pkcs7 }).toString(CryptoJS.enc.Utf8);
    return JSON.parse(decrypted);
  } catch { return { users: [], projects: [], files: [], captchas: {}, appData: [] }; }
}

function saveDB(db) {
  const encrypted = CryptoJS.AES.encrypt(JSON.stringify(db), key, { mode: CryptoJS.mode.ECB, padding: CryptoJS.pad.Pkcs7 }).toString();
  fs.writeFileSync(DB_FILE, encrypted, 'utf8');
}

// ---------- Middleware ----------
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));
app.use('/api', rateLimit({ windowMs: 15 * 60 * 1000, max: 500, message: { error: 'Çok fazla istek attın kral, biraz bekle.' } }));

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => cb(null, Date.now() + '-' + Math.round(Math.random() * 1E9) + '.enc')
});
const upload = multer({ storage, limits: { fileSize: 50 * 1024 * 1024 } });

function randomString(length = 32) { return CryptoJS.lib.WordArray.random(length / 2).toString(); }

// Kullanıcı (Panel) Doğrulaması
function authenticateToken(req, res, next) {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.sendStatus(401);
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

// Uygulama (Geliştirici) Doğrulaması - API Key ile
function authenticateApp(req, res, next) {
  const apiKey = req.headers['x-api-key'];
  if (!apiKey) return res.status(401).json({ error: 'API Key eksik (x-api-key header ekle)' });
  
  const db = loadDB();
  const project = db.projects.find(p => p.apiKey === apiKey);
  if (!project) return res.status(403).json({ error: 'Geçersiz API Key' });
  
  req.project = project;
  next();
}

// ==========================================
// PANEL API ROTALARI
// ==========================================

app.get('/api/captcha', (req, res) => {
  const db = loadDB();
  const a = Math.floor(Math.random() * 10) + 1;
  const b = Math.floor(Math.random() * 10) + 1;
  const captchaId = randomString(16);
  db.captchas[captchaId] = { answer: a + b, createdAt: Date.now() };
  for (const id in db.captchas) { if (Date.now() - db.captchas[id].createdAt > 600000) delete db.captchas[id]; }
  saveDB(db);
  res.json({ captchaId, soru: `${a} + ${b} = ?` });
});

app.post('/api/register', async (req, res) => {
  try {
    const { username, password, captchaId, captchaAnswer } = req.body;
    const db = loadDB();
    const captcha = db.captchas[captchaId];
    if (!captcha || captcha.answer !== parseInt(captchaAnswer)) return res.status(400).json({ error: 'Captcha yanlış' });
    if (db.users.find(u => u.username === username)) return res.status(400).json({ error: 'Kullanıcı adı zaten var' });
    const hashed = await bcrypt.hash(password, 10);
    const user = { id: randomString(16), username, password: hashed, createdAt: Date.now() };
    db.users.push(user);
    delete db.captchas[captchaId];
    saveDB(db);
    const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: user.id, username: user.username } });
  } catch { res.status(500).json({ error: 'Sunucu hatası' }); }
});

app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const db = loadDB();
    const user = db.users.find(u => u.username === username);
    if (!user || !(await bcrypt.compare(password, user.password))) return res.status(401).json({ error: 'Geçersiz bilgiler' });
    const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: user.id, username: user.username } });
  } catch { res.status(500).json({ error: 'Sunucu hatası' }); }
});

app.post('/api/projects', authenticateToken, (req, res) => {
  try {
    const { name, packageName } = req.body;
    const db = loadDB();
    const project = { id: randomString(16), userId: req.user.id, name, packageName, apiKey: randomString(32), createdAt: Date.now() };
    db.projects.push(project);
    saveDB(db);
    res.json({ project });
  } catch { res.status(500).json({ error: 'Hata' }); }
});

app.get('/api/projects', authenticateToken, (req, res) => {
  const db = loadDB();
  res.json({ projects: db.projects.filter(p => p.userId === req.user.id) });
});

app.post('/api/upload', authenticateToken, upload.single('file'), (req, res) => {
  try {
    const { projectId } = req.body;
    if (!req.file) return res.status(400).json({ error: 'Dosya yok' });
    const fileData = fs.readFileSync(req.file.path);
    const encryptedData = CryptoJS.AES.encrypt(fileData.toString('base64'), key).toString();
    fs.writeFileSync(req.file.path, encryptedData, 'utf8');
    const db = loadDB();
    const fileId = randomString(16);
    db.files.push({ id: fileId, projectId, userId: req.user.id, filename: req.file.originalname, mimetype: req.file.mimetype, path: req.file.filename, size: req.file.size, createdAt: Date.now() });
    saveDB(db);
    res.json({ fileId, filename: req.file.originalname });
  } catch { res.status(500).json({ error: 'Dosya yüklenemedi' }); }
});

// ==========================================
// GELİŞTİRİCİ / UYGULAMA API ROTALARI (API KEY İLE)
// ==========================================

// 1. Uygulama Verisi Kaydet (Skor, Sohbet, Envanter vs.)
app.post('/api/app/data', authenticateApp, (req, res) => {
  try {
    const { key, value } = req.body;
    if (!key || value === undefined) return res.status(400).json({ error: 'key ve value gerekli' });
    
    const db = loadDB();
    // Aynı key varsa güncelle, yoksa ekle
    const existingData = db.appData.find(d => d.projectId === req.project.id && d.key === key);
    
    if (existingData) {
      existingData.value = value;
      existingData.updatedAt = Date.now();
    } else {
      db.appData.push({
        projectId: req.project.id,
        key,
        value,
        createdAt: Date.now()
      });
    }
    saveDB(db);
    res.json({ success: true, message: 'Veri kaydedildi' });
  } catch { res.status(500).json({ error: 'Sunucu hatası' }); }
});

// 2. Uygulama Verisi Oku
app.get('/api/app/data/:key', authenticateApp, (req, res) => {
  const db = loadDB();
  const data = db.appData.find(d => d.projectId === req.project.id && d.key === req.params.key);
  if (!data) return res.status(404).json({ error: 'Veri bulunamadı' });
  res.json({ key: data.key, value: data.value, updatedAt: data.updatedAt });
});

// 3. Uygulamanın Tüm Verilerini Listele
app.get('/api/app/data', authenticateApp, (req, res) => {
  const db = loadDB();
  const data = db.appData.filter(d => d.projectId === req.project.id);
  res.json({ data });
});

// 4. Uygulama İçin Kullanıcı (Oyuncu) Kaydı
app.post('/api/app/player/register', authenticateApp, async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Kullanıcı adı ve şifre gerekli' });
    
    const db = loadDB();
    const playerId = req.project.id + '_' + username; // Projeye özel oyuncu ID
    
    if (db.appData.find(d => d.key === 'player_' + playerId)) {
      return res.status(400).json({ error: 'Bu oyuncu adı zaten alınmış' });
    }
    
    const hashed = await bcrypt.hash(password, 10);
    db.appData.push({
      projectId: req.project.id,
      key: 'player_' + playerId,
      value: { username, password: hashed, createdAt: Date.now() },
      createdAt: Date.now()
    });
    saveDB(db);
    res.json({ success: true, playerId, username });
  } catch { res.status(500).json({ error: 'Sunucu hatası' }); }
});

// 5. Uygulama İçin Kullanıcı (Oyuncu) Girişi
app.post('/api/app/player/login', authenticateApp, async (req, res) => {
  try {
    const { username, password } = req.body;
    const db = loadDB();
    const playerId = req.project.id + '_' + username;
    const playerData = db.appData.find(d => d.projectId === req.project.id && d.key === 'player_' + playerId);
    
    if (!playerData || !(await bcrypt.compare(password, playerData.value.password))) {
      return res.status(401).json({ error: 'Geçersiz kullanıcı adı veya şifre' });
    }
    
    res.json({ success: true, playerId, username });
  } catch { res.status(500).json({ error: 'Sunucu hatası' }); }
});

// ==========================================
// ARAYÜZ (FRONTEND)
// ==========================================
app.get('/', (req, res) => {
  res.send(`
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Kralın Backend Paneli</title>
    <style>
        :root { --bg: #121212; --card: #1e1e1e; --text: #e0e0e0; --primary: #bb86fc; --error: #cf6679; --success: #03dac6; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: var(--bg); color: var(--text); margin: 0; padding: 20px; display: flex; justify-content: center; align-items: center; min-height: 100vh; }
        .container { background: var(--card); padding: 30px; border-radius: 12px; box-shadow: 0 8px 32px rgba(0,0,0,0.5); width: 100%; max-width: 900px; }
        h1, h2, h3 { color: var(--primary); margin-top: 0; }
        input, button { width: 100%; padding: 12px; margin: 8px 0; border-radius: 8px; border: 1px solid #333; background: #2c2c2c; color: white; box-sizing: border-box; }
        button { background: var(--primary); color: #000; font-weight: bold; cursor: pointer; border: none; transition: 0.2s; }
        button:hover { opacity: 0.8; }
        .error { color: var(--error); font-size: 14px; margin-top: 10px; }
        .success { color: var(--success); font-size: 14px; margin-top: 10px; }
        .hidden { display: none; }
        .project-card { background: #2c2c2c; padding: 15px; border-radius: 8px; margin-bottom: 15px; border-left: 4px solid var(--primary); }
        .code-block { background: #000; padding: 10px; border-radius: 6px; font-family: monospace; font-size: 13px; overflow-x: auto; white-space: pre-wrap; word-wrap: break-word; color: #00ff00; margin-top: 10px; }
        .flex { display: flex; gap: 10px; align-items: center; }
        .flex button { width: auto; margin: 0; }
        .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
        .header button { width: auto; background: var(--error); color: white; }
        .tab-btn { background: #333; color: white; margin-bottom: 10px; }
        .tab-btn:hover { background: #444; }
    </style>
</head>
<body>

<div class="container" id="authView">
    <h1 style="text-align: center;">Sisteme Giriş</h1>
    <div id="loginForm">
        <input type="text" id="logUser" placeholder="Kullanıcı Adı">
        <input type="password" id="logPass" placeholder="Şifre">
        <button onclick="login()">Giriş Yap</button>
        <p style="text-align: center; font-size: 14px; margin-top: 15px;">Hesabın yok mu? <a href="#" onclick="toggleAuth()" style="color: var(--primary);">Kayıt Ol</a></p>
    </div>
    <div id="registerForm" class="hidden">
        <input type="text" id="regUser" placeholder="Kullanıcı Adı">
        <input type="password" id="regPass" placeholder="Şifre">
        <div class="flex">
            <input type="text" id="regCaptchaInput" placeholder="Cevap" style="flex: 1;">
            <span id="captchaQuestion" style="font-weight: bold; min-width: 80px; text-align: center;"></span>
            <button onclick="loadCaptcha()" style="padding: 10px;">↻</button>
        </div>
        <button onclick="register()">Kayıt Ol</button>
        <p style="text-align: center; font-size: 14px; margin-top: 15px;">Zaten üye misin? <a href="#" onclick="toggleAuth()" style="color: var(--primary);">Giriş Yap</a></p>
    </div>
    <div id="authError" class="error"></div>
</div>

<div class="container hidden" id="dashboardView">
    <div class="header">
        <h2>Kralın Paneli</h2>
        <button onclick="logout()">Çıkış Yap</button>
    </div>
    
    <div style="background: #252525; padding: 20px; border-radius: 8px; margin-bottom: 20px;">
        <h3>Yeni Proje Oluştur</h3>
        <input type="text" id="projName" placeholder="Uygulama Adı (Örn: Süper Oyun)">
        <input type="text" id="projPackage" placeholder="Paket Adı (Örn: com.kral.oyun)">
        <button onclick="createProject()">Proje Oluştur</button>
        <div id="projMsg"></div>
    </div>

    <h3>Projelerin & Bağlantı Rehberi</h3>
    <div id="projectsList"></div>
</div>

<script>
    const API_URL = window.location.origin;
    let token = localStorage.getItem('token');
    let captchaId = '';

    if (token) { showDashboard(); }

    function toggleAuth() {
        document.getElementById('loginForm').classList.toggle('hidden');
        document.getElementById('registerForm').classList.toggle('hidden');
        if (!document.getElementById('registerForm').classList.contains('hidden')) loadCaptcha();
    }

    async function loadCaptcha() {
        const res = await fetch(API_URL + '/api/captcha');
        const data = await res.json();
        captchaId = data.captchaId;
        document.getElementById('captchaQuestion').innerText = data.soru;
    }

    async function register() {
        const username = document.getElementById('regUser').value;
        const password = document.getElementById('regPass').value;
        const captchaAnswer = document.getElementById('regCaptchaInput').value;
        const res = await fetch(API_URL + '/api/register', {
            method: 'POST', headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ username, password, captchaId, captchaAnswer })
        });
        const data = await res.json();
        if (res.ok) { localStorage.setItem('token', data.token); showDashboard(); }
        else { document.getElementById('authError').innerText = data.error; loadCaptcha(); }
    }

    async function login() {
        const username = document.getElementById('logUser').value;
        const password = document.getElementById('logPass').value;
        const res = await fetch(API_URL + '/api/login', {
            method: 'POST', headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ username, password })
        });
        const data = await res.json();
        if (res.ok) { localStorage.setItem('token', data.token); showDashboard(); }
        else { document.getElementById('authError').innerText = data.error; }
    }

    function logout() {
        localStorage.removeItem('token'); location.reload();
    }

    async function showDashboard() {
        document.getElementById('authView').classList.add('hidden');
        document.getElementById('dashboardView').classList.remove('hidden');
        loadProjects();
    }

    async function createProject() {
        const name = document.getElementById('projName').value;
        const packageName = document.getElementById('projPackage').value;
        const res = await fetch(API_URL + '/api/projects', {
            method: 'POST', headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token },
            body: JSON.stringify({ name, packageName })
        });
        if (res.ok) { document.getElementById('projMsg').innerHTML = '<span class="success">Proje oluşturuldu!</span>'; loadProjects(); }
    }

    async function loadProjects() {
        const res = await fetch(API_URL + '/api/projects', { headers: { 'Authorization': 'Bearer ' + token } });
        const data = await res.json();
        const list = document.getElementById('projectsList');
        list.innerHTML = '';
        data.projects.forEach(p => {
            list.innerHTML += \`
                <div class="project-card">
                    <h4>\${p.name} <span style="font-size:12px; color:gray;">(\${p.packageName})</span></h4>
                    <div class="code-block">
                        <strong>API KEY (Gizli Tut):</strong> \${p.apiKey}
                    </div>
                    
                    <button class="tab-btn" onclick="toggleGuide('\${p.id}')">📖 Uygulamaya Nasıl Bağlanırım? (Kodları Göster)</button>
                    
                    <div id="guide-\${p.id}" class="hidden" style="background: #1a1a1a; padding: 15px; border-radius: 8px; margin-top: 10px; border: 1px solid #333;">
                        <p style="font-size: 13px; color: #aaa;">Bu API'yi kendi oyununa veya uygulamana bağlamak için aşağıdaki JavaScript kodlarını kullanabilirsin. İstediğin her şeyi (skor, sohbet, envanter) kaydedebilirsin.</p>
                        
                        <strong style="font-size: 13px; color: var(--primary);">1. Veri Kaydetme (Örn: Skor):</strong>
                        <div class="code-block">
fetch("\${API_URL}/api/app/data", {
  method: "POST",
  headers: {
    "Content-Type": "application/json",
    "x-api-key": "\${p.apiKey}"
  },
  body: JSON.stringify({
    key: "skorTablosu",
    value: [ { isim: "Kral", skor: 9999 } ]
  })
});</div>

                        <strong style="font-size: 13px; color: var(--primary);">2. Veri Okuma:</strong>
                        <div class="code-block">
fetch("\${API_URL}/api/app/data/skorTablosu", {
  headers: { "x-api-key": "\${p.apiKey}" }
})
.then(res => res.json())
.then(data => console.log("Skorlar:", data.value));</div>

                        <strong style="font-size: 13px; color: var(--primary);">3. Oyuncu Kaydı (Uygulamanın Kendi İçin):</strong>
                        <div class="code-block">
fetch("\${API_URL}/api/app/player/register", {
  method: "POST",
  headers: {
    "Content-Type": "application/json",
    "x-api-key": "\${p.apiKey}"
  },
  body: JSON.stringify({ username: "oyuncu1", password: "sifre123" })
});</div>

                        <strong style="font-size: 13px; color: var(--primary);">4. Oyuncu Girişi:</strong>
                        <div class="code-block">
fetch("\${API_URL}/api/app/player/login", {
  method: "POST",
  headers: {
    "Content-Type": "application/json",
    "x-api-key": "\${p.apiKey}"
  },
  body: JSON.stringify({ username: "oyuncu1", password: "sifre123" })
});</div>

                        <p style="font-size: 12px; color: #888; margin-top: 10px;">* Bu kodları kendi uygulamanın (örneğin HTML5 oyununun) içine yapıştırarak sunucumuzu backend olarak kullanabilirsin.</p>
                    </div>
                </div>
            \`;
        });
    }

    function toggleGuide(id) {
        document.getElementById('guide-' + id).classList.toggle('hidden');
    }
</script>
</body>
</html>
  `);
});

app.listen(PORT, () => console.log(`Sunucu ${PORT} portunda hazır kral!`));
