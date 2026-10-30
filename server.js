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
  if (!fs.existsSync(DB_FILE)) return { users: [], projects: [], files: [], captchas: {}, appData: [], bannedIps: [], verifyAttempts: {} };
  try {
    const encrypted = fs.readFileSync(DB_FILE, 'utf8');
    const decrypted = CryptoJS.AES.decrypt(encrypted, key, { mode: CryptoJS.mode.ECB, padding: CryptoJS.pad.Pkcs7 }).toString(CryptoJS.enc.Utf8);
    const db = JSON.parse(decrypted);
    if (!db.bannedIps) db.bannedIps = [];
    if (!db.verifyAttempts) db.verifyAttempts = {};
    return db;
  } catch { return { users: [], projects: [], files: [], captchas: {}, appData: [], bannedIps: [], verifyAttempts: {} }; }
}

function saveDB(db) {
  const encrypted = CryptoJS.AES.encrypt(JSON.stringify(db), key, { mode: CryptoJS.mode.ECB, padding: CryptoJS.pad.Pkcs7 }).toString();
  fs.writeFileSync(DB_FILE, encrypted, 'utf8');
}

// ---------- IP BAN KONTROLÜ ----------
function checkBan(req, res, next) {
  const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
  const db = loadDB();
  if (db.bannedIps.includes(clientIp)) {
    return res.status(403).send("<div style='font-family:sans-serif; text-align:center; margin-top:20%'><h1 style='color:#ef4444'>Vantorium Base | Erişim Engellendi</h1><p>IP adresiniz güvenlik ihlali nedeniyle kalıcı olarak banlandı.</p></div>");
  }
  req.clientIp = clientIp;
  next();
}

app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));
app.use(checkBan);

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  handler: (req, res) => {
    const db = loadDB();
    if (!db.bannedIps.includes(req.clientIp)) { db.bannedIps.push(req.clientIp); saveDB(db); }
    res.status(429).send("<div style='font-family:sans-serif; text-align:center; margin-top:20%'><h1 style='color:#ef4444'>Vantorium Base | Çok Fazla İstek</h1><p>IP adresiniz banlandı.</p></div>");
  }
});
app.use('/api', limiter);

const upload = multer({ dest: UPLOAD_DIR, limits: { fileSize: 50 * 1024 * 1024 } });

function randomString(length = 32) { return CryptoJS.lib.WordArray.random(length / 2).toString(); }

function authenticateToken(req, res, next) {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Yetkisiz erişim' });
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Oturum süren dolmuş' });
    req.user = user;
    next();
  });
}

function authenticateApp(req, res, next) {
  const apiKey = req.headers['x-api-key'];
  if (!apiKey) return res.status(401).json({ error: 'API Key eksik' });
  const db = loadDB();
  const project = db.projects.find(p => p.apiKey === apiKey);
  if (!project) return res.status(403).json({ error: 'Geçersiz API Key' });
  
  if (project.allowedOrigin && project.allowedOrigin !== "*") {
    const origin = req.headers.origin || req.headers.referer || "";
    if (!origin.includes(project.allowedOrigin)) {
      return res.status(403).json({ error: 'Klonlama Koruması: Farklı adresten çağrılıyor.' });
    }
  }
  req.project = project;
  next();
}

// ==========================================
// API ROTALARI
// ==========================================

app.post('/api/verify-human', (req, res) => {
  const { interactionTime, mouseMoved, captchaId, captchaAnswer } = req.body;
  const db = loadDB();
  const clientIp = req.clientIp;

  if (interactionTime < 800 || mouseMoved === false) {
    if (!db.bannedIps.includes(clientIp)) { db.bannedIps.push(clientIp); saveDB(db); }
    return res.status(403).json({ error: 'Bot tespit edildi! IP adresiniz kalıcı olarak banlandı.' });
  }

  const captcha = db.captchas[captchaId];
  if (!captcha || captcha.answer !== parseInt(captchaAnswer)) {
    db.verifyAttempts[clientIp] = (db.verifyAttempts[clientIp] || 0) + 1;
    const remaining = 3 - db.verifyAttempts[clientIp];
    
    if (remaining <= 0) {
      if (!db.bannedIps.includes(clientIp)) { db.bannedIps.push(clientIp); saveDB(db); }
      return res.status(403).json({ error: '3 kez yanlış yaptınız! IP adresiniz kalıcı olarak banlandı.' });
    }
    
    saveDB(db);
    return res.status(400).json({ error: `Captcha yanlış! Kalan hakkınız: ${remaining}`, remainingAttempts: remaining });
  }

  delete db.captchas[captchaId];
  if (db.verifyAttempts[clientIp]) delete db.verifyAttempts[clientIp];
  saveDB(db);
  res.json({ success: true, verified: true });
});

app.get('/api/generate-captcha', (req, res) => {
  const db = loadDB();
  const a = Math.floor(Math.random() * 10) + 1;
  const b = Math.floor(Math.random() * 10) + 1;
  const captchaId = randomString(16);
  db.captchas[captchaId] = { answer: a + b, createdAt: Date.now() };
  for (const id in db.captchas) { if (Date.now() - db.captchas[id].createdAt > 600000) delete db.captchas[id]; }
  saveDB(db);
  res.json({ captchaId, soru: `${a} + ${b}` });
});

app.get('/api/captcha', (req, res) => {
  const db = loadDB();
  const a = Math.floor(Math.random() * 10) + 1;
  const b = Math.floor(Math.random() * 10) + 1;
  const captchaId = randomString(16);
  db.captchas[captchaId] = { answer: a + b, createdAt: Date.now() };
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

app.get('/api/projects', authenticateToken, (req, res) => {
  const db = loadDB();
  res.json({ projects: db.projects.filter(p => p.userId === req.user.id) });
});

app.post('/api/projects', authenticateToken, (req, res) => {
  try {
    const { name, packageName, type } = req.body;
    if (!name || !packageName) return res.status(400).json({ error: 'Boş alan bırakma' });
    const db = loadDB();
    const project = { id: randomString(16), userId: req.user.id, name, packageName, type: type || 'Web', allowedOrigin: "*", apiKey: randomString(32), createdAt: Date.now() };
    db.projects.push(project);
    saveDB(db);
    res.json({ project });
  } catch { res.status(500).json({ error: 'Hata' }); }
});

app.put('/api/projects/:id/settings', authenticateToken, (req, res) => {
  try {
    const { allowedOrigin } = req.body;
    const db = loadDB();
    const project = db.projects.find(p => p.id === req.params.id && p.userId === req.user.id);
    if (!project) return res.status(403).json({ error: 'Yetkisiz' });
    project.allowedOrigin = allowedOrigin || "*";
    saveDB(db);
    res.json({ success: true, allowedOrigin: project.allowedOrigin });
  } catch { res.status(500).json({ error: 'Hata' }); }
});

app.post('/api/app/data', authenticateApp, (req, res) => {
  try {
    const { key, value } = req.body;
    const db = loadDB();
    const existingData = db.appData.find(d => d.projectId === req.project.id && d.key === key);
    if (existingData) { existingData.value = value; existingData.updatedAt = Date.now(); } 
    else { db.appData.push({ projectId: req.project.id, key, value, createdAt: Date.now() }); }
    saveDB(db);
    res.json({ success: true, message: 'Veri kaydedildi' });
  } catch { res.status(500).json({ error: 'Sunucu hatası' }); }
});

// ==========================================
// VANTORIUM BASE FRONTEND
// ==========================================
app.get('/', (req, res) => {
  res.send(`
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vantorium Base | Console</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <script>
        tailwind.config = {
            theme: {
                extend: {
                    fontFamily: { sans: ['"Plus Jakarta Sans"', 'sans-serif'] },
                    colors: { primary: '#4f46e5', secondary: '#7c3aed', dark: '#0f172a' }
                }
            }
        }
    </script>
    <style>
        body { font-family: 'Plus Jakarta Sans', sans-serif; background-color: #f8fafc; color: #0f172a; }
        body { user-select: none; -webkit-user-select: none; }
        input, textarea, .select-text { user-select: text !important; -webkit-user-select: text !important; }
        
        .glass-panel { background: rgba(255, 255, 255, 0.7); backdrop-filter: blur(16px); border: 1px solid rgba(255, 255, 255, 0.4); box-shadow: 0 4px 24px -4px rgba(0,0,0,0.06); }
        .card-hover { transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1); }
        .card-hover:hover { transform: translateY(-3px); box-shadow: 0 20px 40px -8px rgba(79, 70, 229, 0.1); border-color: rgba(79, 70, 229, 0.2); }
        
        .btn-primary { background: linear-gradient(135deg, #4f46e5 0%, #7c3aed 100%); color: #fff; transition: all 0.3s; box-shadow: 0 4px 12px rgba(79, 70, 229, 0.2); }
        .btn-primary:hover { transform: translateY(-1px); box-shadow: 0 8px 20px rgba(79, 70, 229, 0.3); opacity: 0.95; }
        .btn-outline { background: #fff; border: 1px solid #e2e8f0; transition: all 0.2s; }
        .btn-outline:hover { background: #f8fafc; border-color: #cbd5e1; }
        
        .input-field { background: #fff; border: 1px solid #e2e8f0; transition: all 0.2s; }
        .input-field:focus { outline: none; border-color: #6366f1; box-shadow: 0 0 0 4px rgba(99, 102, 241, 0.1); }
        
        .toast { animation: slideInRight 0.4s cubic-bezier(0.4, 0, 0.2, 1) forwards; }
        @keyframes slideInRight { from { transform: translateX(100%); opacity: 0; } to { transform: translateX(0); opacity: 1; } }
        .fade-in { animation: fadeIn 0.5s ease-out forwards; }
        @keyframes fadeIn { from { opacity: 0; transform: translateY(15px); } to { opacity: 1; transform: translateY(0); } }
        
        .spinner { border: 2px solid rgba(79, 70, 229, 0.1); border-left-color: #4f46e5; border-radius: 50%; width: 20px; height: 20px; animation: spin 0.8s linear infinite; }
        @keyframes spin { to { transform: rotate(360deg); } }
        
        .glow { position: absolute; width: 400px; height: 400px; background: radial-gradient(circle, rgba(124,58,237,0.15) 0%, rgba(255,255,255,0) 70%); border-radius: 50%; z-index: -1; }
    </style>
</head>
<body class="antialiased overflow-hidden text-[15px] relative">

<div class="glow top-0 left-0"></div>
<div class="glow bottom-0 right-0"></div>

<div id="toastContainer" class="fixed top-4 right-4 z-[100] flex flex-col gap-2"></div>

<!-- DOĞRULAMA EKRANI -->
<div id="verifyScreen" class="fixed inset-0 bg-white/80 backdrop-blur-md z-50 flex items-center justify-center transition-all duration-700">
    <div class="w-full max-w-[440px] px-6 fade-in">
        <div class="flex flex-col items-center mb-10">
            <div class="w-14 h-14 bg-gradient-to-br from-indigo-600 to-purple-600 rounded-2xl flex items-center justify-center text-white font-bold text-2xl shadow-xl shadow-indigo-500/30 mb-4">V</div>
            <h1 class="text-3xl font-bold tracking-tight text-gray-900">Vantorium Base</h1>
            <p class="text-sm text-gray-500 mt-2">Güvenlik Duvarı</p>
        </div>
        
        <div id="humanBox" class="bg-white p-6 rounded-2xl border border-gray-100 shadow-[0_8px_30px_rgb(0,0,0,0.04)] flex items-center justify-between cursor-pointer card-hover" onclick="startVerifyFlow()">
            <div class="flex items-center gap-4">
                <div class="w-7 h-7 border-2 border-gray-300 rounded-lg flex items-center justify-center bg-white transition-colors" id="checkBox">
                    <div id="checkSpinner" class="hidden spinner"></div>
                    <svg class="w-5 h-5 text-white hidden" id="checkIcon" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="3" d="M5 13l4 4L19 7"></path></svg>
                </div>
                <span class="text-gray-800 font-semibold">İnsan olduğumu onayla</span>
            </div>
            <svg class="w-7 h-7 text-indigo-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path></svg>
        </div>
        
        <div id="captchaModal" class="hidden bg-white p-6 rounded-2xl border border-gray-100 shadow-lg mt-4 fade-in">
            <div class="flex justify-between items-center mb-4">
                <p class="text-sm text-gray-600 font-medium">İşlemi tamamlayın:</p>
                <span id="attemptsDisplay" class="text-xs font-bold px-2.5 py-1 bg-red-50 text-red-600 rounded-lg border border-red-100">Kalan Hak: 3</span>
            </div>
            <div class="flex items-center gap-4 mb-5">
                <div class="bg-indigo-50 border border-indigo-100 px-6 py-3 rounded-xl font-mono text-xl font-bold text-indigo-700" id="captchaQuestion">-</div>
                <span class="text-gray-400 font-bold">=</span>
                <input type="number" id="captchaInput" class="flex-1 input-field px-4 py-3 rounded-xl text-xl font-bold text-center" placeholder="?">
            </div>
            <button id="captchaBtn" onclick="submitCaptcha()" class="w-full btn-primary font-bold py-3.5 rounded-xl">Doğrula</button>
        </div>
    </div>
</div>

<!-- GİRİŞ EKRANI -->
<div id="authView" class="hidden w-full min-h-screen flex items-center justify-center p-4 relative z-10">
    <div class="w-full max-w-[420px] glass-panel p-8 rounded-3xl fade-in">
        <div class="flex justify-center mb-6">
            <div class="w-14 h-14 bg-gradient-to-br from-indigo-600 to-purple-600 rounded-2xl flex items-center justify-center text-white font-bold text-2xl shadow-lg shadow-indigo-500/30">V</div>
        </div>
        <h1 class="text-2xl font-bold text-center mb-8 text-gray-900 tracking-tight">Vantorium Base</h1>
        
        <div id="loginForm">
            <div class="space-y-4 mb-6">
                <input type="text" id="logUser" placeholder="Kullanıcı Adı" class="w-full input-field p-4 rounded-xl text-sm font-medium">
                <input type="password" id="logPass" placeholder="Şifre" class="w-full input-field p-4 rounded-xl text-sm font-medium">
            </div>
            <button onclick="login()" class="w-full btn-primary font-bold p-4 rounded-xl text-sm">Giriş Yap</button>
            <p class="text-center text-sm text-gray-500 mt-6 font-medium">Hesabın yok mu? <a href="#" onclick="toggleAuth()" class="text-indigo-600 font-bold hover:underline">Kayıt Ol</a></p>
        </div>

        <div id="registerForm" class="hidden">
            <div class="space-y-4 mb-6">
                <input type="text" id="regUser" placeholder="Kullanıcı Adı" class="w-full input-field p-4 rounded-xl text-sm font-medium">
                <input type="password" id="regPass" placeholder="Şifre" class="w-full input-field p-4 rounded-xl text-sm font-medium">
                <div class="flex gap-2">
                    <input type="number" id="regCaptchaInput" placeholder="Cevap" class="flex-1 input-field p-4 rounded-xl text-sm font-medium">
                    <div class="bg-gray-50 border border-gray-200 p-4 rounded-xl font-mono text-sm font-bold flex items-center justify-center min-w-[100px]" id="captchaQuestion2">-</div>
                    <button onclick="loadCaptcha()" class="bg-white border border-gray-200 hover:bg-gray-50 px-4 rounded-xl text-gray-700 transition">↻</button>
                </div>
            </div>
            <button onclick="register()" class="w-full btn-primary font-bold p-4 rounded-xl text-sm">Hesap Oluştur</button>
            <p class="text-center text-sm text-gray-500 mt-6 font-medium">Zaten üye misin? <a href="#" onclick="toggleAuth()" class="text-indigo-600 font-bold hover:underline">Giriş Yap</a></p>
        </div>
    </div>
</div>

<!-- DASHBOARD -->
<div id="dashboardView" class="hidden w-full h-screen flex fade-in relative z-10">
    <aside class="w-64 border-r border-gray-200/60 bg-white/50 backdrop-blur-xl flex flex-col h-full z-10">
        <div class="p-6 flex items-center gap-3">
            <div class="w-9 h-9 bg-gradient-to-br from-indigo-600 to-purple-600 rounded-xl flex items-center justify-center text-white font-bold text-lg shadow-md shadow-indigo-500/20">V</div>
            <span class="font-bold text-gray-900 tracking-tight text-lg">Vantorium <span class="text-indigo-600">Base</span></span>
        </div>
        <nav class="flex-1 px-4 space-y-1 mt-2">
            <a href="#" class="flex items-center gap-3 px-4 py-3 bg-indigo-50/80 text-indigo-700 rounded-xl text-sm font-bold transition">
                <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10"></path></svg>
                Projeler
            </a>
        </nav>
        <div class="p-4 border-t border-gray-200/60">
            <button onclick="logout()" class="flex items-center gap-3 w-full px-4 py-3 text-sm font-semibold text-gray-500 hover:text-red-600 hover:bg-red-50 rounded-xl transition">
                <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1"></path></svg>
                Çıkış Yap
            </button>
        </div>
    </aside>

    <main class="flex-1 h-full overflow-y-auto p-8 md:p-12">
        <div class="max-w-5xl mx-auto">
            <div class="flex justify-between items-end mb-10">
                <div>
                    <h1 class="text-3xl font-extrabold text-gray-900 tracking-tight">Projeler</h1>
                    <p class="text-sm text-gray-500 mt-2 font-medium">Hoş geldin, <span id="userNameDisplay" class="text-indigo-600 font-bold"></span>. Sistemlerini buradan yönet.</p>
                </div>
            </div>

            <!-- Proje Oluşturma Formu -->
            <div class="bg-white border border-gray-200/60 p-3 rounded-2xl shadow-sm mb-12 flex gap-3">
                <input type="text" id="projName" placeholder="Proje Adı" class="flex-1 input-field p-3.5 rounded-xl text-sm border-transparent bg-gray-50 hover:bg-white focus:bg-white transition">
                <input type="text" id="projPackage" placeholder="Paket Adı (com.ornek)" class="flex-1 input-field p-3.5 rounded-xl text-sm border-transparent bg-gray-50 hover:bg-white focus:bg-white transition">
                <select id="projType" class="input-field p-3.5 rounded-xl text-sm border-transparent bg-gray-50 hover:bg-white w-44 font-medium">
                    <option value="Web">Web Uygulaması</option>
                    <option value="Mobil">Mobil Uygulama</option>
                    <option value="Oyun">Oyun</option>
                    <option value="API">Backend API</option>
                </select>
                <button onclick="createProject()" class="btn-primary font-bold px-8 py-3.5 rounded-xl text-sm whitespace-nowrap">Oluştur</button>
            </div>

            <!-- Proje Listesi -->
            <div id="projectsList" class="grid grid-cols-1 gap-6"></div>
        </div>
    </main>
</div>

<script>
    document.addEventListener('contextmenu', e => {
        if (e.target.closest('.select-text') || e.target.tagName === 'INPUT') return;
        e.preventDefault();
    });
    document.addEventListener('keydown', e => {
        if (e.key === 'F12' || (e.ctrlKey && e.shiftKey && e.key === 'I') || (e.ctrlKey && e.key === 'u')) {
            e.preventDefault(); showToast("Güvenlik İhlali: Kaynak kodu inceleme engellendi!", "error");
        }
    });

    function copyToClipboard(text) {
        navigator.clipboard.writeText(text).then(() => {
            showToast("API Key panoya kopyalandı!", "success");
        }).catch(() => {
            const textarea = document.createElement('textarea'); textarea.value = text;
            document.body.appendChild(textarea); textarea.select(); document.execCommand('copy');
            document.body.removeChild(textarea); showToast("API Key panoya kopyalandı!", "success");
        });
    }

    const API_URL = window.location.origin;
    let token = localStorage.getItem('token');
    let verifyCaptchaId = '';
    let regCaptchaId = '';
    let pageLoadTime = Date.now();
    let mouseMoved = false;

    document.addEventListener('mousemove', () => { mouseMoved = true; });

    if (localStorage.getItem('humanVerified') === 'true') {
        document.getElementById('verifyScreen').classList.add('hidden');
        if (token) { showDashboard(); } else { document.getElementById('authView').classList.remove('hidden'); }
    }

    async function startVerifyFlow() {
        document.getElementById('checkSpinner').classList.remove('hidden');
        document.getElementById('humanBox').classList.add('pointer-events-none');
        
        setTimeout(async () => {
            document.getElementById('checkSpinner').classList.add('hidden');
            document.getElementById('checkBox').classList.replace('border-gray-300', 'bg-indigo-600 border-indigo-600');
            document.getElementById('checkIcon').classList.remove('hidden');
            
            document.getElementById('captchaModal').classList.remove('hidden');
            
            const res = await fetch(API_URL + '/api/generate-captcha');
            const data = await res.json();
            verifyCaptchaId = data.captchaId;
            document.getElementById('captchaQuestion').innerText = data.soru;
            document.getElementById('captchaInput').focus();
        }, 1000);
    }

    async function submitCaptcha() {
        const answer = document.getElementById('captchaInput').value;
        if (!answer) return showToast("Cevabı gir!", "error");

        const btn = document.getElementById('captchaBtn');
        btn.disabled = true;
        btn.innerText = "Kontrol ediliyor...";

        const interactionTime = Date.now() - pageLoadTime;
        const res = await fetch(API_URL + '/api/verify-human', {
            method: 'POST', headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ interactionTime, mouseMoved, captchaId: verifyCaptchaId, captchaAnswer: answer })
        });
        const data = await res.json();

        if (res.ok) {
            localStorage.setItem('humanVerified', 'true');
            document.getElementById('verifyScreen').style.opacity = '0';
            setTimeout(() => {
                document.getElementById('verifyScreen').classList.add('hidden');
                if (token) { showDashboard(); } else { document.getElementById('authView').classList.remove('hidden'); }
            }, 500);
        } else {
            if (res.status === 403) {
                showToast(data.error, "error");
                btn.innerText = "Banlandınız!";
                setTimeout(() => window.location.reload(), 2000);
            } else {
                showToast(data.error, "error");
                document.getElementById('attemptsDisplay').innerText = `Kalan Hak: ${data.remainingAttempts}`;
                
                const newCaptcha = await fetch(API_URL + '/api/generate-captcha');
                const newData = await newCaptcha.json();
                verifyCaptchaId = newData.captchaId;
                document.getElementById('captchaQuestion').innerText = newData.soru;
                document.getElementById('captchaInput').value = '';
                document.getElementById('captchaInput').focus();

                btn.disabled = false;
                btn.innerText = "Doğrula";
            }
        }
    }

    function showToast(message, type = 'error') {
        const container = document.getElementById('toastContainer');
        const toast = document.createElement('div');
        toast.className = 'toast bg-white p-4 rounded-xl shadow-lg border text-sm font-medium flex items-center gap-3 ' + (type === 'error' ? 'border-red-100 text-red-600' : 'border-green-100 text-green-600');
        toast.innerHTML = \`<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">\${type === 'error' ? '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path>' : '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path>'}</svg>\` + message;
        container.appendChild(toast);
        setTimeout(() => { toast.style.opacity = '0'; setTimeout(() => toast.remove(), 300); }, 3500);
    }

    function toggleAuth() {
        document.getElementById('loginForm').classList.toggle('hidden');
        document.getElementById('registerForm').classList.toggle('hidden');
        if (!document.getElementById('registerForm').classList.contains('hidden')) loadCaptcha();
    }

    async function loadCaptcha() {
        const res = await fetch(API_URL + '/api/captcha');
        const data = await res.json();
        regCaptchaId = data.captchaId;
        document.getElementById('captchaQuestion2').innerText = data.soru;
    }

    async function register() {
        const username = document.getElementById('regUser').value;
        const password = document.getElementById('regPass').value;
        const captchaAnswer = document.getElementById('regCaptchaInput').value;
        if(!username || !password || !captchaAnswer) return showToast("Tüm alanları doldur!");
        
        const res = await fetch(API_URL + '/api/register', {
            method: 'POST', headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ username, password, captchaId: regCaptchaId, captchaAnswer })
        });
        const data = await res.json();
        if (res.ok) { 
            localStorage.setItem('token', data.token); localStorage.setItem('username', data.user.username);
            showToast("Kayıt başarılı!", "success"); setTimeout(() => showDashboard(), 1000);
        } else { showToast(data.error); loadCaptcha(); }
    }

    async function login() {
        const username = document.getElementById('logUser').value;
        const password = document.getElementById('logPass').value;
        if(!username || !password) return showToast("Bilgileri gir!");
        
        const res = await fetch(API_URL + '/api/login', {
            method: 'POST', headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ username, password })
        });
        const data = await res.json();
        if (res.ok) { 
            localStorage.setItem('token', data.token); localStorage.setItem('username', data.user.username);
            showToast("Giriş başarılı!", "success"); setTimeout(() => showDashboard(), 1000);
        } else { showToast(data.error); }
    }

    function logout() {
        localStorage.removeItem('token'); localStorage.removeItem('username'); location.reload();
    }

    function showDashboard() {
        document.getElementById('authView').classList.add('hidden');
        document.getElementById('dashboardView').classList.remove('hidden');
        document.getElementById('userNameDisplay').innerText = localStorage.getItem('username') || 'Kullanıcı';
        loadProjects();
    }

    async function createProject() {
        const name = document.getElementById('projName').value;
        const packageName = document.getElementById('projPackage').value;
        const type = document.getElementById('projType').value;
        if (!name || !packageName) return showToast("Proje adı ve paket adı zorunlu!");

        const res = await fetch(API_URL + '/api/projects', {
            method: 'POST', 
            headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token },
            body: JSON.stringify({ name, packageName, type })
        });
        
        const data = await res.json();
        if (res.ok) { 
            showToast("Proje oluşturuldu!", "success");
            document.getElementById('projName').value = ''; document.getElementById('projPackage').value = '';
            loadProjects(); 
        } else { showToast(data.error || "Hata!"); }
    }

    async function saveSettings(id) {
        const origin = document.getElementById('origin-' + id).value;
        const res = await fetch(API_URL + '/api/projects/' + id + '/settings', {
            method: 'PUT', 
            headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token },
            body: JSON.stringify({ allowedOrigin: origin })
        });
        if(res.ok) showToast("Domain kilidi güncellendi!", "success");
    }

    async function loadProjects() {
        const res = await fetch(API_URL + '/api/projects', { headers: { 'Authorization': 'Bearer ' + token } });
        if (!res.ok) { logout(); return; }
        
        const data = await res.json();
        const list = document.getElementById('projectsList');
        list.innerHTML = '';
        
        if(data.projects.length === 0) {
            list.innerHTML = '<div class="col-span-1 text-center text-gray-400 py-16 font-medium bg-white border border-dashed border-gray-200 rounded-2xl">Henüz bir proje oluşturmadın kral. Yukarıdan ilk projeni yarat!</div>';
            return;
        }

        const icons = { 'Web': '🌐', 'Mobil': '📱', 'Oyun': '🎮', 'API': '⚙️' };

        data.projects.forEach(p => {
            list.innerHTML += \`
                <div class="bg-white border border-gray-200/60 p-6 rounded-2xl card-hover relative overflow-hidden group">
                    <div class="absolute top-0 right-0 w-32 h-32 bg-indigo-50 rounded-bl-full -z-10 opacity-50 group-hover:scale-110 transition-transform"></div>
                    <div class="flex items-center justify-between mb-5">
                        <div class="flex items-center gap-4">
                            <div class="w-14 h-14 bg-gradient-to-br from-indigo-50 to-purple-50 border border-indigo-100 rounded-2xl flex items-center justify-center text-2xl shadow-sm">\${icons[p.type] || '📦'}</div>
                            <div>
                                <h4 class="text-xl font-bold text-gray-900 tracking-tight">\${p.name}</h4>
                                <p class="text-sm text-gray-500 font-medium mt-0.5">\${p.packageName} <span class="mx-1">•</span> \${p.type}</p>
                            </div>
                        </div>
                        <span class="text-xs px-3 py-1.5 bg-green-50 text-green-700 border border-green-200 rounded-lg font-bold shadow-sm">Aktif</span>
                    </div>
                    
                    <div class="bg-gray-50 p-4 rounded-xl font-mono text-sm text-gray-700 break-all mb-5 border border-gray-200 flex justify-between items-center group-hover:bg-white transition-colors">
                        <span class="select-text font-medium">\${p.apiKey}</span>
                        <button onclick="copyToClipboard('\${p.apiKey}')" class="ml-3 p-2.5 bg-white border border-gray-200 rounded-lg text-gray-400 hover:text-indigo-600 hover:border-indigo-200 hover:bg-indigo-50 transition-all shadow-sm" title="API Key'i Kopyala">
                            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"></path></svg>
                        </button>
                    </div>

                    <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <div class="border border-gray-200 p-4 rounded-xl bg-white">
                            <label class="text-xs font-bold text-gray-800 mb-2 block flex items-center gap-1">
                                <svg class="w-3.5 h-3.5 text-indigo-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"></path></svg>
                                Klonlama Koruması (Domain Kilidi)
                            </label>
                            <div class="flex gap-2">
                                <input type="text" id="origin-\${p.id}" value="\${p.allowedOrigin}" placeholder="Örn: siteadresin.com" class="flex-1 input-field p-2.5 rounded-lg text-sm select-text font-medium">
                                <button onclick="saveSettings('\${p.id}')" class="btn-outline px-4 rounded-lg text-sm font-bold text-gray-700">Kaydet</button>
                            </div>
                            <p class="text-[11px] text-gray-400 mt-2 font-medium">* Boş bırakırsan herkes erişebilir. Doldurursan sadece o site çalışır.</p>
                        </div>

                        <div class="flex items-center">
                             <button onclick="toggleGuide('\${p.id}')" class="w-full btn-outline py-3.5 rounded-xl text-sm font-bold text-gray-700 flex items-center justify-center gap-2">
                                <svg class="w-4 h-4 text-indigo-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4"></path></svg>
                                Entegrasyon Kodlarını Gör
                             </button>
                        </div>
                    </div>
                    
                    <div id="guide-\${p.id}" class="hidden mt-5 pt-5 border-t border-gray-100 space-y-4 text-sm">
                        <div>
                            <span class="text-gray-800 font-bold block mb-2 text-xs uppercase tracking-wider">1. Veri Kaydet</span>
                            <pre class="bg-[#0f172a] text-indigo-300 p-4 rounded-xl mt-1 overflow-x-auto text-xs select-text font-mono shadow-inner border border-gray-800">fetch("\${API_URL}/api/app/data", {
  method: "POST",
  headers: { "Content-Type": "application/json", "x-api-key": "\${p.apiKey}" },
  body: JSON.stringify({ key: "skor", value: 1500 })
});</pre>
                        </div>
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

app.listen(PORT, () => console.log(`Vantorium Base ${PORT} portunda hazır kral!`));
