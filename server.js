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
    return res.status(403).send("<h1 style='color:red; text-align:center; margin-top:20%'>Vantorium Base | IP Adresiniz Banlandı!</h1>");
  }
  req.clientIp = clientIp;
  next();
}

app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));
app.use(checkBan);

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200, 
  handler: (req, res) => {
    const db = loadDB();
    if (!db.bannedIps.includes(req.clientIp)) { db.bannedIps.push(req.clientIp); saveDB(db); }
    res.status(429).send("<h1 style='color:red; text-align:center; margin-top:20%'>Çok Fazla İstek Attınız. IP Adresiniz Banlandı!</h1>");
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
  
  project.apiCalls = (project.apiCalls || 0) + 1;
  saveDB(db);

  req.project = project;
  next();
}

// ==========================================
// API ROTALARI
// ==========================================

app.get('/ping', (req, res) => res.send('pong'));

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
    const remaining = 2 - db.verifyAttempts[clientIp];
    
    if (remaining <= 0) {
      if (!db.bannedIps.includes(clientIp)) { db.bannedIps.push(clientIp); saveDB(db); }
      return res.status(403).json({ error: '2 kez yanlış yaptınız! IP adresiniz kalıcı olarak banlandı.' });
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
    const project = { id: randomString(16), userId: req.user.id, name, packageName, type: type || 'Web', allowedOrigin: "*", apiKey: randomString(32), apiCalls: 0, createdAt: Date.now() };
    db.projects.push(project);
    saveDB(db);
    res.json({ project });
  } catch { res.status(500).json({ error: 'Hata' }); }
});

app.delete('/api/projects/:id', authenticateToken, (req, res) => {
  try {
    const db = loadDB();
    const pIndex = db.projects.findIndex(p => p.id === req.params.id && p.userId === req.user.id);
    if (pIndex === -1) return res.status(403).json({ error: 'Yetkisiz veya bulunamadı' });
    db.projects.splice(pIndex, 1);
    db.appData = db.appData.filter(d => d.projectId !== req.params.id);
    saveDB(db);
    res.json({ success: true });
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

app.get('/api/projects/:id/data', authenticateToken, (req, res) => {
  const db = loadDB();
  const data = db.appData.filter(d => d.projectId === req.params.id);
  res.json({ data });
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

app.get('/api/app/data/:key', authenticateApp, (req, res) => {
  const db = loadDB();
  const data = db.appData.find(d => d.projectId === req.project.id && d.key === req.params.key);
  if (!data) return res.status(404).json({ error: 'Veri bulunamadı' });
  res.json({ key: data.key, value: data.value });
});

setInterval(() => {
  const http = require('http');
  http.get(`http://localhost:${PORT}/ping`, () => {}).on('error', () => {});
}, 10 * 60 * 1000);

// ==========================================
// VANTORIUM BASE FRONTEND (MOBİL UYUMLU)
// ==========================================
app.get('/', (req, res) => {
  const html = `
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
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
        input, textarea, .select-text, pre { user-select: text !important; -webkit-user-select: text !important; }
        
        .glass-panel { background: rgba(255, 255, 255, 0.7); backdrop-filter: blur(16px); border: 1px solid rgba(255, 255, 255, 0.4); box-shadow: 0 4px 24px -4px rgba(0,0,0,0.06); }
        .card-hover { transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1); }
        .card-hover:hover { transform: translateY(-3px); box-shadow: 0 20px 40px -8px rgba(79, 70, 229, 0.1); border-color: rgba(79, 70, 229, 0.2); }
        
        .btn-primary { background: linear-gradient(135deg, #4f46e5 0%, #7c3aed 100%); color: #fff; transition: all 0.3s; box-shadow: 0 4px 12px rgba(79, 70, 229, 0.2); }
        .btn-primary:hover { transform: translateY(-1px); box-shadow: 0 8px 20px rgba(79, 70, 229, 0.3); opacity: 0.95; }
        .btn-outline { background: #fff; border: 1px solid #e2e8f0; transition: all 0.2s; }
        .btn-outline:hover { background: #f8fafc; border-color: #cbd5e1; }
        .btn-danger { background: #fef2f2; color: #ef4444; border: 1px solid #fee2e2; transition: all 0.2s; }
        .btn-danger:hover { background: #ef4444; color: #fff; }
        
        .input-field { background: #fff; border: 1px solid #e2e8f0; transition: all 0.2s; }
        .input-field:focus { outline: none; border-color: #6366f1; box-shadow: 0 0 0 4px rgba(99, 102, 241, 0.1); }
        
        .toast { animation: slideInRight 0.4s cubic-bezier(0.4, 0, 0.2, 1) forwards; }
        @keyframes slideInRight { from { transform: translateX(100%); opacity: 0; } to { transform: translateX(0); opacity: 1; } }
        .fade-in { animation: fadeIn 0.5s ease-out forwards; }
        @keyframes fadeIn { from { opacity: 0; transform: translateY(15px); } to { opacity: 1; transform: translateY(0); } }
        
        .spinner { border: 2px solid rgba(79, 70, 229, 0.1); border-left-color: #4f46e5; border-radius: 50%; width: 20px; height: 20px; animation: spin 0.8s linear infinite; }
        @keyframes spin { to { transform: rotate(360deg); } }
        
        .glow { position: absolute; width: 300px; height: 300px; background: radial-gradient(circle, rgba(124,58,237,0.15) 0%, rgba(255,255,255,0) 70%); border-radius: 50%; z-index: -1; }
        
        .modal-overlay { background: rgba(15, 23, 42, 0.5); backdrop-filter: blur(4px); }
    </style>
</head>
<body class="antialiased overflow-hidden text-[15px] relative w-full h-full">

<div class="glow top-0 left-0"></div>
<div class="glow bottom-0 right-0"></div>

<div id="toastContainer" class="fixed top-4 right-4 left-4 md:left-auto z-[100] flex flex-col items-end gap-2 pointer-events-none"></div>

<!-- DOĞRULAMA EKRANI -->
<div id="verifyScreen" class="fixed inset-0 bg-white/90 backdrop-blur-md z-50 flex items-center justify-center transition-all duration-700 p-4">
    <div class="w-full max-w-[420px] fade-in">
        <div class="flex flex-col items-center mb-10">
            <div class="w-14 h-14 bg-gradient-to-br from-indigo-600 to-purple-600 rounded-2xl flex items-center justify-center text-white font-bold text-2xl shadow-xl shadow-indigo-500/30 mb-4">V</div>
            <h1 class="text-3xl font-bold tracking-tight text-gray-900">Vantorium Base</h1>
            <p class="text-sm text-gray-500 mt-2">Güvenlik Duvarı</p>
        </div>
        
        <div id="humanBox" class="bg-white p-5 rounded-2xl border border-gray-100 shadow-[0_8px_30px_rgb(0,0,0,0.04)] flex items-center justify-between cursor-pointer card-hover" onclick="startVerifyFlow()">
            <div class="flex items-center gap-4">
                <div class="w-7 h-7 border-2 border-gray-300 rounded-lg flex items-center justify-center bg-white transition-colors" id="checkBox">
                    <div id="checkSpinner" class="hidden spinner"></div>
                    <svg class="w-5 h-5 text-white hidden" id="checkIcon" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="3" d="M5 13l4 4L19 7"></path></svg>
                </div>
                <span class="text-gray-800 font-semibold text-sm">İnsan olduğumu onayla</span>
            </div>
            <svg class="w-7 h-7 text-indigo-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path></svg>
        </div>
        
        <div id="serverWakeup" class="hidden mt-4 p-3 bg-amber-50 border border-amber-100 rounded-xl text-center">
            <p class="text-xs text-amber-700 font-medium animate-pulse">Sunucu uyanıyor, lütfen bekleyin...</p>
        </div>

        <div id="captchaModal" class="hidden bg-white p-5 rounded-2xl border border-gray-100 shadow-lg mt-4 fade-in">
            <div class="flex justify-between items-center mb-4">
                <p class="text-sm text-gray-600 font-medium">İşlemi tamamlayın:</p>
                <span id="attemptsDisplay" class="text-xs font-bold px-2.5 py-1 bg-red-50 text-red-600 rounded-lg border border-red-100">Kalan Hak: 2</span>
            </div>
            <div class="flex items-center gap-3 mb-5">
                <div class="bg-indigo-50 border border-indigo-100 px-4 py-2.5 rounded-xl font-mono text-lg font-bold text-indigo-700" id="captchaQuestion">-</div>
                <span class="text-gray-400 font-bold">=</span>
                <input type="number" id="captchaInput" class="flex-1 input-field px-4 py-2.5 rounded-xl text-lg font-bold text-center" placeholder="?">
            </div>
            <button id="captchaBtn" onclick="submitCaptcha()" class="w-full btn-primary font-bold py-3 rounded-xl">Doğrula</button>
        </div>
    </div>
</div>

<!-- GİRİŞ EKRANI -->
<div id="authView" class="hidden w-full min-h-screen flex items-center justify-center p-4 relative z-10">
    <div class="w-full max-w-[400px] glass-panel p-6 md:p-8 rounded-3xl fade-in">
        <div class="flex justify-center mb-6">
            <div class="w-14 h-14 bg-gradient-to-br from-indigo-600 to-purple-600 rounded-2xl flex items-center justify-center text-white font-bold text-2xl shadow-lg shadow-indigo-500/30">V</div>
        </div>
        <h1 class="text-2xl font-bold text-center mb-8 text-gray-900 tracking-tight">Vantorium Base</h1>
        
        <div id="loginForm">
            <div class="space-y-4 mb-6">
                <input type="text" id="logUser" placeholder="Kullanıcı Adı" class="w-full input-field p-3.5 rounded-xl text-sm font-medium">
                <input type="password" id="logPass" placeholder="Şifre" class="w-full input-field p-3.5 rounded-xl text-sm font-medium">
            </div>
            <button onclick="login()" class="w-full btn-primary font-bold p-3.5 rounded-xl text-sm">Giriş Yap</button>
            <p class="text-center text-sm text-gray-500 mt-6 font-medium">Hesabın yok mu? <a href="#" onclick="toggleAuth()" class="text-indigo-600 font-bold hover:underline">Kayıt Ol</a></p>
        </div>

        <div id="registerForm" class="hidden">
            <div class="space-y-4 mb-6">
                <input type="text" id="regUser" placeholder="Kullanıcı Adı" class="w-full input-field p-3.5 rounded-xl text-sm font-medium">
                <input type="password" id="regPass" placeholder="Şifre" class="w-full input-field p-3.5 rounded-xl text-sm font-medium">
                <div class="flex gap-2">
                    <input type="number" id="regCaptchaInput" placeholder="Cevap" class="flex-1 input-field p-3.5 rounded-xl text-sm font-medium">
                    <div class="bg-gray-50 border border-gray-200 p-3.5 rounded-xl font-mono text-sm font-bold flex items-center justify-center min-w-[90px]" id="captchaQuestion2">-</div>
                    <button onclick="loadCaptcha()" class="bg-white border border-gray-200 hover:bg-gray-50 px-4 rounded-xl text-gray-700 transition">↻</button>
                </div>
            </div>
            <button onclick="register()" class="w-full btn-primary font-bold p-3.5 rounded-xl text-sm">Hesap Oluştur</button>
            <p class="text-center text-sm text-gray-500 mt-6 font-medium">Zaten üye misin? <a href="#" onclick="toggleAuth()" class="text-indigo-600 font-bold hover:underline">Giriş Yap</a></p>
        </div>
    </div>
</div>

<!-- DASHBOARD -->
<div id="dashboardView" class="hidden w-full h-screen flex flex-col md:flex-row fade-in relative z-10">
    
    <!-- Mobil Üst Bar -->
    <div class="md:hidden flex items-center justify-between p-4 bg-white border-b border-gray-200 z-20 w-full shrink-0">
        <div class="flex items-center gap-2">
            <div class="w-8 h-8 bg-gradient-to-br from-indigo-600 to-purple-600 rounded-lg flex items-center justify-center text-white font-bold text-sm shadow-md">V</div>
            <span class="font-bold text-gray-900 text-base">Vantorium</span>
        </div>
        <button onclick="logout()" class="p-2 text-gray-500 hover:text-red-600 bg-gray-50 rounded-lg transition">
            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1"></path></svg>
        </button>
    </div>

    <!-- Masaüstü Yan Menü -->
    <aside class="hidden md:flex w-64 border-r border-gray-200/60 bg-white/50 backdrop-blur-xl flex-col h-full z-10 shrink-0">
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

    <!-- Ana İçerik Alanı -->
    <main class="flex-1 h-full overflow-y-auto p-4 md:p-10 w-full">
        <div class="max-w-5xl mx-auto pb-10">
            
            <!-- Başlık -->
            <div class="mb-8 mt-2 md:mt-0">
                <h1 class="text-2xl md:text-3xl font-extrabold text-gray-900 tracking-tight">Projeler</h1>
                <p class="text-sm text-gray-500 mt-1 font-medium">Merhaba <span id="userNameDisplay" class="text-indigo-600 font-bold"></span>, sistemlerini buradan yönet.</p>
            </div>

            <!-- İstatistik Kartları -->
            <div class="grid grid-cols-2 md:grid-cols-3 gap-3 mb-8">
                <div class="bg-white p-4 rounded-2xl border border-gray-200/60 shadow-sm flex flex-col justify-center">
                    <span class="text-xs font-bold text-gray-400 uppercase tracking-wider mb-1">Toplam Proje</span>
                    <span id="statProjects" class="text-2xl font-extrabold text-gray-900">0</span>
                </div>
                <div class="bg-white p-4 rounded-2xl border border-gray-200/60 shadow-sm flex flex-col justify-center">
                    <span class="text-xs font-bold text-gray-400 uppercase tracking-wider mb-1">API Çağrısı</span>
                    <span id="statCalls" class="text-2xl font-extrabold text-indigo-600">0</span>
                </div>
                <div class="hidden md:flex bg-white p-4 rounded-2xl border border-gray-200/60 shadow-sm flex-col justify-center">
                    <span class="text-xs font-bold text-gray-400 uppercase tracking-wider mb-1">Sistem Durumu</span>
                    <span class="flex items-center gap-2 text-sm font-bold text-green-500 mt-1"><span class="w-2 h-2 rounded-full bg-green-500 animate-pulse"></span> Aktif</span>
                </div>
            </div>

            <!-- Proje Oluşturma Formu -->
            <div class="bg-white border border-gray-200/60 p-4 rounded-2xl shadow-sm mb-8 flex flex-col md:flex-row gap-3">
                <input type="text" id="projName" placeholder="Uygulama Adı" class="w-full md:flex-1 input-field p-3.5 rounded-xl text-sm bg-gray-50 hover:bg-white focus:bg-white transition">
                <input type="text" id="projPackage" placeholder="Paket Adı (com.ornek)" class="w-full md:flex-1 input-field p-3.5 rounded-xl text-sm bg-gray-50 hover:bg-white focus:bg-white transition">
                <select id="projType" class="w-full md:w-44 input-field p-3.5 rounded-xl text-sm bg-gray-50 hover:bg-white font-medium">
                    <option value="Web">Web Uygulaması</option>
                    <option value="Mobil">Mobil Uygulama</option>
                    <option value="Oyun">Oyun</option>
                    <option value="API">Backend API</option>
                </select>
                <button onclick="createProject()" class="w-full md:w-auto btn-primary font-bold px-8 py-3.5 rounded-xl text-sm whitespace-nowrap">Proje Oluştur</button>
            </div>

            <!-- Proje Listesi -->
            <div id="projectsList" class="grid grid-cols-1 gap-5"></div>
        </div>
    </main>
</div>

<!-- VERİ İZLEYİCİ MODAL (Mobil Uyumlu) -->
<div id="dataModal" class="fixed inset-0 z-[90] hidden items-center justify-center modal-overlay p-4">
    <div class="bg-white rounded-3xl shadow-2xl w-full max-w-2xl overflow-hidden fade-in flex flex-col max-h-[85vh]">
        <div class="p-5 md:p-6 border-b border-gray-100 flex justify-between items-center bg-gray-50/50 shrink-0">
            <div>
                <h3 class="text-lg md:text-xl font-bold text-gray-900" id="dataModalTitle">Veri İzleyici</h3>
                <p class="text-xs text-gray-500 mt-1">API üzerinden kaydedilen veriler</p>
            </div>
            <button onclick="closeDataModal()" class="p-2 bg-white rounded-lg border border-gray-200 hover:bg-gray-50 text-gray-500 transition">
                <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg>
            </button>
        </div>
        <div class="p-4 md:p-6 overflow-y-auto bg-gray-50 flex-1">
            <pre id="dataContent" class="text-xs md:text-sm font-mono text-indigo-700 bg-white p-4 rounded-xl border border-gray-200 whitespace-pre-wrap break-all">Yükleniyor...</pre>
        </div>
    </div>
</div>

<script>
    document.addEventListener('contextmenu', e => {
        if (e.target.closest('.select-text') || e.target.tagName === 'INPUT' || e.target.tagName === 'PRE') return;
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
    let isVerifying = false;

    document.addEventListener('mousemove', () => { mouseMoved = true; });
    document.addEventListener('touchstart', () => { mouseMoved = true; }); // Mobil için dokunma algılama

    if (localStorage.getItem('humanVerified') === 'true') {
        document.getElementById('verifyScreen').classList.add('hidden');
        if (token) { showDashboard(); } else { document.getElementById('authView').classList.remove('hidden'); }
    }

    async function startVerifyFlow() {
        if (isVerifying) return;
        isVerifying = true;

        document.getElementById('checkSpinner').classList.remove('hidden');
        document.getElementById('humanBox').classList.add('pointer-events-none');
        
        const wakeupTimer = setTimeout(() => {
            document.getElementById('serverWakeup').classList.remove('hidden');
        }, 3000);

        try {
            const res = await fetch(API_URL + '/api/generate-captcha');
            clearTimeout(wakeupTimer);
            document.getElementById('serverWakeup').classList.add('hidden');
            
            if (!res.ok) throw new Error("Sunucu yanıt vermedi");
            const data = await res.json();
            
            verifyCaptchaId = data.captchaId;
            document.getElementById('captchaQuestion').innerText = data.soru;
            
            document.getElementById('checkSpinner').classList.add('hidden');
            document.getElementById('checkBox').classList.replace('border-gray-300', 'bg-indigo-600 border-indigo-600');
            document.getElementById('checkIcon').classList.remove('hidden');
            document.getElementById('captchaModal').classList.remove('hidden');
            document.getElementById('captchaInput').focus();
        } catch (error) {
            clearTimeout(wakeupTimer);
            document.getElementById('serverWakeup').classList.add('hidden');
            showToast("Sunucuya ulaşılamadı. Lütfen tekrar deneyin.", "error");
            document.getElementById('checkSpinner').classList.add('hidden');
            document.getElementById('humanBox').classList.remove('pointer-events-none');
            isVerifying = false;
        }
    }

    async function submitCaptcha() {
        const answer = document.getElementById('captchaInput').value;
        if (!answer) return showToast("Cevabı gir!", "error");

        const btn = document.getElementById('captchaBtn');
        btn.disabled = true;
        btn.innerText = "Kontrol ediliyor...";

        const interactionTime = Date.now() - pageLoadTime;
        
        try {
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
                    document.getElementById('attemptsDisplay').innerText = 'Kalan Hak: ' + data.remainingAttempts;
                    
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
        } catch (err) {
            showToast("Bağlantı hatası oluştu!", "error");
            btn.disabled = false;
            btn.innerText = "Tekrar Dene";
        }
    }

    function showToast(message, type) {
        if(!type) type = 'error';
        const container = document.getElementById('toastContainer');
        const toast = document.createElement('div');
        toast.className = 'toast bg-white p-3.5 rounded-xl shadow-lg border text-sm font-medium flex items-center gap-3 w-full md:w-auto pointer-events-auto ' + (type === 'error' ? 'border-red-100 text-red-600' : 'border-green-100 text-green-600');
        var iconSvg = type === 'error' 
            ? '<svg class="w-5 h-5 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>'
            : '<svg class="w-5 h-5 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>';
        
        toast.innerHTML = iconSvg + message;
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

    async function deleteProject(id) {
        if(!confirm("Bu projeyi silmek istediğinize emin misiniz?")) return;
        const res = await fetch(API_URL + '/api/projects/' + id, {
            method: 'DELETE', 
            headers: { 'Authorization': 'Bearer ' + token }
        });
        if(res.ok) { showToast("Proje silindi!", "success"); loadProjects(); }
        else { showToast("Silinemedi!"); }
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

    async function openDataModal(projectId, projectName) {
        document.getElementById('dataModal').classList.remove('hidden');
        document.getElementById('dataModal').classList.add('flex');
        document.getElementById('dataModalTitle').innerText = projectName;
        document.getElementById('dataContent').innerText = 'Yükleniyor...';

        const res = await fetch(API_URL + '/api/projects/' + projectId + '/data', {
            headers: { 'Authorization': 'Bearer ' + token }
        });
        const data = await res.json();
        
        if(data.data.length === 0) {
            document.getElementById('dataContent').innerText = '// Henüz veri yok.\\n// Uygulamanızdan API isteği attığınızda veriler burada görünecektir.';
        } else {
            document.getElementById('dataContent').innerText = JSON.stringify(data.data, null, 2);
        }
    }

    function closeDataModal() {
        document.getElementById('dataModal').classList.add('hidden');
        document.getElementById('dataModal').classList.remove('flex');
    }

    async function loadProjects() {
        const res = await fetch(API_URL + '/api/projects', { headers: { 'Authorization': 'Bearer ' + token } });
        if (!res.ok) { logout(); return; }
        
        const data = await res.json();
        const list = document.getElementById('projectsList');
        list.innerHTML = '';
        
        // İstatistikleri güncelle
        let totalCalls = 0;
        data.projects.forEach(p => totalCalls += (p.apiCalls || 0));
        document.getElementById('statProjects').innerText = data.projects.length;
        document.getElementById('statCalls').innerText = totalCalls;

        if(data.projects.length === 0) {
            list.innerHTML = '<div class="col-span-1 text-center text-gray-400 py-12 font-medium bg-white border border-dashed border-gray-200 rounded-2xl">Henüz bir proje oluşturmadın kral.</div>';
            return;
        }

        const icons = { 'Web': '🌐', 'Mobil': '📱', 'Oyun': '🎮', 'API': '⚙️' };

        data.projects.forEach(function(p) {
            var date = new Date(p.createdAt).toLocaleDateString('tr-TR');
            
            var htmlStr = '<div class="bg-white border border-gray-200/60 p-4 md:p-6 rounded-2xl card-hover relative overflow-hidden group">';
            htmlStr += '<div class="absolute top-0 right-0 w-24 h-24 md:w-32 md:h-32 bg-indigo-50 rounded-bl-full -z-10 opacity-50 group-hover:scale-110 transition-transform"></div>';
            
            // Başlık & Detaylar
            htmlStr += '<div class="flex flex-col md:flex-row md:items-center justify-between mb-4 gap-3">';
            htmlStr += '<div class="flex items-center gap-3">';
            htmlStr += '<div class="w-12 h-12 md:w-14 md:h-14 bg-gradient-to-br from-indigo-50 to-purple-50 border border-indigo-100 rounded-2xl flex items-center justify-center text-2xl shadow-sm shrink-0">' + (icons[p.type] || '📦') + '</div>';
            htmlStr += '<div><h4 class="text-lg md:text-xl font-bold text-gray-900 tracking-tight">' + p.name + '</h4>';
            htmlStr += '<p class="text-xs md:text-sm text-gray-500 font-medium mt-0.5">' + p.packageName + ' <span class="mx-1">•</span> ' + p.type + ' <span class="mx-1">•</span> ' + date + '</p></div></div>';
            
            // Aksiyon Butonları
            htmlStr += '<div class="flex items-center gap-2">';
            htmlStr += '<span class="text-[10px] md:text-xs px-2.5 py-1.5 bg-indigo-50 text-indigo-600 border border-indigo-100 rounded-lg font-bold">' + (p.apiCalls || 0) + ' Çağrı</span>';
            htmlStr += '<button onclick="deleteProject(\\'' + p.id + '\\')" class="p-2 btn-danger rounded-lg text-xs font-bold" title="Sil">';
            htmlStr += '<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"></path></svg>';
            htmlStr += '</button></div></div>';
            
            // API Key Alanı
            htmlStr += '<div class="bg-gray-50 p-3 md:p-4 rounded-xl font-mono text-xs md:text-sm text-gray-700 break-all mb-4 border border-gray-200 flex justify-between items-center group-hover:bg-white transition-colors">';
            htmlStr += '<span class="select-text font-medium truncate mr-2">' + p.apiKey + '</span>';
            htmlStr += '<button onclick="copyToClipboard(\\'' + p.apiKey + '\\')" class="p-2 bg-white border border-gray-200 rounded-lg text-gray-400 hover:text-indigo-600 hover:border-indigo-200 hover:bg-indigo-50 transition-all shadow-sm shrink-0" title="Kopyala">';
            htmlStr += '<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"></path></svg></button></div>';

            // Alt Butonlar (Mobilde Alt Alta)
            htmlStr += '<div class="flex flex-col md:flex-row gap-3">';
            htmlStr += '<button onclick="openDataModal(\\'' + p.id + '\\', \\'' + p.name + '\\')" class="w-full btn-outline py-2.5 rounded-xl text-xs font-bold text-gray-700 flex items-center justify-center gap-2">';
            htmlStr += '<svg class="w-4 h-4 text-indigo-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4m0 5c0 2.21-3.582 4-8 4s-8-1.79-8-4"></path></svg>';
            htmlStr += 'Verileri Gör</button>';
            
            htmlStr += '<button onclick="toggleGuide(\\'' + p.id + '\\')" class="w-full btn-outline py-2.5 rounded-xl text-xs font-bold text-gray-700 flex items-center justify-center gap-2">';
            htmlStr += '<svg class="w-4 h-4 text-indigo-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4"></path></svg>Entegrasyon Kodu</button></div>';

            // Entegrasyon Detayları (Gizli)
            htmlStr += '<div id="guide-' + p.id + '" class="hidden mt-4 pt-4 border-t border-gray-100 space-y-4">';
            
            // Domain Kilidi
            htmlStr += '<div class="border border-gray-200 p-3 rounded-xl bg-gray-50">';
            htmlStr += '<label class="text-xs font-bold text-gray-800 mb-2 block">Domain Kilidi (Klonlama Koruması)</label>';
            htmlStr += '<div class="flex gap-2">';
            htmlStr += '<input type="text" id="origin-' + p.id + '" value="' + p.allowedOrigin + '" placeholder="Örn: siteadresin.com" class="flex-1 input-field p-2 rounded-lg text-xs select-text">';
            htmlStr += '<button onclick="saveSettings(\\'' + p.id + '\\')" class="btn-outline px-3 rounded-lg text-xs font-bold text-gray-700">Kaydet</button></div></div>';

            // Fetch Kodu
            htmlStr += '<div><span class="text-gray-800 font-bold block mb-1 text-[10px] uppercase tracking-wider">Veri Kaydet (Fetch)</span>';
            htmlStr += '<pre class="bg-[#0f172a] text-indigo-300 p-3 rounded-xl mt-1 overflow-x-auto text-[11px] select-text font-mono shadow-inner border border-gray-800">fetch("' + API_URL + '/api/app/data", {\\n  method: "POST",\\n  headers: { "Content-Type": "application/json", "x-api-key": "' + p.apiKey + '" },\\n  body: JSON.stringify({ key: "skor", value: 1500 })\\n});</pre></div>';

            htmlStr += '</div></div>';

            list.innerHTML += htmlStr;
        });
    }

    function toggleGuide(id) {
        document.getElementById('guide-' + id).classList.toggle('hidden');
    }
</script>
</body>
</html>
  `;
  res.send(html);
});

app.listen(PORT, () => console.log(`Vantorium Base ${PORT} portunda hazır kral!`));
