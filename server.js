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
  if (!fs.existsSync(DB_FILE)) return { users: [], projects: [], files: [], captchas: {}, appData: [], bannedIps: [] };
  try {
    const encrypted = fs.readFileSync(DB_FILE, 'utf8');
    const decrypted = CryptoJS.AES.decrypt(encrypted, key, { mode: CryptoJS.mode.ECB, padding: CryptoJS.pad.Pkcs7 }).toString(CryptoJS.enc.Utf8);
    const db = JSON.parse(decrypted);
    if (!db.bannedIps) db.bannedIps = [];
    return db;
  } catch { return { users: [], projects: [], files: [], captchas: {}, appData: [], bannedIps: [] }; }
}

function saveDB(db) {
  const encrypted = CryptoJS.AES.encrypt(JSON.stringify(db), key, { mode: CryptoJS.mode.ECB, padding: CryptoJS.pad.Pkcs7 }).toString();
  fs.writeFileSync(DB_FILE, encrypted, 'utf8');
}

// ---------- IP BAN KONTROLÜ (Cloudflare Kalkanı) ----------
function checkBan(req, res, next) {
  const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
  const db = loadDB();
  if (db.bannedIps.includes(clientIp)) {
    return res.status(403).send("<h1 style='color:red; text-align:center; margin-top:20%'>IP Adresiniz Bot Tespitinden Dolayı Kalıcı Olarak Banlandı!</h1>");
  }
  req.clientIp = clientIp;
  next();
}

// ---------- Middleware ----------
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));
app.use(checkBan); // Ban kontrolü her istekte çalışır

// Rate Limit Aşılınca Direkt IP Banla!
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100, // 15 dakikada 100 istek sınırı
  handler: (req, res) => {
    const db = loadDB();
    if (!db.bannedIps.includes(req.clientIp)) {
      db.bannedIps.push(req.clientIp);
      saveDB(db);
    }
    res.status(429).send("<h1 style='color:red; text-align:center; margin-top:20%'>Çok Fazla İstek Attınız. IP Adresiniz Banlandı!</h1>");
  }
});
app.use('/api', limiter);

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => cb(null, Date.now() + '-' + Math.round(Math.random() * 1E9) + '.enc')
});
const upload = multer({ storage, limits: { fileSize: 50 * 1024 * 1024 } });

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
  req.project = project;
  next();
}

// ==========================================
// API ROTALARI
// ==========================================

// İNSAN DOĞRULAMA VE BOT BAN SİSTEMİ
app.post('/api/verify-human', (req, res) => {
  const { interactionTime, mouseMoved } = req.body;
  
  // Bot Tespiti: 800ms'den kısa sürede tıklandıysa veya fare hiç oynamadıysa BOT'tur!
  if (interactionTime < 800 || mouseMoved === false) {
    const db = loadDB();
    if (!db.bannedIps.includes(req.clientIp)) {
      db.bannedIps.push(req.clientIp);
      saveDB(db);
    }
    return res.status(403).json({ error: 'Bot tespit edildi! IP adresiniz kalıcı olarak banlandı.' });
  }

  res.json({ success: true, verified: true });
});

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

app.get('/api/projects', authenticateToken, (req, res) => {
  const db = loadDB();
  res.json({ projects: db.projects.filter(p => p.userId === req.user.id) });
});

app.post('/api/projects', authenticateToken, (req, res) => {
  try {
    const { name, packageName } = req.body;
    if (!name || !packageName) return res.status(400).json({ error: 'Boş alan bırakma' });
    const db = loadDB();
    const project = { id: randomString(16), userId: req.user.id, name, packageName, apiKey: randomString(32), createdAt: Date.now() };
    db.projects.push(project);
    saveDB(db);
    res.json({ project });
  } catch { res.status(500).json({ error: 'Hata' }); }
});

app.post('/api/app/data', authenticateApp, (req, res) => {
  try {
    const { key, value } = req.body;
    if (!key || value === undefined) return res.status(400).json({ error: 'key ve value gerekli' });
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
  res.json({ key: data.key, value: data.value, updatedAt: data.updatedAt });
});

// ==========================================
// BEYAZ TEMA + DOĞRULAMA EKRANI
// ==========================================
app.get('/', (req, res) => {
  res.send(`
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Güvenlik Doğrulaması</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;800&display=swap" rel="stylesheet">
    <style>
        body { font-family: 'Outfit', sans-serif; background-color: #f8fafc; color: #1e293b; }
        .glass-white { background: rgba(255, 255, 255, 0.9); backdrop-filter: blur(10px); border: 1px solid #e2e8f0; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.05); }
        .toast { animation: slideIn 0.3s ease forwards; }
        @keyframes slideIn { from { transform: translateX(100%); opacity: 0; } to { transform: translateX(0); opacity: 1; } }
    </style>
</head>
<body class="antialiased">

<!-- Bildirim Alanı -->
<div id="toastContainer" class="fixed top-4 right-4 z-50 flex flex-col gap-2"></div>

<!-- 1. AŞAMA: TAM EKRAN DOĞRULAMA (BEYAZ TEMA) -->
<div id="verifyScreen" class="fixed inset-0 bg-white z-50 flex items-center pl-4 md:pl-32 transition-opacity duration-500">
    <div class="w-full max-w-md">
        <div class="flex items-center gap-4 mb-8">
            <div class="w-12 h-12 bg-blue-600 rounded-lg flex items-center justify-center text-white font-bold text-xl shadow-lg">K</div>
            <h1 class="text-2xl font-extrabold text-slate-800">Güvenlik Kontrolü</h1>
        </div>
        
        <div class="glass-white p-6 rounded-2xl flex items-center justify-between cursor-pointer hover:shadow-md transition" onclick="triggerVerify()">
            <div class="flex items-center gap-4">
                <div class="w-6 h-6 border-2 border-slate-300 rounded flex items-center justify-center bg-white" id="checkBox">
                    <svg class="w-4 h-4 text-white hidden" id="checkIcon" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="3" d="M5 13l4 4L19 7"></path></svg>
                </div>
                <span class="text-slate-700 font-medium text-lg">İnsan olduğumu onayla</span>
            </div>
            <div class="text-blue-500">
                <svg class="w-8 h-8 animate-pulse" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path></svg>
            </div>
        </div>
        <p class="text-sm text-slate-500 mt-4 text-center">Bu site Cloudflare benzeri bot koruması ile korunmaktadır. Lütfen fareyi hareket ettirerek onaylayın.</p>
    </div>
</div>

<!-- 2. AŞAMA: GİRİŞ / KAYIT EKRANI (BEYAZ TEMA) -->
<div id="authView" class="hidden w-full min-h-screen flex items-center justify-center p-4">
    <div class="w-full max-w-md glass-white p-8 rounded-3xl relative overflow-hidden">
        <h1 class="text-3xl font-extrabold text-center mb-8 text-slate-800">KRALIN PANELİ</h1>
        
        <div id="loginForm">
            <input type="text" id="logUser" placeholder="Kullanıcı Adı" class="w-full bg-slate-50 border border-slate-200 p-4 rounded-xl mb-4 focus:outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-200 transition">
            <input type="password" id="logPass" placeholder="Şifre" class="w-full bg-slate-50 border border-slate-200 p-4 rounded-xl mb-6 focus:outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-200 transition">
            <button onclick="login()" class="w-full bg-blue-600 hover:bg-blue-700 text-white font-bold p-4 rounded-xl shadow-lg transition">Giriş Yap</button>
            <p class="text-center text-sm text-slate-500 mt-6">Hesabın yok mu? <a href="#" onclick="toggleAuth()" class="text-blue-600 font-semibold hover:underline">Kayıt Ol</a></p>
        </div>

        <div id="registerForm" class="hidden">
            <input type="text" id="regUser" placeholder="Kullanıcı Adı" class="w-full bg-slate-50 border border-slate-200 p-4 rounded-xl mb-4 focus:outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-200 transition">
            <input type="password" id="regPass" placeholder="Şifre" class="w-full bg-slate-50 border border-slate-200 p-4 rounded-xl mb-4 focus:outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-200 transition">
            <div class="flex gap-2 mb-6">
                <input type="text" id="regCaptchaInput" placeholder="Matematik Cevabı" class="flex-1 bg-slate-50 border border-slate-200 p-4 rounded-xl focus:outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-200 transition">
                <div class="bg-slate-100 border border-slate-200 p-4 rounded-xl font-mono text-lg flex items-center justify-center min-w-[100px]" id="captchaQuestion">-</div>
                <button onclick="loadCaptcha()" class="bg-slate-200 hover:bg-slate-300 px-4 rounded-xl text-slate-700 transition">↻</button>
            </div>
            <button onclick="register()" class="w-full bg-blue-600 hover:bg-blue-700 text-white font-bold p-4 rounded-xl shadow-lg transition">Kayıt Ol</button>
            <p class="text-center text-sm text-slate-500 mt-6">Zaten üye misin? <a href="#" onclick="toggleAuth()" class="text-blue-600 font-semibold hover:underline">Giriş Yap</a></p>
        </div>
    </div>
</div>

<!-- DASHBOARD -->
<div id="dashboardView" class="hidden w-full max-w-4xl p-4 md:p-8">
    <div class="flex justify-between items-center mb-8 glass-white p-6 rounded-2xl">
        <h2 class="text-2xl font-bold text-slate-800">Merhaba, <span id="userNameDisplay" class="text-blue-600"></span> 👑</h2>
        <button onclick="logout()" class="bg-red-50 text-red-500 hover:bg-red-500 hover:text-white px-6 py-2 rounded-xl font-semibold transition border border-red-100">Çıkış Yap</button>
    </div>

    <div class="glass-white p-8 rounded-2xl mb-8">
        <h3 class="text-xl font-bold mb-4 text-slate-800">Yeni Proje Oluştur</h3>
        <div class="flex flex-col md:flex-row gap-4">
            <input type="text" id="projName" placeholder="Uygulama Adı (Örn: Süper Oyun)" class="flex-1 bg-slate-50 border border-slate-200 p-4 rounded-xl focus:outline-none focus:border-blue-500 transition">
            <input type="text" id="projPackage" placeholder="Paket Adı (Örn: com.kral.oyun)" class="flex-1 bg-slate-50 border border-slate-200 p-4 rounded-xl focus:outline-none focus:border-blue-500 transition">
            <button onclick="createProject()" class="bg-blue-600 hover:bg-blue-700 text-white font-bold px-8 py-4 md:py-0 rounded-xl shadow-md transition">Oluştur</button>
        </div>
    </div>

    <h3 class="text-xl font-bold mb-4 text-slate-800">Projelerin</h3>
    <div id="projectsList" class="grid grid-cols-1 md:grid-cols-2 gap-6"></div>
</div>

<script>
    const API_URL = window.location.origin;
    let token = localStorage.getItem('token');
    let captchaId = '';
    let pageLoadTime = Date.now();
    let mouseMoved = false;

    // Fare hareketini dinle (Bot koruması için)
    document.addEventListener('mousemove', () => { mouseMoved = true; });

    // Uygulama başlarken
    if (localStorage.getItem('humanVerified') === 'true') {
        document.getElementById('verifyScreen').classList.add('hidden');
        if (token) { showDashboard(); } else { document.getElementById('authView').classList.remove('hidden'); }
    }

    async function triggerVerify() {
        const interactionTime = Date.now() - pageLoadTime;
        document.getElementById('checkBox').classList.replace('border-slate-300', 'bg-blue-600');
        document.getElementById('checkIcon').classList.remove('hidden');

        // Cloudflare gibi davran, 1 saniye beklet
        setTimeout(async () => {
            const res = await fetch(API_URL + '/api/verify-human', {
                method: 'POST', headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ interactionTime, mouseMoved })
            });
            
            if (res.ok) {
                localStorage.setItem('humanVerified', 'true');
                document.getElementById('verifyScreen').style.opacity = '0';
                setTimeout(() => {
                    document.getElementById('verifyScreen').classList.add('hidden');
                    if (token) { showDashboard(); } else { document.getElementById('authView').classList.remove('hidden'); }
                }, 500);
            } else {
                const data = await res.json();
                alert(data.error);
                window.location.reload();
            }
        }, 800);
    }

    function showToast(message, type = 'error') {
        const container = document.getElementById('toastContainer');
        const toast = document.createElement('div');
        toast.className = 'toast bg-white p-4 rounded-xl shadow-lg border-l-4 ' + (type === 'error' ? 'border-red-500' : 'border-green-500');
        toast.innerText = message;
        container.appendChild(toast);
        setTimeout(() => { toast.style.opacity = '0'; setTimeout(() => toast.remove(), 300); }, 3000);
    }

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
        if(!username || !password || !captchaAnswer) return showToast("Tüm alanları doldur kral!");
        
        const res = await fetch(API_URL + '/api/register', {
            method: 'POST', headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ username, password, captchaId, captchaAnswer })
        });
        const data = await res.json();
        if (res.ok) { 
            localStorage.setItem('token', data.token); 
            localStorage.setItem('username', data.user.username);
            showToast("Kayıt başarılı!", "success");
            setTimeout(() => showDashboard(), 1000);
        } else { 
            showToast(data.error); 
            loadCaptcha(); 
        }
    }

    async function login() {
        const username = document.getElementById('logUser').value;
        const password = document.getElementById('logPass').value;
        if(!username || !password) return showToast("Kullanıcı adı ve şifre gir!");
        
        const res = await fetch(API_URL + '/api/login', {
            method: 'POST', headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ username, password })
        });
        const data = await res.json();
        if (res.ok) { 
            localStorage.setItem('token', data.token); 
            localStorage.setItem('username', data.user.username);
            showToast("Giriş başarılı!", "success");
            setTimeout(() => showDashboard(), 1000);
        } else { 
            showToast(data.error); 
        }
    }

    function logout() {
        localStorage.removeItem('token');
        localStorage.removeItem('username');
        location.reload();
    }

    function showDashboard() {
        document.getElementById('authView').classList.add('hidden');
        document.getElementById('dashboardView').classList.remove('hidden');
        document.getElementById('userNameDisplay').innerText = localStorage.getItem('username') || 'Kral';
        loadProjects();
    }

    async function createProject() {
        const name = document.getElementById('projName').value;
        const packageName = document.getElementById('projPackage').value;
        
        if (!name || !packageName) {
            return showToast("Uygulama adı ve paket adı boş bırakılamaz!");
        }

        const res = await fetch(API_URL + '/api/projects', {
            method: 'POST', 
            headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token },
            body: JSON.stringify({ name, packageName })
        });
        
        const data = await res.json();
        
        if (res.ok) { 
            showToast("Proje başarıyla oluşturuldu!", "success");
            document.getElementById('projName').value = '';
            document.getElementById('projPackage').value = '';
            loadProjects(); 
        } else {
            showToast(data.error || "Proje oluşturulamadı!");
        }
    }

    async function loadProjects() {
        const res = await fetch(API_URL + '/api/projects', { headers: { 'Authorization': 'Bearer ' + token } });
        if (!res.ok) { logout(); return; }
        
        const data = await res.json();
        const list = document.getElementById('projectsList');
        list.innerHTML = '';
        
        if(data.projects.length === 0) {
            list.innerHTML = '<div class="col-span-2 text-center text-slate-400 py-10">Henüz bir proje oluşturmadın kral.</div>';
            return;
        }

        data.projects.forEach(p => {
            list.innerHTML += \`
                <div class="bg-white p-6 rounded-2xl relative border border-slate-200 shadow-sm hover:shadow-md transition duration-300">
                    <h4 class="text-xl font-bold mb-1 text-slate-800">\${p.name}</h4>
                    <p class="text-sm text-slate-500 mb-4">\${p.packageName}</p>
                    
                    <div class="bg-slate-100 p-3 rounded-lg font-mono text-xs text-slate-700 break-all mb-4 border border-slate-200">
                        <span class="text-slate-400 block mb-1">API KEY:</span>
                        \${p.apiKey}
                    </div>

                    <button onclick="toggleGuide('\${p.id}')" class="w-full bg-slate-50 hover:bg-slate-100 text-slate-700 py-2 rounded-lg text-sm font-semibold transition mb-2 border border-slate-200">📖 Bağlantı Rehberi</button>
                    
                    <div id="guide-\${p.id}" class="hidden mt-4 space-y-4 text-xs">
                        <div>
                            <span class="text-blue-600 font-bold">1. Veri Kaydet (Skor vb):</span>
                            <pre class="bg-slate-900 text-green-400 p-3 rounded mt-1 overflow-x-auto">fetch("\${API_URL}/api/app/data", {
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

app.listen(PORT, () => console.log(`Sunucu ${PORT} portunda hazır kral!`));
