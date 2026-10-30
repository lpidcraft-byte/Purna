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
app.set('trust proxy', 1);

// VANTORIUM GÜVENLİK ANAHTARLARI
const JWT_SECRET = process.env.JWT_SECRET || '75N6Wtyf4KtOgv1CQ6ici1rZz30pBxsHGxSYw9JcDPn';
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || 'd0ec01759c5c3498b69340e0343bbdf3e5830faed6beca2389339800debb6990';

if (!JWT_SECRET || JWT_SECRET.length < 32)
  throw new Error('JWT_SECRET en az 32 karakter olmalıdır.');

if (!ENCRYPTION_KEY || !/^[a-fA-F0-9]{64}$/.test(ENCRYPTION_KEY))
  throw new Error('ENCRYPTION_KEY 64 karakterlik hexadecimal anahtar olmalıdır.');

const key = CryptoJS.enc.Hex.parse(ENCRYPTION_KEY);

const DATA_DIR = process.env.DATA_DIR || (process.env.RENDER ? '/var/data' : __dirname);
fs.mkdirSync(DATA_DIR, { recursive: true });

const DB_FILE = path.join(DATA_DIR, 'data.enc');
const UPLOAD_DIR = path.join(DATA_DIR, 'uploads');
fs.mkdirSync(UPLOAD_DIR, { recursive: true });

// Eski veritabanını kalıcı depolama alanına taşı.
const legacyDB = path.join(__dirname, 'data.enc');

if (
  !fs.existsSync(DB_FILE) &&
  path.resolve(legacyDB) !== path.resolve(DB_FILE) &&
  fs.existsSync(legacyDB)
) {
  fs.copyFileSync(legacyDB, DB_FILE);
  console.log('Eski data.enc kalıcı depolama alanına kopyalandı.');
}

function emptyDB() {
  return {
    users: [],
    projects: [],
    files: [],
    captchas: {},
    appData: [],
    appUsers: [],
    bannedIps: [],
    verifyAttempts: {}
  };
}

function loadDB() {
  if (!fs.existsSync(DB_FILE)) return emptyDB();

  try {
    const encrypted = fs.readFileSync(DB_FILE, 'utf8');

    const decrypted = CryptoJS.AES.decrypt(encrypted, key, {
      mode: CryptoJS.mode.ECB,
      padding: CryptoJS.pad.Pkcs7
    }).toString(CryptoJS.enc.Utf8);

    const db = JSON.parse(decrypted);
    const defaults = emptyDB();

    for (const field of Object.keys(defaults)) {
      if (db[field] === undefined) {
        db[field] = defaults[field];
      }
    }

    return db;
  } catch (e) {
    console.error('DB okunamadı:', e.message);
    throw new Error(
      'Veritabanı okunamadı. ENCRYPTION_KEY değerinin eski kurulumla aynı olduğundan emin olun.'
    );
  }
}

function saveDB(db) {
  const encrypted = CryptoJS.AES.encrypt(
    JSON.stringify(db),
    key,
    {
      mode: CryptoJS.mode.ECB,
      padding: CryptoJS.pad.Pkcs7
    }
  ).toString();

  const tmp = DB_FILE + '.tmp';

  fs.writeFileSync(tmp, encrypted, 'utf8');
  fs.renameSync(tmp, DB_FILE);
}

function randomString(bytes = 32) {
  return CryptoJS.lib.WordArray.random(bytes).toString();
}

function validEmail(email) {
  return typeof email === 'string' &&
    /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email) &&
    email.length <= 254;
}

function safeUser(user) {
  return {
    id: user.id,
    username: user.username,
    email: user.email || null,
    createdAt: user.createdAt
  };
}

app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true, limit: '2mb' }));

function checkBan(req, res, next) {
  const db = loadDB();

  if (db.bannedIps.includes(req.ip)) {
    return res.status(403).json({
      error: 'IP adresiniz engellenmiş.'
    });
  }

  req.clientIp = req.ip;
  next();
}

app.use(checkBan);

app.use('/api', rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 300,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  handler: (req, res) => res.status(429).json({
    error: 'Çok fazla istek. Biraz bekleyin.'
  })
}));

function requireHuman(req, res, next) {
  const token = req.headers['x-verification-token'];

  if (!token) {
    return res.status(403).json({
      error: 'Önce insan doğrulamasını tamamlayın.',
      verificationRequired: true
    });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);

    if (decoded.purpose !== 'human-verification') {
      throw new Error('invalid purpose');
    }

    next();
  } catch {
    return res.status(403).json({
      error: 'Doğrulama geçersiz veya süresi dolmuş.',
      verificationRequired: true
    });
  }
}

app.use('/api', (req, res, next) => {
  const publicRoutes = [
    '/generate-captcha',
    '/captcha',
    '/verify-human',
    '/verify-status'
  ];

  if (
    publicRoutes.includes(req.path) ||
    req.path.startsWith('/app/')
  ) {
    return next();
  }

  requireHuman(req, res, next);
});

function authenticateToken(req, res, next) {
  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;

  if (!token) {
    return res.status(401).json({
      error: 'Oturum gerekli.'
    });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);

    if (decoded.kind && decoded.kind !== 'dashboard') {
      throw new Error('wrong token');
    }

    req.user = decoded;
    next();
  } catch {
    res.status(401).json({
      error: 'Oturum geçersiz veya süresi dolmuş.'
    });
  }
}

function authenticateApp(req, res, next) {
  const apiKey = req.headers['x-api-key'];

  if (!apiKey) {
    return res.status(401).json({
      error: 'x-api-key başlığı eksik.'
    });
  }

  const db = loadDB();
  const project = db.projects.find(p => p.apiKey === apiKey);

  if (!project) {
    return res.status(403).json({
      error: 'Geçersiz API Key.'
    });
  }

  if (project.allowedOrigin && project.allowedOrigin !== '*') {
    const origin = req.headers.origin;

    if (origin) {
      try {
        const hostname = new URL(origin).hostname.toLowerCase();

        const allowed = new URL(
          project.allowedOrigin.includes('://')
            ? project.allowedOrigin
            : 'https://' + project.allowedOrigin
        ).hostname.toLowerCase();

        if (hostname !== allowed) {
          return res.status(403).json({
            error: 'Bu domain için izin yok.'
          });
        }
      } catch {
        return res.status(403).json({
          error: 'Geçersiz Origin.'
        });
      }
    }
  }

  project.apiCalls = (project.apiCalls || 0) + 1;
  saveDB(db);

  req.project = project;
  next();
}

function authenticateAppUser(req, res, next) {
  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;

  if (!token) {
    return res.status(401).json({
      error: 'Uygulama kullanıcı oturumu gerekli.'
    });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);

    if (
      decoded.kind !== 'app-user' ||
      decoded.projectId !== req.project.id
    ) {
      throw new Error('wrong project');
    }

    req.appUser = decoded;
    next();
  } catch {
    res.status(401).json({
      error: 'Uygulama oturumu geçersiz veya süresi dolmuş.'
    });
  }
}

app.get('/ping', (req, res) => {
  res.json({
    success: true,
    service: 'Vantorium Base',
    status: 'online',
    timestamp: Date.now()
  });
});

function createCaptcha(db) {
  const a = Math.floor(Math.random() * 10) + 1;
  const b = Math.floor(Math.random() * 10) + 1;
  const id = randomString(16);

  db.captchas[id] = {
    answer: a + b,
    createdAt: Date.now()
  };

  for (const k of Object.keys(db.captchas)) {
    if (Date.now() - db.captchas[k].createdAt > 600000) {
      delete db.captchas[k];
    }
  }

  return {
    captchaId: id,
    soru: `${a} + ${b} = ?`
  };
}

app.get('/api/generate-captcha', (req, res) => {
  const db = loadDB();
  const captcha = createCaptcha(db);
  saveDB(db);
  res.json(captcha);
});

app.get('/api/captcha', (req, res) => {
  const db = loadDB();
  const captcha = createCaptcha(db);
  saveDB(db);
  res.json(captcha);
});

app.post('/api/verify-human', (req, res) => {
  const { captchaId, captchaAnswer } = req.body || {};

  const db = loadDB();
  const captcha = db.captchas[captchaId];

  if (!captcha || Date.now() - captcha.createdAt > 600000) {
    delete db.captchas[captchaId];
    saveDB(db);

    return res.status(400).json({
      error: 'CAPTCHA bulunamadı veya süresi doldu. Yenileyin.'
    });
  }

  if (captcha.answer !== Number(captchaAnswer)) {
    const attempts = (db.verifyAttempts[req.clientIp] || 0) + 1;
    db.verifyAttempts[req.clientIp] = attempts;
    saveDB(db);

    return res.status(400).json({
      error: 'CAPTCHA cevabı yanlış.',
      remainingAttempts: Math.max(0, 5 - attempts)
    });
  }

  delete db.captchas[captchaId];
  delete db.verifyAttempts[req.clientIp];
  saveDB(db);

  const verificationToken = jwt.sign(
    { purpose: 'human-verification' },
    JWT_SECRET,
    { expiresIn: '12h' }
  );

  res.json({
    success: true,
    verified: true,
    verificationToken,
    expiresIn: 43200
  });
});

app.get('/api/verify-status', (req, res) => {
  try {
    const decoded = jwt.verify(
      req.headers['x-verification-token'] || '',
      JWT_SECRET
    );

    res.json({
      verified: decoded.purpose === 'human-verification'
    });
  } catch {
    res.json({ verified: false });
  }
});

// PANEL KAYIT
app.post('/api/register', async (req, res) => {
  try {
    const {
      username,
      email,
      password,
      captchaId,
      captchaAnswer
    } = req.body || {};

    if (
      typeof username !== 'string' ||
      username.trim().length < 3 ||
      username.trim().length > 24 ||
      !validEmail(email) ||
      typeof password !== 'string' ||
      password.length < 8 ||
      password.length > 128
    ) {
      return res.status(400).json({
        error: 'Kullanıcı adı 3-24, geçerli e-posta ve 8-128 karakterlik şifre gereklidir.'
      });
    }

    const db = loadDB();
    const captcha = db.captchas[captchaId];

    if (
      !captcha ||
      Date.now() - captcha.createdAt > 600000 ||
      captcha.answer !== Number(captchaAnswer)
    ) {
      return res.status(400).json({
        error: 'Kayıt CAPTCHA bilgileri hatalı.'
      });
    }

    const normalizedEmail = email.trim().toLowerCase();
    const normalizedName = username.trim();

    if (db.users.some(
      u => u.username.toLowerCase() === normalizedName.toLowerCase()
    )) {
      return res.status(409).json({
        error: 'Kullanıcı adı zaten kullanılıyor.'
      });
    }

    if (db.users.some(
      u => (u.email || '').toLowerCase() === normalizedEmail
    )) {
      return res.status(409).json({
        error: 'Bu e-posta zaten kayıtlı.'
      });
    }

    const user = {
      id: randomString(16),
      username: normalizedName,
      email: normalizedEmail,
      password: await bcrypt.hash(password, 12),
      createdAt: Date.now()
    };

    db.users.push(user);
    delete db.captchas[captchaId];
    saveDB(db);

    const token = jwt.sign(
      {
        kind: 'dashboard',
        id: user.id,
        username: user.username
      },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      success: true,
      token,
      user: safeUser(user)
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({
      error: 'Kayıt sırasında sunucu hatası.'
    });
  }
});

// PANEL GİRİŞ
app.post('/api/login', async (req, res) => {
  try {
    const {
      login,
      username,
      email,
      password
    } = req.body || {};

    const identity = String(
      login || email || username || ''
    ).trim().toLowerCase();

    if (!identity || typeof password !== 'string') {
      return res.status(400).json({
        error: 'E-posta/kullanıcı adı ve şifre gerekli.'
      });
    }

    const db = loadDB();

    const user = db.users.find(
      u =>
        u.username.toLowerCase() === identity ||
        (u.email || '').toLowerCase() === identity
    );

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({
        error: 'E-posta/kullanıcı adı veya şifre hatalı.'
      });
    }

    const token = jwt.sign(
      {
        kind: 'dashboard',
        id: user.id,
        username: user.username
      },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      success: true,
      token,
      user: safeUser(user)
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({
      error: 'Giriş sırasında sunucu hatası.'
    });
  }
});

app.get('/api/me', authenticateToken, (req, res) => {
  const user = loadDB().users.find(u => u.id === req.user.id);

  if (!user) {
    return res.status(404).json({
      error: 'Kullanıcı bulunamadı.'
    });
  }

  res.json({ user: safeUser(user) });
});

// PROJELER
app.get('/api/projects', authenticateToken, (req, res) => {
  const db = loadDB();

  res.json({
    projects: db.projects
      .filter(p => p.userId === req.user.id)
      .map(({ apiKey, ...p }) => ({ ...p, apiKey }))
  });
});

app.post('/api/projects', authenticateToken, (req, res) => {
  try {
    const { name, type } = req.body || {};

    if (
      typeof name !== 'string' ||
      name.trim().length < 2 ||
      name.trim().length > 60
    ) {
      return res.status(400).json({
        error: 'Proje adı 2-60 karakter olmalıdır.'
      });
    }

    if (!['Web', 'Mobil', 'Oyun', 'API'].includes(type || 'Web')) {
      return res.status(400).json({
        error: 'Geçersiz proje türü.'
      });
    }

    const db = loadDB();

    const project = {
      id: randomString(16),
      userId: req.user.id,
      name: name.trim(),
      type: type || 'Web',
      identifier: '',
      gameName: null,
      packageName: null,
      allowedOrigin: '*',
      apiKey: 'vant_' + randomString(32),
      apiCalls: 0,
      createdAt: Date.now()
    };

    if (project.type === 'Oyun') {
      const { gameName, packageName } = req.body;

      if (
        typeof gameName !== 'string' ||
        !gameName.trim() ||
        gameName.trim().length > 80 ||
        typeof packageName !== 'string' ||
        !/^[a-zA-Z][a-zA-Z0-9_]*(\.[a-zA-Z][a-zA-Z0-9_]*)+$/.test(packageName.trim())
      ) {
        return res.status(400).json({
          error: 'Oyun adı ve geçerli paket adı zorunludur. Örn: com.vantorium.mygame'
        });
      }

      project.gameName = gameName.trim();
      project.packageName = packageName.trim();
      project.identifier = packageName.trim();
    } else {
      const { identifier } = req.body;

      if (
        typeof identifier !== 'string' ||
        !identifier.trim() ||
        identifier.length > 255
      ) {
        return res.status(400).json({
          error: 'Tanımlayıcı alanı zorunludur.'
        });
      }

      project.identifier = identifier.trim();

      if (project.type === 'Mobil') {
        project.packageName = identifier.trim();
      }
    }

    db.projects.push(project);
    saveDB(db);

    res.json({
      success: true,
      project
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({
      error: 'Proje oluşturulamadı.'
    });
  }
});

app.delete('/api/projects/:id', authenticateToken, (req, res) => {
  const db = loadDB();

  const index = db.projects.findIndex(
    p => p.id === req.params.id && p.userId === req.user.id
  );

  if (index < 0) {
    return res.status(404).json({
      error: 'Proje bulunamadı.'
    });
  }

  db.projects.splice(index, 1);
  db.appData = db.appData.filter(d => d.projectId !== req.params.id);
  db.appUsers = db.appUsers.filter(u => u.projectId !== req.params.id);
  db.files = db.files.filter(f => f.projectId !== req.params.id);

  saveDB(db);
  res.json({ success: true });
});

app.put('/api/projects/:id/settings', authenticateToken, (req, res) => {
  const db = loadDB();

  const project = db.projects.find(
    p => p.id === req.params.id && p.userId === req.user.id
  );

  if (!project) {
    return res.status(404).json({
      error: 'Proje bulunamadı.'
    });
  }

  const origin = String(req.body.allowedOrigin || '*').trim();

  if (origin !== '*') {
    try {
      new URL(origin.includes('://') ? origin : 'https://' + origin);
    } catch {
      return res.status(400).json({
        error: 'Geçersiz domain.'
      });
    }
  }

  project.allowedOrigin = origin;
  saveDB(db);

  res.json({
    success: true,
    allowedOrigin: origin
  });
});

app.get('/api/projects/:id/data', authenticateToken, (req, res) => {
  const db = loadDB();

  const project = db.projects.find(
    p => p.id === req.params.id && p.userId === req.user.id
  );

  if (!project) {
    return res.status(404).json({
      error: 'Proje bulunamadı.'
    });
  }

  res.json({
    data: db.appData.filter(d => d.projectId === project.id)
  });
});

// UYGULAMA KAYIT
app.post('/api/app/auth/register', authenticateApp, async (req, res) => {
  try {
    const { email, password, username } = req.body || {};

    if (
      !validEmail(email) ||
      typeof password !== 'string' ||
      password.length < 8 ||
      password.length > 128
    ) {
      return res.status(400).json({
        error: 'Geçerli e-posta ve 8-128 karakterlik şifre gerekli.'
      });
    }

    if (
      username !== undefined &&
      (
        typeof username !== 'string' ||
        username.trim().length < 2 ||
        username.trim().length > 32
      )
    ) {
      return res.status(400).json({
        error: 'Kullanıcı adı 2-32 karakter olmalıdır.'
      });
    }

    const db = loadDB();
    const normalizedEmail = email.trim().toLowerCase();

    if (
      db.appUsers.some(
        u => u.projectId === req.project.id && u.email === normalizedEmail
      )
    ) {
      return res.status(409).json({
        error: 'Bu e-posta bu uygulamada kayıtlı.'
      });
    }

    const user = {
      id: randomString(16),
      projectId: req.project.id,
      email: normalizedEmail,
      username: username ? username.trim() : null,
      password: await bcrypt.hash(password, 12),
      createdAt: Date.now()
    };

    db.appUsers.push(user);
    saveDB(db);

    const token = jwt.sign(
      {
        kind: 'app-user',
        sub: user.id,
        projectId: req.project.id,
        email: user.email
      },
      JWT_SECRET,
      { expiresIn: '30d' }
    );

    res.status(201).json({
      success: true,
      token,
      user: {
        id: user.id,
        email: user.email,
        username: user.username
      }
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({
      error: 'Uygulama kaydı başarısız.'
    });
  }
});

// UYGULAMA GİRİŞ
app.post('/api/app/auth/login', authenticateApp, async (req, res) => {
  try {
    const { email, password } = req.body || {};

    if (!validEmail(email) || typeof password !== 'string') {
      return res.status(400).json({
        error: 'E-posta ve şifre gerekli.'
      });
    }

    const db = loadDB();
    const normalizedEmail = email.trim().toLowerCase();

    const user = db.appUsers.find(
      u => u.projectId === req.project.id && u.email === normalizedEmail
    );

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({
        error: 'E-posta veya şifre hatalı.'
      });
    }

    const token = jwt.sign(
      {
        kind: 'app-user',
        sub: user.id,
        projectId: req.project.id,
        email: user.email
      },
      JWT_SECRET,
      { expiresIn: '30d' }
    );

    res.json({
      success: true,
      token,
      user: {
        id: user.id,
        email: user.email,
        username: user.username
      }
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({
      error: 'Uygulama girişi başarısız.'
    });
  }
});

app.get(
  '/api/app/auth/me',
  authenticateApp,
  authenticateAppUser,
  (req, res) => {
    const user = loadDB().appUsers.find(
      u => u.id === req.appUser.sub && u.projectId === req.project.id
    );

    if (!user) {
      return res.status(404).json({
        error: 'Kullanıcı bulunamadı.'
      });
    }

    res.json({
      user: {
        id: user.id,
        email: user.email,
        username: user.username,
        createdAt: user.createdAt
      }
    });
  }
);

// UYGULAMA VERİ KAYDETME
app.post('/api/app/data', authenticateApp, (req, res) => {
  try {
    const { key: dataKey, value } = req.body || {};

    if (
      typeof dataKey !== 'string' ||
      !dataKey.trim() ||
      dataKey.length > 100
    ) {
      return res.status(400).json({
        error: 'Geçersiz veri anahtarı.'
      });
    }

    const serialized = JSON.stringify(value);

    if (serialized === undefined || serialized.length > 100000) {
      return res.status(413).json({
        error: 'Veri eksik veya çok büyük.'
      });
    }

    const db = loadDB();

    const existing = db.appData.find(
      d => d.projectId === req.project.id && d.key === dataKey
    );

    if (existing) {
      existing.value = value;
      existing.updatedAt = Date.now();
    } else {
      db.appData.push({
        projectId: req.project.id,
        key: dataKey,
        value,
        createdAt: Date.now()
      });
    }

    saveDB(db);

    res.json({
      success: true,
      message: 'Veri kaydedildi.'
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({
      error: 'Veri kaydedilemedi.'
    });
  }
});

app.get('/api/app/data/:key', authenticateApp, (req, res) => {
  const data = loadDB().appData.find(
    d => d.projectId === req.project.id && d.key === req.params.key
  );

  if (!data) {
    return res.status(404).json({
      error: 'Veri bulunamadı.'
    });
  }

  res.json({
    key: data.key,
    value: data.value
  });
});

// DOSYA YÜKLEME
const upload = multer({
  dest: UPLOAD_DIR,
  limits: {
    fileSize: 50 * 1024 * 1024,
    files: 1
  }
});

app.post(
  '/api/projects/:id/files',
  authenticateToken,
  upload.single('file'),
  (req, res) => {
    if (!req.file) {
      return res.status(400).json({
        error: 'Dosya seçilmedi.'
      });
    }

    const db = loadDB();

    const project = db.projects.find(
      p => p.id === req.params.id && p.userId === req.user.id
    );

    if (!project) {
      fs.unlinkSync(req.file.path);

      return res.status(404).json({
        error: 'Proje bulunamadı.'
      });
    }

    const file = {
      id: randomString(12),
      projectId: project.id,
      originalName: path.basename(req.file.originalname),
      storedName: req.file.filename,
      size: req.file.size,
      createdAt: Date.now()
    };

    db.files.push(file);
    saveDB(db);

    res.json({
      success: true,
      file
    });
  }
);

// FRONTEND
const frontend = `<!doctype html>
<html lang="tr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Vantorium Base</title>
<script src="https://cdn.tailwindcss.com"></script>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
<style>
:root{font-family:Inter,ui-sans-serif,system-ui;background:#f6f7fb;color:#171923}
*{box-sizing:border-box}
body{font-family:Inter,ui-sans-serif,system-ui}
.card{background:#fff;border:1px solid #e9eaf0;border-radius:18px;box-shadow:0 4px 18px rgba(20,25,45,.035)}
.field{width:100%;padding:12px 14px;border:1px solid #e4e6ed;border-radius:11px;background:#fff;outline:none;font:inherit;font-size:14px;transition:.2s}
.field:focus{border-color:#7567ed;box-shadow:0 0 0 3px #7567ed18}
.btn{background:#6254df;color:#fff;padding:11px 16px;border-radius:11px;font-size:13px;font-weight:650;transition:.18s}
.btn:hover{background:#5143ce;transform:translateY(-1px)}
.btn-soft{background:#f0efff;color:#5547d0}
.btn-soft:hover{background:#e6e3ff}
.muted{color:#85899a}
.hidden{display:none!important}
.sidebar{width:246px;background:#fff;border-right:1px solid #ececf1;min-height:100vh}
.navitem{display:flex;align-items:center;gap:12px;padding:11px 13px;border-radius:10px;color:#737789;font-size:13px;font-weight:600}
.navitem.active{background:#f0efff;color:#584bd2}
.stat{background:linear-gradient(145deg,#fff,#fbfbff)}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
@media(max-width:760px){.sidebar{display:none}.main{padding:18px!important}.topbar{padding:16px!important}}
</style>
</head>
<body>

<div id="toast" class="fixed top-4 right-4 z-[100]"></div>

<section id="verifyScreen" class="fixed inset-0 z-50 bg-[#f6f7fb] flex items-center justify-center p-5">
<div class="card w-full max-w-md p-8 text-center">
<div class="mx-auto mb-5 grid h-12 w-12 place-items-center rounded-2xl bg-[#6254df] text-white text-xl font-extrabold">V</div>
<h1 class="text-2xl font-extrabold tracking-tight">Vantorium Base</h1>
<p class="muted mt-2 text-sm">Devam etmek için güvenlik kontrolünü tamamlayın.</p>
<button class="btn w-full mt-7" onclick="startVerify()">Doğrulamayı başlat</button>
<div id="captchaBox" class="hidden mt-5">
<p id="question" class="font-bold mb-3"></p>
<input id="answer" type="number" class="field mb-3" placeholder="Cevap">
<button class="btn w-full" onclick="submitVerify()">Onayla</button>
</div>
</div>
</section>

<section id="auth" class="hidden min-h-screen flex items-center justify-center p-5">
<div class="card w-full max-w-[430px] p-8">
<div class="flex items-center gap-3 mb-7">
<div class="grid h-10 w-10 place-items-center rounded-xl bg-[#6254df] text-white font-bold">V</div>
<div><b class="text-lg">Vantorium Base</b><p class="muted text-xs">Developer workspace</p></div>
</div>
<h1 class="text-2xl font-bold tracking-tight mb-1" id="authTitle">Tekrar hoş geldin</h1>
<p class="muted text-sm mb-6" id="authDesc">Hesabına giriş yap ve projelerini yönet.</p>

<div id="loginForm">
<label class="text-xs font-semibold">E-posta veya kullanıcı adı</label>
<input id="loginIdentity" class="field mt-2 mb-4" placeholder="ornek@mail.com">
<label class="text-xs font-semibold">Şifre</label>
<input id="loginPass" type="password" class="field mt-2 mb-5" placeholder="Şifren">
<button class="btn w-full" onclick="login()">Giriş yap</button>
<p class="text-center text-sm muted mt-5">Hesabın yok mu? <button class="font-semibold text-[#6254df]" onclick="toggleAuth()">Kayıt ol</button></p>
</div>

<div id="registerForm" class="hidden">
<label class="text-xs font-semibold">Kullanıcı adı</label>
<input id="regUser" class="field mt-2 mb-3" placeholder="kullaniciadi">
<label class="text-xs font-semibold">E-posta</label>
<input id="regEmail" type="email" class="field mt-2 mb-3" placeholder="ornek@mail.com">
<label class="text-xs font-semibold">Şifre</label>
<input id="regPass" type="password" class="field mt-2 mb-3" placeholder="En az 8 karakter">
<div class="flex gap-2 items-center mb-4">
<input id="regAnswer" type="number" class="field" placeholder="CAPTCHA">
<span id="regQuestion" class="rounded-xl bg-[#f2f1ff] px-4 py-3 text-sm font-bold whitespace-nowrap"></span>
</div>
<button class="btn w-full" onclick="register()">Hesap oluştur</button>
<p class="text-center text-sm muted mt-5">Zaten hesabın var mı? <button class="font-semibold text-[#6254df]" onclick="toggleAuth()">Giriş yap</button></p>
</div>
</div>
</section>

<div id="dashboard" class="hidden min-h-screen">
<aside class="sidebar fixed left-0 top-0 hidden md:block p-5">
<div class="flex items-center gap-3 px-2 mb-10">
<div class="grid h-10 w-10 place-items-center rounded-xl bg-[#6254df] text-white font-extrabold">V</div>
<div><b>Vantorium</b><p class="muted text-[11px]">BASE PLATFORM</p></div>
</div>
<p class="muted text-[10px] font-bold tracking-[.16em] px-3 mb-2">WORKSPACE</p>
<div class="navitem active">▦ <span>Genel Bakış</span></div>
<div class="navitem">◇ <span>Projeler</span></div>
<div class="navitem">⌘ <span>API & Entegrasyon</span></div>
<div class="absolute bottom-5 left-5 right-5">
<div class="rounded-xl bg-[#f7f7fb] p-3">
<p class="text-xs font-semibold">Vantorium Base</p>
<p class="muted text-[11px] mt-1">Developer workspace</p>
</div>
</div>
</aside>

<main class="main md:ml-[246px] p-8 max-w-[1500px]">
<header class="topbar flex flex-wrap justify-between items-center gap-4 mb-8">
<div>
<p class="muted text-xs mb-1">WORKSPACE / OVERVIEW</p>
<h1 class="text-2xl font-extrabold tracking-tight">Genel Bakış</h1>
<p class="muted text-sm mt-1">Projelerini ve uygulama servislerini yönet.</p>
</div>
<div class="flex items-center gap-3">
<div class="text-right hidden sm:block">
<p id="profileName" class="text-sm font-semibold">Kullanıcı</p>
<p id="profileEmail" class="muted text-xs"></p>
</div>
<button class="btn btn-soft" onclick="logout()">Çıkış yap</button>
</div>
</header>

<div class="grid grid-cols-1 sm:grid-cols-2 gap-4 mb-7">
<div class="card stat p-5">
<p class="muted text-xs font-semibold">TOPLAM PROJE</p>
<div id="projectCount" class="text-3xl font-extrabold mt-3">0</div>
<p class="muted text-xs mt-2">Workspace projeleri</p>
</div>
<div class="card stat p-5">
<p class="muted text-xs font-semibold">API ÇAĞRISI</p>
<div id="callCount" class="text-3xl font-extrabold mt-3">0</div>
<p class="muted text-xs mt-2">Toplam istek sayısı</p>
</div>
</div>

<div class="card p-6 mb-8">
<div class="flex justify-between items-start mb-5">
<div>
<h2 class="font-bold text-lg">Yeni proje oluştur</h2>
<p class="muted text-sm mt-1">Uygulaman için ayrı bir API alanı oluştur.</p>
</div>
<span class="rounded-lg bg-[#f0efff] px-3 py-1.5 text-xs font-bold text-[#6254df]">NEW PROJECT</span>
</div>

<div class="grid grid-cols-1 md:grid-cols-2 gap-4">
<div>
<label class="text-xs font-semibold">Proje adı</label>
<input id="projName" class="field mt-2" placeholder="Örn. Vantorium Mobile">
</div>
<div>
<label class="text-xs font-semibold">Proje türü</label>
<select id="projType" class="field mt-2" onchange="updateFields()">
<option value="Web">Web uygulaması</option>
<option value="Mobil">Mobil uygulama</option>
<option value="Oyun">Oyun</option>
<option value="API">Backend API</option>
</select>
</div>
</div>

<div id="normalFields" class="mt-4">
<label id="identifierLabel" class="text-xs font-semibold">Domain / URL</label>
<input id="identifier" class="field mt-2" placeholder="https://example.com">
</div>

<div id="gameFields" class="hidden mt-4 grid grid-cols-1 md:grid-cols-2 gap-4">
<div>
<label class="text-xs font-semibold">Oyun adı</label>
<input id="gameName" class="field mt-2" placeholder="Vantorium Adventure">
</div>
<div>
<label class="text-xs font-semibold">Paket adı</label>
<input id="packageName" class="field mt-2" placeholder="com.vantorium.mygame">
</div>
</div>

<button class="btn mt-5" onclick="createProject()">＋ Proje oluştur</button>
</div>

<div class="flex items-end justify-between mb-4">
<div>
<h2 class="text-lg font-bold">Projelerim</h2>
<p class="muted text-sm mt-1">Oluşturduğun tüm projeler.</p>
</div>
<span id="projectLabel" class="muted text-xs"></span>
</div>

<div id="projects" class="grid grid-cols-1 xl:grid-cols-2 gap-4"></div>
</main>
</div>

<div id="dataModal" class="hidden fixed inset-0 bg-black/40 z-[80] p-4 items-center justify-center">
<div class="card p-6 w-full max-w-2xl">
<div class="flex justify-between mb-4">
<h2 class="font-bold text-lg">Proje verileri</h2>
<button onclick="closeData()">✕</button>
</div>
<pre id="dataContent" class="bg-[#f6f7fb] rounded-xl p-4 overflow-auto max-h-96 text-xs mono"></pre>
</div>
</div>

<script>
const API = location.origin;

let token = localStorage.getItem('token');
let verificationToken = localStorage.getItem('verificationToken');
let captchaId = '';
let registerCaptchaId = '';

function esc(v) {
  return String(v ?? '').replace(/[&<>"']/g, c => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;'
  }[c]));
}

function toast(m) {
  const e = document.getElementById('toast');
  e.innerHTML =
    '<div class="rounded-xl bg-[#202130] text-white px-4 py-3 text-sm shadow-xl">' +
    esc(m) +
    '</div>';

  setTimeout(() => e.innerHTML = '', 3200);
}

async function api(url, options = {}) {
  const headers = {
    ...(options.headers || {}),
    'Content-Type': 'application/json',
    'X-Verification-Token': verificationToken || ''
  };

  const r = await fetch(API + url, {
    ...options,
    headers
  });

  const d = await r.json().catch(() => ({
    error: 'Sunucu yanıtı okunamadı.'
  }));

  if (r.status === 403 && d.verificationRequired) {
    localStorage.removeItem('verificationToken');
    verificationToken = null;
    document.getElementById('verifyScreen').classList.remove('hidden');
  }

  return {
    response: r,
    data: d
  };
}

async function startVerify() {
  try {
    const r = await fetch(API + '/api/generate-captcha');
    const d = await r.json();

    if (!r.ok) throw Error(d.error);

    captchaId = d.captchaId;
    document.getElementById('question').innerText = d.soru;
    document.getElementById('captchaBox').classList.remove('hidden');
  } catch (e) {
    toast(e.message);
  }
}

async function submitVerify() {
  const answer = document.getElementById('answer').value;

  if (!answer) return toast('CAPTCHA cevabını girin.');

  try {
    const r = await fetch(API + '/api/verify-human', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        captchaId,
        captchaAnswer: answer
      })
    });

    const d = await r.json();

    if (!r.ok) {
      toast(d.error);
      document.getElementById('answer').value = '';
      return;
    }

    verificationToken = d.verificationToken;
    localStorage.setItem('verificationToken', verificationToken);

    await continueApp();
  } catch {
    toast('Bağlantı hatası.');
  }
}

async function continueApp() {
  if (!verificationToken) {
    document.getElementById('verifyScreen').classList.remove('hidden');
    return;
  }

  const r = await fetch(API + '/api/verify-status', {
    headers: {
      'X-Verification-Token': verificationToken
    }
  });

  const d = await r.json();

  if (!d.verified) {
    localStorage.removeItem('verificationToken');
    verificationToken = null;
    document.getElementById('verifyScreen').classList.remove('hidden');
    return;
  }

  document.getElementById('verifyScreen').classList.add('hidden');

  if (token) {
    const me = await api('/api/me', {
      headers: {
        Authorization: 'Bearer ' + token
      }
    });

    if (me.response.ok) {
      document.getElementById('auth').classList.add('hidden');
      document.getElementById('dashboard').classList.remove('hidden');

      document.getElementById('profileName').innerText =
        me.data.user.username;

      document.getElementById('profileEmail').innerText =
        me.data.user.email || '';

      loadProjects();
      return;
    }

    localStorage.removeItem('token');
    token = null;
  }

  document.getElementById('auth').classList.remove('hidden');
}

function toggleAuth() {
  const reg = document
    .getElementById('registerForm')
    .classList.toggle('hidden');

  document.getElementById('loginForm').classList.toggle('hidden');

  document.getElementById('authTitle').innerText =
    reg ? 'Hesabını oluştur' : 'Tekrar hoş geldin';

  document.getElementById('authDesc').innerText =
    reg
      ? 'Yeni workspace hesabını oluştur.'
      : 'Hesabına giriş yap ve projelerini yönet.';

  if (reg) loadRegisterCaptcha();
}

async function loadRegisterCaptcha() {
  try {
    const r = await fetch(API + '/api/captcha');
    const d = await r.json();

    registerCaptchaId = d.captchaId;
    document.getElementById('regQuestion').innerText = d.soru;
  } catch {
    toast('CAPTCHA yüklenemedi.');
  }
}

async function register() {
  const body = {
    username: document.getElementById('regUser').value.trim(),
    email: document.getElementById('regEmail').value.trim(),
    password: document.getElementById('regPass').value,
    captchaId: registerCaptchaId,
    captchaAnswer: document.getElementById('regAnswer').value
  };

  const { response, data } = await api('/api/register', {
    method: 'POST',
    body: JSON.stringify(body)
  });

  if (!response.ok) {
    toast(data.error);
    loadRegisterCaptcha();
    return;
  }

  saveSession(data);
}

async function login() {
  const identity =
    document.getElementById('loginIdentity').value.trim();

  const password =
    document.getElementById('loginPass').value;

  const { response, data } = await api('/api/login', {
    method: 'POST',
    body: JSON.stringify({
      login: identity,
      password
    })
  });

  if (!response.ok) return toast(data.error);

  saveSession(data);
}

function saveSession(d) {
  token = d.token;
  localStorage.setItem('token', token);

  document.getElementById('auth').classList.add('hidden');
  document.getElementById('dashboard').classList.remove('hidden');

  document.getElementById('profileName').innerText =
    d.user.username;

  document.getElementById('profileEmail').innerText =
    d.user.email || '';

  toast('Giriş başarılı.');
  loadProjects();
}

function logout() {
  localStorage.removeItem('token');
  token = null;
  location.reload();
}

function updateFields() {
  const type = document.getElementById('projType').value;
  const game = type === 'Oyun';

  document.getElementById('normalFields')
    .classList.toggle('hidden', game);

  document.getElementById('gameFields')
    .classList.toggle('hidden', !game);

  document.getElementById('identifierLabel').innerText = ({
    Web: 'DOMAIN / URL',
    Mobil: 'PAKET ADI',
    API: 'AÇIKLAMA'
  })[type] || 'Tanımlayıcı';

  document.getElementById('identifier').placeholder = ({
    Web: 'https://example.com',
    Mobil: 'com.company.app',
    API: 'Skor API'
  })[type] || '';
}

async function createProject() {
  const name = document.getElementById('projName').value.trim();
  const type = document.getElementById('projType').value;

  const body = {
    name,
    type
  };

  if (type === 'Oyun') {
    body.gameName = document.getElementById('gameName').value.trim();
    body.packageName = document.getElementById('packageName').value.trim();
  } else {
    body.identifier = document.getElementById('identifier').value.trim();
  }

  if (!name) return toast('Proje adını girin.');

  const { response, data } = await api('/api/projects', {
    method: 'POST',
    headers: {
      Authorization: 'Bearer ' + token
    },
    body: JSON.stringify(body)
  });

  if (!response.ok) return toast(data.error);

  toast('Proje oluşturuldu.');

  ['projName', 'gameName', 'packageName', 'identifier'].forEach(id => {
    document.getElementById(id).value = '';
  });

  loadProjects();
}

async function loadProjects() {
  const { response, data } = await api('/api/projects', {
    headers: {
      Authorization: 'Bearer ' + token
    }
  });

  if (!response.ok) {
    if (response.status === 401) logout();
    return;
  }

  const list = document.getElementById('projects');
  list.innerHTML = '';

  document.getElementById('projectCount').innerText =
    data.projects.length;

  document.getElementById('projectLabel').innerText =
    data.projects.length + ' proje';

  document.getElementById('callCount').innerText =
    data.projects.reduce((s, p) => s + (p.apiCalls || 0), 0);

  if (!data.projects.length) {
    list.innerHTML =
      '<div class="card p-8 text-center muted text-sm">Henüz proje oluşturmadın.</div>';
    return;
  }

  data.projects.forEach(p => {
    const id = esc(p.id);

    const identity = p.type === 'Oyun'
      ? 'Oyun: ' + p.gameName + ' · Paket: ' + p.packageName
      : 'Tanımlayıcı: ' + (p.identifier || '-');

    const card = document.createElement('article');
    card.className = 'card p-5';

    card.innerHTML =
      '<div class="flex justify-between gap-3">' +
        '<div>' +
          '<span class="rounded-md bg-[#f0efff] px-2 py-1 text-[10px] font-bold text-[#6254df]">' +
            esc(p.type) +
          '</span>' +
          '<h3 class="font-bold text-lg mt-3">' + esc(p.name) + '</h3>' +
          '<p class="muted text-xs mt-1">' + esc(identity) + '</p>' +
        '</div>' +
        '<button class="text-xs font-semibold text-red-500" data-delete="' + id + '">Sil</button>' +
      '</div>' +

      '<div class="mt-4 rounded-xl bg-[#f7f7fb] p-3">' +
        '<p class="muted text-[10px] font-bold mb-2">PROJECT API KEY</p>' +
        '<p class="mono text-xs break-all">' + esc(p.apiKey) + '</p>' +
      '</div>' +

      '<div class="flex flex-wrap gap-2 mt-4">' +
        '<button class="btn btn-soft" data-copy="' + esc(p.apiKey) + '">Key kopyala</button>' +
        '<button class="btn btn-soft" data-guide="' + id + '">Entegrasyon</button>' +
        '<button class="btn btn-soft" data-data="' + id + '">Veriler</button>' +
      '</div>' +

      '<div id="guide-' + id + '" class="hidden mt-4 border-t pt-4">' +
        '<label class="text-xs font-semibold">İzin verilen domain (* = tümü)</label>' +
        '<input class="field mt-2 mb-2" id="origin-' + id + '" value="' + esc(p.allowedOrigin || '*') + '">' +
        '<button class="btn mb-4" data-save="' + id + '">Ayarları kaydet</button>' +
        '<p class="font-bold text-sm mb-2">Uygulama kullanıcı kayıt/giriş API</p>' +
        '<pre class="mono whitespace-pre-wrap rounded-xl bg-[#202130] p-3 text-[11px] text-green-300">' +
          'POST ' + API + '/api/app/auth/register\\n' +
          'POST ' + API + '/api/app/auth/login\\n' +
          'GET  ' + API + '/api/app/auth/me\\n\\n' +
          'Header: x-api-key: ' + p.apiKey + '\\n' +
          'Header (me): Authorization: Bearer APP_USER_TOKEN\\n\\n' +
          'Register body: {email,password,username?}\\n' +
          'Login body: {email,password}' +
        '</pre>' +
        '<p class="muted text-[11px] mt-2">API anahtarını herkese açık istemci kodunda kullanmak güvenlik riski taşır. Hassas işlemleri sunucu tarafında yap.</p>' +
      '</div>';

    list.appendChild(card);
  });
}

document.addEventListener('click', async e => {
  const t = e.target;

  if (t.dataset.copy) {
    try {
      await navigator.clipboard.writeText(t.dataset.copy);
      toast('API Key kopyalandı.');
    } catch {
      toast('Kopyalama başarısız.');
    }
  }

  if (t.dataset.delete) {
    if (!confirm('Projeyi ve projeye ait kullanıcı/verileri silmek istiyor musun?')) {
      return;
    }

    const { response, data } = await api(
      '/api/projects/' + encodeURIComponent(t.dataset.delete),
      {
        method: 'DELETE',
        headers: {
          Authorization: 'Bearer ' + token
        }
      }
    );

    toast(response.ok ? 'Proje silindi.' : data.error);
    loadProjects();
  }

  if (t.dataset.guide) {
    document.getElementById('guide-' + t.dataset.guide)
      .classList.toggle('hidden');
  }

  if (t.dataset.save) {
    const id = t.dataset.save;
    const origin = document.getElementById('origin-' + id).value;

    const { response, data } = await api(
      '/api/projects/' + encodeURIComponent(id) + '/settings',
      {
        method: 'PUT',
        headers: {
          Authorization: 'Bearer ' + token
        },
        body: JSON.stringify({
          allowedOrigin: origin
        })
      }
    );

    toast(response.ok ? 'Ayarlar kaydedildi.' : data.error);
  }

  if (t.dataset.data) {
    openData(t.dataset.data);
  }
});

async function openData(id) {
  const { response, data } = await api(
    '/api/projects/' + encodeURIComponent(id) + '/data',
    {
      headers: {
        Authorization: 'Bearer ' + token
      }
    }
  );

  if (!response.ok) return toast(data.error);

  document.getElementById('dataContent').textContent =
    JSON.stringify(data.data, null, 2);

  document.getElementById('dataModal').classList.remove('hidden');
  document.getElementById('dataModal').classList.add('flex');
}

function closeData() {
  document.getElementById('dataModal').classList.add('hidden');
  document.getElementById('dataModal').classList.remove('flex');
}

updateFields();
continueApp();
</script>
</body>
</html>`;

app.get('/', (req, res) => {
  res.type('html').send(frontend);
});

app.use((err, req, res, next) => {
  console.error(err);

  if (err instanceof multer.MulterError) {
    return res.status(400).json({
      error: err.message
    });
  }

  res.status(500).json({
    error: 'Beklenmeyen sunucu hatası.'
  });
});

const server = app.listen(PORT, '0.0.0.0', () => {
  console.log(`Vantorium Base ${PORT} portunda. DB: ${DB_FILE}`);
});

process.on('SIGTERM', () => {
  server.close(() => process.exit(0));
});

process.on('SIGINT', () => {
  server.close(() => process.exit(0));
});
