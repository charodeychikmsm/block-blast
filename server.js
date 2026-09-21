const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
const DATA_FILE = path.join(__dirname, 'data.json');
const PUBLIC_DIR = path.join(__dirname, 'public');

app.use(express.json());
app.use(express.static(PUBLIC_DIR));

// ---------- Хранилище (JSON-файл) ----------
let data = { users: {} };

function loadData() {
  try {
    if (fs.existsSync(DATA_FILE)) {
      const raw = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
      if (raw && typeof raw === 'object') data = raw;
      if (!data.users) data.users = {};
    }
  } catch (e) {
    console.error('Ошибка загрузки data.json:', e.message);
  }
}

function saveData() {
  try {
    fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2));
  } catch (e) {
    console.error('Ошибка сохранения data.json:', e.message);
  }
}

loadData();

// ---------- Утилиты ----------
function hashPass(password, salt) {
  return crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
}
function makeToken() {
  return crypto.randomBytes(32).toString('hex');
}

function auth(req, res, next) {
  const token = req.headers['x-token'] || (req.body && req.body.token);
  if (!token) return res.status(401).json({ error: 'Нет токена' });
  for (const key in data.users) {
    if (data.users[key].token === token) {
      req.userKey = key;
      req.user = data.users[key];
      return next();
    }
  }
  return res.status(401).json({ error: 'Сессия истекла, войдите заново' });
}

// ---------- API ----------

// Регистрация
app.post('/api/register', (req, res) => {
  const { nick, password } = req.body || {};
  if (typeof nick !== 'string' || typeof password !== 'string')
    return res.status(400).json({ error: 'Некорректные данные' });

  const cleanNick = nick.trim();
  if (cleanNick.length < 2 || cleanNick.length > 20)
    return res.status(400).json({ error: 'Ник должен быть от 2 до 20 символов' });
  if (!/^[A-Za-zА-Яа-я0-9_\-]+$/.test(cleanNick))
    return res.status(400).json({ error: 'Ник: только буквы, цифры, "_" и "-"' });
  if (password.length < 3)
    return res.status(400).json({ error: 'Пароль минимум 3 символа' });

  const key = cleanNick.toLowerCase();
  if (data.users[key])
    return res.status(409).json({ error: 'Такой ник уже занят' });

  const salt = crypto.randomBytes(16).toString('hex');
  data.users[key] = {
    nick: cleanNick,
    salt,
    passHash: hashPass(password, salt),
    best: 0,
    token: makeToken()
  };
  saveData();

  res.json({
    ok: true,
    nick: cleanNick,
    best: 0,
    token: data.users[key].token
  });
});

// Вход
app.post('/api/login', (req, res) => {
  const { nick, password } = req.body || {};
  if (typeof nick !== 'string' || typeof password !== 'string')
    return res.status(400).json({ error: 'Некорректные данные' });

  const key = nick.trim().toLowerCase();
  const u = data.users[key];
  if (!u) return res.status(401).json({ error: 'Пользователь не найден' });

  if (hashPass(password, u.salt) !== u.passHash)
    return res.status(401).json({ error: 'Неверный пароль' });

  u.token = makeToken();
  saveData();

  res.json({ ok: true, nick: u.nick, best: u.best || 0, token: u.token });
});

// Кто я
app.get('/api/me', auth, (req, res) => {
  res.json({ nick: req.user.nick, best: req.user.best || 0 });
});

// Отправить счёт
app.post('/api/score', auth, (req, res) => {
  const { score } = req.body || {};
  if (typeof score !== 'number' || !isFinite(score) || score < 0 || score > 1e7)
    return res.status(400).json({ error: 'Некорректный счёт' });

  const s = Math.floor(score);
  if (s > (req.user.best || 0)) {
    req.user.best = s;
    saveData();
  }
  res.json({ ok: true, best: req.user.best });
});

// Таблица рекордов
app.get('/api/leaderboard', (req, res) => {
  const list = Object.values(data.users)
    .map(u => ({ nick: u.nick, best: u.best || 0 }))
    .sort((a, b) => b.best - a.best)
    .slice(0, 100);
  res.json({ leaderboard: list });
});

// Fallback — отдать index.html
app.use((req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, 'index.html'));
});

app.listen(PORT, () => {
  console.log('Server started on port ' + PORT);
});