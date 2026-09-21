const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
const DATA_FILE = path.join(__dirname, 'data.json');
const PUBLIC_DIR = path.join(__dirname, 'public');

app.use(express.json({ limit: '64kb' }));
app.use(express.static(PUBLIC_DIR));

// ---------- Константы времени ----------
const ONE_HOUR  = 60 * 60 * 1000;
const ONE_DAY   = 24 * ONE_HOUR;
const THREE_DAYS = 3 * ONE_DAY;

// ---------- Хранилище ----------
let data = { users: {}, feedback: [] };

function loadData() {
  try {
    if (fs.existsSync(DATA_FILE)) {
      const raw = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
      if (raw && typeof raw === 'object') data = raw;
      if (!data.users) data.users = {};
      if (!Array.isArray(data.feedback)) data.feedback = [];
    }
  } catch (e) { console.error('Ошибка загрузки data.json:', e.message); }
}
function saveData() {
  try { fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2)); }
  catch (e) { console.error('Ошибка сохранения data.json:', e.message); }
}
loadData();

// ---------- Утилиты ----------
function hashPass(password, salt) {
  return crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
}
function makeToken() { return crypto.randomBytes(32).toString('hex'); }

function auth(req, res, next) {
  const token = req.headers['x-token'] || (req.body && req.body.token);
  if (!token) return res.status(401).json({ error: 'Нет токена' });
  for (const key in data.users) {
    if (data.users[key].token === token) {
      req.userKey = key; req.user = data.users[key];
      return next();
    }
  }
  return res.status(401).json({ error: 'Сессия истекла, войдите заново' });
}

// Удаление отзывов старше 3 дней
function cleanOldFeedback() {
  const now = Date.now();
  const before = data.feedback.length;
  data.feedback = data.feedback.filter(f => now - f.createdAt < THREE_DAYS);
  if (data.feedback.length !== before) saveData();
}

// ---------- API аккаунтов ----------

app.post('/api/register', (req, res) => {
  const { nick, password } = req.body || {};
  if (typeof nick !== 'string' || typeof password !== 'string')
    return res.status(400).json({ error: 'Некорректные данные' });

  const cleanNick = nick.trim();
  if (cleanNick.length < 2 || cleanNick.length > 20)
    return res.status(400).json({ error: 'Ник: от 2 до 20 символов' });
  if (!/^[A-Za-zА-Яа-я0-9_\-]+$/.test(cleanNick))
    return res.status(400).json({ error: 'Ник: буквы, цифры, "_" и "-"' });
  if (password.length < 3)
    return res.status(400).json({ error: 'Пароль минимум 3 символа' });

  const key = cleanNick.toLowerCase();
  if (data.users[key]) return res.status(409).json({ error: 'Ник занят' });

  const salt = crypto.randomBytes(16).toString('hex');
  data.users[key] = {
    nick: cleanNick, salt, passHash: hashPass(password, salt),
    best: 0, token: makeToken()
  };
  saveData();
  res.json({ ok: true, nick: cleanNick, best: 0, token: data.users[key].token });
});

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

app.get('/api/me', auth, (req, res) => {
  res.json({ nick: req.user.nick, best: req.user.best || 0 });
});

app.post('/api/score', auth, (req, res) => {
  const { score } = req.body || {};
  if (typeof score !== 'number' || !isFinite(score) || score < 0 || score > 1e7)
    return res.status(400).json({ error: 'Некорректный счёт' });
  const s = Math.floor(score);
  if (s > (req.user.best || 0)) { req.user.best = s; saveData(); }
  res.json({ ok: true, best: req.user.best });
});

app.get('/api/leaderboard', (req, res) => {
  const list = Object.values(data.users)
    .map(u => ({ nick: u.nick, best: u.best || 0 }))
    .sort((a, b) => b.best - a.best)
    .slice(0, 100);
  res.json({ leaderboard: list });
});

// ---------- API отзывов ----------

// Список (только свежие, сортировка по лайкам)
app.get('/api/feedback', auth, (req, res) => {
  cleanOldFeedback();
  const now = Date.now();

  const list = data.feedback.map(f => ({
    id: f.id,
    nick: f.nick,
    text: f.text,
    likes: f.likes.length,
    liked: f.likes.includes(req.userKey),
    mine: f.userKey === req.userKey,
    createdAt: f.createdAt
  })).sort((a, b) => b.likes - a.likes || b.createdAt - a.createdAt);

  // Когда юзер может снова написать
  const myLast = data.feedback
    .filter(f => f.userKey === req.userKey)
    .sort((a, b) => b.createdAt - a.createdAt)[0];
  let canPostIn = 0;
  if (myLast) {
    const elapsed = now - myLast.createdAt;
    if (elapsed < ONE_DAY) canPostIn = ONE_DAY - elapsed;
  }

  res.json({ feedback: list, canPostIn });
});

// Создать отзыв (не чаще 1 раза в 24 часа)
app.post('/api/feedback', auth, (req, res) => {
  const { text } = req.body || {};
  if (typeof text !== 'string')
    return res.status(400).json({ error: 'Некорректные данные' });
  const clean = text.trim();
  if (clean.length < 3) return res.status(400).json({ error: 'Минимум 3 символа' });
  if (clean.length > 500) return res.status(400).json({ error: 'Максимум 500 символов' });

  cleanOldFeedback();

  const myLast = data.feedback
    .filter(f => f.userKey === req.userKey)
    .sort((a, b) => b.createdAt - a.createdAt)[0];
  if (myLast && Date.now() - myLast.createdAt < ONE_DAY) {
    const leftMs = ONE_DAY - (Date.now() - myLast.createdAt);
    const hours = Math.ceil(leftMs / ONE_HOUR);
    return res.status(429).json({ error: 'Вы уже писали. Следующий отзыв через ' + hours + ' ч.' });
  }

  const id = crypto.randomBytes(8).toString('hex');
  data.feedback.push({
    id, userKey: req.userKey, nick: req.user.nick,
    text: clean, likes: [], createdAt: Date.now()
  });
  saveData();
  res.json({ ok: true, id });
});

// Лайк / анлайк
app.post('/api/feedback/:id/like', auth, (req, res) => {
  cleanOldFeedback();
  const item = data.feedback.find(f => f.id === req.params.id);
  if (!item) return res.status(404).json({ error: 'Отзыв не найден' });
  const idx = item.likes.indexOf(req.userKey);
  if (idx >= 0) item.likes.splice(idx, 1);
  else item.likes.push(req.userKey);
  saveData();
  res.json({ ok: true, likes: item.likes.length, liked: idx < 0 });
});

// ---------- Fallback ----------
app.use((req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, 'index.html'));
});

app.listen(PORT, () => console.log('Server started on port ' + PORT));
