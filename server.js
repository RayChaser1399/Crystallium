/* ═══════════════════════════════════════════════════════════════════
   CRYSTALLIUM — backend
   Что делает:
     1) Проверяет initData Telegram Mini App (подпись бота) —
        /api/status, /api/events
     2) Проверяет оплату TON напрямую в блокчейне через tonapi.io —
        /api/status
     3) Принимает Telegram Stars через вебхук бота —
        /api/telegram/webhook
     4) Собирает события аналитики —
        POST /api/events
     5) Отдаёт агрегированную статистику для stats.html —
        GET /api/stats
     6) Раздаёт статику (index.html, config.js, манифест) из /public

   Хранилище: простые JSON/JSONL файлы в ./data — этого достаточно
   для старта. Если игроков станет много (тысячи в день) — замените
   readPaid()/markPaid()/appendEvents() на настоящую БД (Postgres/
   SQLite), сигнатуры функций можно оставить теми же.
   ═══════════════════════════════════════════════════════════════════ */

require('dotenv').config();
const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const app = express();
app.use(express.json({ limit: '256kb' }));

/* ── конфигурация из .env (см. .env.example) ── */
const PORT = process.env.PORT || 3000;
const BOT_TOKEN = process.env.BOT_TOKEN || '';           // токен бота из @BotFather
const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET || ''; // секрет для setWebhook (см. README)
const TON_ADDR = process.env.TON_ADDR || '';              // ваш TON-кошелёк (мерчант)
const TON_MIN_NANO = parseInt(process.env.TON_MIN_NANO || '1500000000', 10); // 1.5 TON
const TONAPI_KEY = process.env.TONAPI_KEY || '';          // необязательно, снимает лимиты tonapi.io
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || '';        // пароль для /api/stats и stats.html
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || '*'; // домен вашего Mini App

if (!BOT_TOKEN) console.warn('[warn] BOT_TOKEN не задан — проверка initData и Stars не будут работать');
if (!TON_ADDR) console.warn('[warn] TON_ADDR не задан — проверка TON-платежей не будет работать');
if (!ADMIN_TOKEN) console.warn('[warn] ADMIN_TOKEN не задан — панель статистики останется без пароля! Задайте его.');

/* ── CORS: разрешаем запросы из Mini App ── */
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', ALLOWED_ORIGIN);
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Init-Data');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

/* ── простой rate-limit по IP (не для DDoS, а чтобы не заспамили дешёвыми запросами) ── */
const hits = new Map();
function rateLimit(max, windowMs) {
  return (req, res, next) => {
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown';
    const now = Date.now();
    const rec = hits.get(ip) || { count: 0, ts: now };
    if (now - rec.ts > windowMs) { rec.count = 0; rec.ts = now; }
    rec.count++;
    hits.set(ip, rec);
    if (rec.count > max) return res.status(429).json({ error: 'rate_limited' });
    next();
  };
}

/* ═══ Telegram initData: проверка подписи ═══
   https://core.telegram.org/bots/webapps#validating-data-received-via-the-mini-app */
function checkInitData(initData) {
  if (!initData || !BOT_TOKEN) return null;
  const params = new URLSearchParams(initData);
  const hash = params.get('hash');
  if (!hash) return null;
  params.delete('hash');
  const pairs = [];
  for (const [k, v] of params.entries()) pairs.push(`${k}=${v}`);
  pairs.sort();
  const dataCheckString = pairs.join('\n');
  const secretKey = crypto.createHmac('sha256', 'WebAppData').update(BOT_TOKEN).digest();
  const computedHash = crypto.createHmac('sha256', secretKey).update(dataCheckString).digest('hex');
  if (computedHash !== hash) return null;
  // не старше 24 часов — защита от replay старого initData
  const authDate = parseInt(params.get('auth_date') || '0', 10);
  if (!authDate || Date.now() / 1000 - authDate > 86400) return null;
  try {
    const user = JSON.parse(params.get('user') || 'null');
    if (!user || !user.id) return null;
    return { uid: 'tg' + user.id, user };
  } catch (e) { return null; }
}

function requireUser(req, res, next) {
  const initData = req.headers['x-init-data'] || '';
  const auth = checkInitData(initData);
  if (!auth) return res.status(401).json({ error: 'invalid_init_data' });
  req.auth = auth;
  next();
}

/* ═══ Хранилище: paid.json { uid: {paid, method, amount, ts} } ═══ */
const DATA_DIR = path.join(__dirname, 'data');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
const PAID_FILE = path.join(DATA_DIR, 'paid.json');
const EVENTS_FILE = path.join(DATA_DIR, 'events.jsonl');

function readPaid() {
  try { return JSON.parse(fs.readFileSync(PAID_FILE, 'utf8')); } catch (e) { return {}; }
}
function markPaid(uid, method, amount) {
  const db = readPaid();
  db[uid] = { paid: true, method, amount, ts: Date.now() };
  fs.writeFileSync(PAID_FILE, JSON.stringify(db, null, 2));
}
function appendEvents(events) {
  const lines = events.map(e => JSON.stringify(e)).join('\n') + '\n';
  fs.appendFileSync(EVENTS_FILE, lines);
}

/* ═══ TON: поиск входящего платежа по memo через tonapi.io ═══
   Смотрим последние события аккаунта-мерчанта, ищем TonTransfer
   с комментарием, равным memo игрока, и суммой не меньше цены. */
async function findTonPayment(memo) {
  if (!TON_ADDR) return false;
  const url = `https://tonapi.io/v2/accounts/${TON_ADDR}/events?limit=100`;
  const headers = TONAPI_KEY ? { Authorization: `Bearer ${TONAPI_KEY}` } : {};
  const r = await fetch(url, { headers });
  if (!r.ok) throw new Error('tonapi ' + r.status);
  const data = await r.json();
  for (const ev of data.events || []) {
    for (const act of ev.actions || []) {
      if (act.type === 'TonTransfer' && act.TonTransfer) {
        const tr = act.TonTransfer;
        const comment = (tr.comment || '').trim();
        const amount = tr.amount || 0;
        if (comment === memo && amount >= TON_MIN_NANO) return true;
      }
    }
  }
  return false;
}

/* ═══ GET /api/status — проверка оплаты (вызывается кнопкой «Я оплатил») ═══ */
app.get('/api/status', rateLimit(20, 60_000), requireUser, async (req, res) => {
  const uid = req.auth.uid;
  const paidDb = readPaid();
  if (paidDb[uid] && paidDb[uid].paid) return res.json({ noAds: true, method: paidDb[uid].method });

  try {
    const memo = 'CRYS-' + uid; // тот же алгоритм, что и payMemo() в клиенте
    const found = await findTonPayment(memo);
    if (found) {
      markPaid(uid, 'ton', TON_MIN_NANO);
      return res.json({ noAds: true, method: 'ton' });
    }
  } catch (e) {
    console.error('TON check failed:', e.message);
    // не роняем запрос — просто говорим "пока не найдено"
  }
  res.json({ noAds: false });
});

/* ═══ POST /api/telegram/webhook — вебхук бота (Stars-платежи) ═══
   Настройка: setWebhook на https://ваш-домен/api/telegram/webhook
   с secret_token = WEBHOOK_SECRET (см. README). */
app.post('/api/telegram/webhook', express.json(), async (req, res) => {
  if (WEBHOOK_SECRET) {
    const got = req.headers['x-telegram-bot-api-secret-token'];
    if (got !== WEBHOOK_SECRET) return res.sendStatus(403);
  }
  const update = req.body;
  try {
    if (update.pre_checkout_query) {
      // Telegram требует ответ в течение 10 секунд, иначе платёж отменяется
      await fetch(`https://api.telegram.org/bot${BOT_TOKEN}/answerPreCheckoutQuery`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ pre_checkout_query_id: update.pre_checkout_query.id, ok: true })
      });
    }
    const msg = update.message;
    if (msg && msg.successful_payment && msg.from) {
      const uid = 'tg' + msg.from.id;
      markPaid(uid, 'stars', msg.successful_payment.total_amount);
    }
  } catch (e) {
    console.error('telegram webhook error:', e.message);
  }
  res.sendStatus(200);
});

/* ═══ POST /api/events — приём событий аналитики от клиента ═══ */
app.post('/api/events', rateLimit(30, 60_000), (req, res) => {
  const body = req.body || {};
  const events = Array.isArray(body.events) ? body.events.slice(0, 200) : [];
  if (!events.length) return res.json({ ok: true, stored: 0 });
  // initData необязателен здесь (клиент шлёт события и для гостей вне Telegram),
  // но если есть — подменяем uid на серверный, чтобы не доверять клиенту
  const auth = checkInitData(body.initData || '');
  const stamped = events.map(e => ({
    ...e,
    uid: auth ? auth.uid : e.uid,
    receivedAt: Date.now()
  }));
  appendEvents(stamped);
  res.json({ ok: true, stored: stamped.length });
});

/* ═══ GET /api/stats — агрегированная статистика для stats.html ═══ */
function readEvents(limit) {
  if (!fs.existsSync(EVENTS_FILE)) return [];
  const raw = fs.readFileSync(EVENTS_FILE, 'utf8').trim();
  if (!raw) return [];
  const lines = raw.split('\n');
  const slice = limit ? lines.slice(-limit) : lines;
  const out = [];
  for (const l of slice) { try { out.push(JSON.parse(l)); } catch (e) {} }
  return out;
}

app.get('/api/stats', (req, res) => {
  if (ADMIN_TOKEN && req.query.token !== ADMIN_TOKEN) return res.status(401).json({ error: 'unauthorized' });

  const events = readEvents(50000); // последние 50k событий — с запасом для дашборда
  const byType = {};
  const dailyActive = {}; // day -> Set(uid)
  const usersSeen = new Set();
  const levelStart = {}, levelWin = {}, levelLose = {};
  let adShown = 0, adCompleted = 0, adFailed = 0;
  let purchases = { ton: 0, usdt: 0, stars: 0, demo_unverified: 0 };
  let lastEventTs = 0;

  for (const e of events) {
    byType[e.name] = (byType[e.name] || 0) + 1;
    if (e.uid) usersSeen.add(e.uid);
    if (e.t) lastEventTs = Math.max(lastEventTs, e.t);
    const day = e.t ? new Date(e.t).toISOString().slice(0, 10) : 'unknown';
    if (!dailyActive[day]) dailyActive[day] = new Set();
    if (e.uid) dailyActive[day].add(e.uid);

    if (e.name === 'level_start' && e.p && e.p.level != null) levelStart[e.p.level] = (levelStart[e.p.level] || 0) + 1;
    if (e.name === 'level_win' && e.p && e.p.level != null) levelWin[e.p.level] = (levelWin[e.p.level] || 0) + 1;
    if (e.name === 'level_lose' && e.p && e.p.level != null) levelLose[e.p.level] = (levelLose[e.p.level] || 0) + 1;
    if (e.name === 'ad_shown') adShown++;
    if (e.name === 'ad_completed') adCompleted++;
    if (e.name === 'ad_failed') adFailed++;
    if (e.name === 'purchase_confirmed' && e.p) {
      const v = e.p.verified === 'server' ? (e.p.mode || 'ton') : 'demo_unverified';
      purchases[v] = (purchases[v] || 0) + 1;
    }
  }

  // самые "залипательные" уровни — где чаще всего проигрывают относительно стартов
  const dropOff = Object.keys(levelStart).map(lv => {
    const starts = levelStart[lv] || 0, wins = levelWin[lv] || 0;
    return { level: +lv, starts, wins, winRate: starts ? +(wins / starts * 100).toFixed(1) : 0 };
  }).sort((a, b) => a.winRate - b.winRate).slice(0, 15);

  const dau = Object.keys(dailyActive).sort().slice(-30).map(day => ({ day, users: dailyActive[day].size }));

  const paidDb = readPaid();
  const paidCount = Object.values(paidDb).filter(p => p.paid).length;

  res.json({
    totalEvents: events.length,
    uniqueUsers: usersSeen.size,
    lastEventAt: lastEventTs,
    byType,
    dau,
    dropOff,
    ads: { shown: adShown, completed: adCompleted, failed: adFailed, completionRate: adShown ? +(adCompleted / adShown * 100).toFixed(1) : 0 },
    purchases,
    paidTotal: paidCount
  });
});

/* ═══ GET /health — лёгкий пинг для анти-сна на Render (см. README) ═══ */
app.get('/health', (req, res) => res.status(200).send('ok'));

/* ═══ статика: index.html, config.js, tonconnect-manifest.json, stats.html ═══ */
app.use(express.static(path.join(__dirname, 'public')));

app.listen(PORT, () => console.log(`Crystallium server on :${PORT}`));
