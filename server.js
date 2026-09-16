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

/* ═══ ПОСЛЕДНИЙ РУБЕЖ ЗАЩИТЫ ═══
   Без этого одна непредвиденная ошибка (как было с кавычками в
   UPSTASH_REDIS_REST_URL) валит процесс целиком — Render его,
   конечно, перезапускает, но несколько секунд/минут сайт лежит
   для ВСЕХ игроков разом. Теперь такая ошибка просто пишется в
   лог, а сервер продолжает работать. Это подстраховка "на всякий
   случай" сверху всех точечных safeRedis() — их наличие не отменяет
   пользы от этого перехватчика. */
process.on('uncaughtException', (err) => {
  console.error('[fatal] uncaughtException (сервер НЕ упал, продолжает работать):', err);
});
process.on('unhandledRejection', (err) => {
  console.error('[fatal] unhandledRejection (сервер НЕ упал, продолжает работать):', err);
});

const app = express();
// JSON-парсер подключается на каждом маршруте отдельно (не глобально) —
// иначе он бы съедал тело запроса ещё до того, как /api/events успеет
// разобрать его сам вручную (см. комментарий у этого маршрута ниже).

/* ── конфигурация из .env (см. .env.example) ── */
const PORT = process.env.PORT || 3000;
const BOT_TOKEN = process.env.BOT_TOKEN || '';           // токен бота из @BotFather
const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET || ''; // секрет для setWebhook (см. README)
const TON_ADDR = process.env.TON_ADDR || '';              // ваш TON-кошелёк (мерчант)
const TON_MIN_NANO = parseInt(process.env.TON_MIN_NANO || '1500000000', 10); // 1.5 TON
const TONAPI_KEY = process.env.TONAPI_KEY || '';          // необязательно, снимает лимиты tonapi.io
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || '';        // пароль для /api/stats и stats.html
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGIN || '*')
  .split(',').map(s => s.trim()).filter(Boolean); // домен(ы) вашего Mini App, через запятую

if (!BOT_TOKEN) console.warn('[warn] BOT_TOKEN не задан — проверка initData и Stars не будут работать');
if (!TON_ADDR) console.warn('[warn] TON_ADDR не задан — проверка TON-платежей не будет работать');
if (!ADMIN_TOKEN) console.warn('[warn] ADMIN_TOKEN не задан — панель статистики останется без пароля! Задайте его.');

/* ── CORS: разрешаем запросы из Mini App ── */
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (ALLOWED_ORIGINS.includes('*')) {
    res.setHeader('Access-Control-Allow-Origin', '*');
  } else if (origin && ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
  }
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

/* ═══ IP и страна ═══
   IP берём из X-Forwarded-For (Render всегда проксирует запросы —
   реальный IP клиента в первом значении этого заголовка, а не в
   req.socket.remoteAddress, это будет внутренний IP прокси Render).
   Страну определяем через бесплатный ip-api.com с кэшем в памяти,
   чтобы не спамить внешний сервис на каждое событие (лимит free-тарифа
   ip-api.com — 45 запросов/минуту, кэш сводит реальные запросы почти
   к нулю после прогрева). */
function getClientIp(req) {
  const fwd = req.headers['x-forwarded-for'];
  if (fwd) return fwd.split(',')[0].trim();
  return req.socket.remoteAddress || '';
}
const countryCache = new Map(); // ip -> {country, countryCode, ts}
const COUNTRY_CACHE_TTL = 7 * 24 * 60 * 60 * 1000; // неделя
async function lookupCountry(ip) {
  if (!ip || ip === '127.0.0.1' || ip.startsWith('::1') || ip.startsWith('10.') || ip.startsWith('192.168.')) return null;
  const cached = countryCache.get(ip);
  if (cached && Date.now() - cached.ts < COUNTRY_CACHE_TTL) return cached;
  try {
    const r = await fetch(`https://ipwho.is/${encodeURIComponent(ip)}?fields=success,country,country_code`);
    if (!r.ok) { console.error('[geo] ipwho.is HTTP', r.status, 'для IP', ip); return null; }
    const data = await r.json();
    if (!data.success) { console.error('[geo] ipwho.is не смог определить страну для', ip, '—', data.message || 'без причины'); return null; }
    const rec = { country: data.country, countryCode: data.country_code, ts: Date.now() };
    countryCache.set(ip, rec);
    return rec;
  } catch (e) {
    console.error('[geo] запрос к ipwho.is упал:', e.message);
    return null;
  }
}

/* ═══ ХРАНИЛИЩЕ ═══
   Если заданы UPSTASH_REDIS_REST_URL / UPSTASH_REDIS_REST_TOKEN —
   данные (оплаты, рейтинг) хранятся в Upstash Redis: это бесплатная
   внешняя база, она живёт отдельно от Render и переживает ЛЮБОЙ
   передеплой (Render стирает только собственный диск сервиса).
   Если переменные не заданы — работаем как раньше, через локальные
   JSON-файлы в ./data (они будут стираться при каждом деплое на
   Render — годится только для локальной разработки/тестов). */
const DATA_DIR = path.join(__dirname, 'data');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
const PAID_FILE = path.join(DATA_DIR, 'paid.json');
const EVENTS_FILE = path.join(DATA_DIR, 'events.jsonl');
const LEADERBOARD_FILE = path.join(DATA_DIR, 'leaderboard.json');

function cleanEnvValue(v) {
  // На случай если при копировании из примера кода (там пишут
  // UPSTASH_REDIS_REST_URL="https://...") кавычки попали в само
  // значение переменной на Render — убираем их и лишние пробелы.
  return String(v || '').trim().replace(/^["']+|["']+$/g, '');
}
const UPSTASH_URL = cleanEnvValue(process.env.UPSTASH_REDIS_REST_URL);
const UPSTASH_TOKEN = cleanEnvValue(process.env.UPSTASH_REDIS_REST_TOKEN);
let USE_REDIS = !!(UPSTASH_URL && UPSTASH_TOKEN);
if (USE_REDIS) {
  try { new URL(UPSTASH_URL); } catch (e) {
    console.error('[error] UPSTASH_REDIS_REST_URL не похож на корректный URL: "' + UPSTASH_URL + '" — Redis отключён, работаем на локальных файлах. Проверьте значение в Render → Environment (без кавычек, полностью вида https://xxx.upstash.io).');
    USE_REDIS = false;
  }
}
if (!USE_REDIS) console.warn('[warn] Upstash Redis не подключён — оплаты, рейтинг и события хранятся в локальном файле и будут стёрты при следующем деплое на Render. См. README, раздел "Хранилище".');

/* Низкоуровневый вызов команды Redis через REST-API Upstash.
   Документация: https://upstash.com/docs/redis/features/restapi
   Любая ошибка здесь ловится вызывающим кодом (см. safeRedis ниже) —
   сама по себе она никогда не должна ронять весь сервер. */
async function redisCmd(...args) {
  const r = await fetch(UPSTASH_URL, {
    method: 'POST',
    headers: { Authorization: `Bearer ${UPSTASH_TOKEN}`, 'Content-Type': 'application/json' },
    body: JSON.stringify(args)
  });
  if (!r.ok) throw new Error('upstash ' + r.status);
  const data = await r.json();
  if (data.error) throw new Error('upstash: ' + data.error);
  return data.result;
}
/* Обёртка: если Redis настроен, но команда всё же упала (сеть, опечатка
   в токене, Upstash недоступен и т.п.) — не роняем сервер, а откатываемся
   на переданное запасное значение/поведение и один раз пишем в лог. */
async function safeRedis(fn, fallback) {
  try { return await fn(); }
  catch (e) {
    console.error('[error] Redis-запрос не удался, используем запасной вариант:', e.message);
    return typeof fallback === 'function' ? fallback() : fallback;
  }
}

function readJsonFile(file) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch (e) { return {}; }
}
function writeJsonFile(file, obj) {
  fs.writeFileSync(file, JSON.stringify(obj, null, 2));
}

async function getPaid(uid) {
  const localFallback = () => { const db = readJsonFile(PAID_FILE); return db[uid] || null; };
  if (USE_REDIS) {
    return safeRedis(async () => {
      const raw = await redisCmd('GET', 'paid:' + uid);
      return raw ? JSON.parse(raw) : null;
    }, localFallback);
  }
  return localFallback();
}
async function markPaid(uid, method, amount) {
  const rec = { paid: true, method, amount, ts: Date.now() };
  const localFallback = () => { const db = readJsonFile(PAID_FILE); db[uid] = rec; writeJsonFile(PAID_FILE, db); };
  if (USE_REDIS) {
    await safeRedis(() => redisCmd('SET', 'paid:' + uid, JSON.stringify(rec)), localFallback);
    return;
  }
  localFallback();
}

const EVENTS_LOG_CAP = 50000; // сколько последних событий храним

async function appendEvents(events) {
  const localFallback = () => {
    const lines = events.map(e => JSON.stringify(e)).join('\n') + '\n';
    fs.appendFileSync(EVENTS_FILE, lines);
  };
  if (USE_REDIS) {
    const lines = events.map(e => JSON.stringify(e));
    if (!lines.length) return;
    await safeRedis(async () => {
      await redisCmd('LPUSH', 'events_log', ...lines);
      await redisCmd('LTRIM', 'events_log', 0, EVENTS_LOG_CAP - 1);
    }, localFallback);
    return;
  }
  localFallback();
}

async function readEventsAsync(limit) {
  if (USE_REDIS) {
    return safeRedis(async () => {
      const raw = await redisCmd('LRANGE', 'events_log', 0, (limit || EVENTS_LOG_CAP) - 1);
      const out = [];
      for (const line of (raw || [])) { try { out.push(JSON.parse(line)); } catch (e) {} }
      return out;
    }, () => readEvents(limit));
  }
  return readEvents(limit);
}

async function getLeaderboardEntry(uid) {
  const localFallback = () => { const db = readJsonFile(LEADERBOARD_FILE); return db[uid] || null; };
  if (USE_REDIS) {
    return safeRedis(async () => {
      const raw = await redisCmd('HGET', 'leaderboard', uid);
      return raw ? JSON.parse(raw) : null;
    }, localFallback);
  }
  return localFallback();
}
async function setLeaderboardEntry(uid, entry) {
  const localFallback = () => { const db = readJsonFile(LEADERBOARD_FILE); db[uid] = entry; writeJsonFile(LEADERBOARD_FILE, db); };
  if (USE_REDIS) {
    await safeRedis(() => redisCmd('HSET', 'leaderboard', uid, JSON.stringify(entry)), localFallback);
    return;
  }
  localFallback();
}
async function getLeaderboardTop(limit) {
  const localFallback = () => {
    const db = readJsonFile(LEADERBOARD_FILE);
    return Object.keys(db).map(uid => ({ id: uid, ...db[uid] })).sort((a, b) => b.best - a.best).slice(0, limit);
  };
  if (USE_REDIS) {
    return safeRedis(async () => {
      const flat = await redisCmd('HGETALL', 'leaderboard'); // [uid1, json1, uid2, json2, ...]
      const rows = [];
      for (let i = 0; i < flat.length; i += 2) {
        try { rows.push({ id: flat[i], ...JSON.parse(flat[i + 1]) }); } catch (e) {}
      }
      return rows.sort((a, b) => b.best - a.best).slice(0, limit);
    }, localFallback);
  }
  return localFallback();
}

/* ═══ МОДЕРАЦИЯ ИГРОКОВ ═══
   Запись на игрока: { banned, banReason, blockedFeatures: [...],
   notes, updatedAt }. Доступные значения blockedFeatures:
   'leaderboard' (нельзя отправлять результат в рейтинг),
   'payments' (нельзя проверять/подтверждать оплату «без рекламы»),
   'ads_reward' (заблокирована выдача наград за рекламу — решается на
   клиенте по статусу, сервер только хранит флаг). */
const PLAYERS_FILE = path.join(DATA_DIR, 'players.json');
const EMPTY_PLAYER = { banned: false, banReason: '', blockedFeatures: [], notes: '' };

async function getPlayerMod(uid) {
  const localFallback = () => { const db = readJsonFile(PLAYERS_FILE); return db[uid] ? { ...EMPTY_PLAYER, ...db[uid] } : { ...EMPTY_PLAYER }; };
  if (USE_REDIS) {
    return safeRedis(async () => {
      const raw = await redisCmd('HGET', 'players', uid);
      return raw ? { ...EMPTY_PLAYER, ...JSON.parse(raw) } : { ...EMPTY_PLAYER };
    }, localFallback);
  }
  return localFallback();
}
async function setPlayerMod(uid, patch) {
  const current = await getPlayerMod(uid);
  const rec = { ...current, ...patch, updatedAt: Date.now() };
  const localFallback = () => { const db = readJsonFile(PLAYERS_FILE); db[uid] = rec; writeJsonFile(PLAYERS_FILE, db); };
  if (USE_REDIS) {
    await safeRedis(() => redisCmd('HSET', 'players', uid, JSON.stringify(rec)), localFallback);
  } else {
    localFallback();
  }
  return rec;
}
async function listModeratedPlayers() {
  const localFallback = () => {
    const db = readJsonFile(PLAYERS_FILE);
    return Object.keys(db).map(uid => ({ uid, ...db[uid] }));
  };
  let rows;
  if (USE_REDIS) {
    rows = await safeRedis(async () => {
      const flat = await redisCmd('HGETALL', 'players');
      const out = [];
      for (let i = 0; i < flat.length; i += 2) {
        try { out.push({ uid: flat[i], ...JSON.parse(flat[i + 1]) }); } catch (e) {}
      }
      return out;
    }, localFallback);
  } else {
    rows = localFallback();
  }
  return rows.filter(r => r.banned || (r.blockedFeatures && r.blockedFeatures.length))
    .sort((a, b) => (b.updatedAt || 0) - (a.updatedAt || 0));
}

async function getPaidCount() {
  const localFallback = () => { const db = readJsonFile(PAID_FILE); return Object.values(db).filter(p => p.paid).length; };
  if (USE_REDIS) {
    return safeRedis(async () => {
      const keys = await redisCmd('KEYS', 'paid:*');
      return Array.isArray(keys) ? keys.length : 0;
    }, localFallback);
  }
  return localFallback();
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

/* ═══ Проверка оплаты (вызывается кнопкой «Я оплатил») ═══
   Доступна под двумя путями для совместимости с разными версиями
   клиента: GET /api/status и POST /api/payment/check делают одно
   и то же. */
async function handlePaymentCheck(req, res) {
  const uid = req.auth.uid;
  const mod = await getPlayerMod(uid);
  if (mod.banned) return res.status(403).json({ error: 'banned', noAds: false });
  if ((mod.blockedFeatures || []).includes('payments')) return res.status(403).json({ error: 'feature_blocked', noAds: false });

  const paidRec = await getPaid(uid);
  if (paidRec && paidRec.paid) return res.json({ noAds: true, method: paidRec.method });

  try {
    const memo = 'NOADS-' + uid; // тот же алгоритм, что и payMemo() в клиенте (index.html)
    const found = await findTonPayment(memo);
    if (found) {
      await markPaid(uid, 'ton', TON_MIN_NANO);
      return res.json({ noAds: true, method: 'ton' });
    }
  } catch (e) {
    console.error('TON check failed:', e.message);
    // не роняем запрос — просто говорим "пока не найдено"
  }
  res.json({ noAds: false });
}
app.get('/api/status', rateLimit(20, 60_000), requireUser, handlePaymentCheck);
app.post('/api/payment/check', rateLimit(20, 60_000), requireUser, handlePaymentCheck);

/* ═══ GET /api/player/status — клиент проверяет при запуске, не забанен ли он ═══ */
app.get('/api/player/status', rateLimit(20, 60_000), requireUser, async (req, res) => {
  const mod = await getPlayerMod(req.auth.uid);
  res.json({ banned: mod.banned, banReason: mod.banReason || '', blockedFeatures: mod.blockedFeatures || [] });
});


/* ═══ Рейтинг лестницы (бесконечный режим) ═══ */
app.post('/api/leaderboard/submit', express.json({ limit: '256kb' }), rateLimit(20, 60_000), requireUser, async (req, res) => {
  const uid = req.auth.uid;
  const mod = await getPlayerMod(uid);
  if (mod.banned) return res.status(403).json({ error: 'banned' });
  if ((mod.blockedFeatures || []).includes('leaderboard')) return res.status(403).json({ error: 'feature_blocked' });

  const name = (req.auth.user && req.auth.user.first_name) || 'Игрок';
  const waves = parseInt((req.body && req.body.waves) || 0, 10);
  if (!Number.isFinite(waves) || waves <= 0) return res.status(400).json({ error: 'bad_waves' });

  const prev = await getLeaderboardEntry(uid);
  let best = prev ? prev.best : 0;
  if (!prev || waves > prev.best) {
    best = waves;
    await setLeaderboardEntry(uid, { name, best, ts: Date.now() });
  } else if (prev.name !== name) {
    await setLeaderboardEntry(uid, { ...prev, name }); // имя сменилось в Telegram — обновим
  }
  res.json({ ok: true, best });
});

app.get('/api/leaderboard', rateLimit(30, 60_000), async (req, res) => {
  try {
    const top = await getLeaderboardTop(50);
    res.json({ top });
  } catch (e) {
    console.error('leaderboard fetch failed:', e.message);
    res.status(500).json({ error: 'leaderboard_unavailable' });
  }
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
      await markPaid(uid, 'stars', msg.successful_payment.total_amount);
    }
  } catch (e) {
    console.error('telegram webhook error:', e.message);
  }
  res.sendStatus(200);
});

/* ═══ POST /api/events — приём событий аналитики от клиента ═══
   Читаем тело запроса вручную (express.text с type:()=>true), а не
   через express.json() — некоторые браузеры/WebView при отправке
   через navigator.sendBeacon() присылают Content-Type: text/plain
   вместо application/json, и стандартный JSON-парсер Express такое
   тело молча игнорирует (req.body остаётся пустым, событие теряется
   без единой ошибки). Здесь разбираем JSON сами, независимо от
   заголовка. */
app.post('/api/events', rateLimit(30, 60_000), express.text({ type: () => true, limit: '256kb' }), async (req, res) => {
  let body = {};
  try { body = typeof req.body === 'string' ? JSON.parse(req.body) : (req.body || {}); } catch (e) {
    console.error('events: bad JSON body:', e.message);
    return res.status(400).json({ error: 'bad_json' });
  }
  const events = Array.isArray(body.events) ? body.events.slice(0, 200) : [];
  if (!events.length) return res.json({ ok: true, stored: 0 });
  // initData необязателен здесь (клиент шлёт события и для гостей вне Telegram),
  // но если есть — подменяем uid на серверный, чтобы не доверять клиенту
  const auth = checkInitData(body.initData || '');
  const ip = getClientIp(req);
  const geo = await lookupCountry(ip).catch(() => null);
  const stamped = events.map(e => ({
    ...e,
    uid: auth ? auth.uid : e.uid,
    uname: auth && auth.user ? (auth.user.username ? '@' + auth.user.username : auth.user.first_name) : e.uname,
    ip,
    country: geo ? geo.country : undefined,
    countryCode: geo ? geo.countryCode : undefined,
    receivedAt: Date.now()
  }));
  await appendEvents(stamped);
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

/* ═══ Админ: модерация игроков ═══ */

// список всех, у кого есть бан или блокировка функций
app.get('/api/admin/players', async (req, res) => {
  if (!ADMIN_TOKEN || req.query.token !== ADMIN_TOKEN) return res.status(401).json({ error: 'unauthorized' });
  try {
    const rows = await listModeratedPlayers();
    res.json({ players: rows });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// поиск игрока по Telegram ID или имени среди тех, кто встречался в событиях
app.get('/api/admin/players/search', async (req, res) => {
  if (!ADMIN_TOKEN || req.query.token !== ADMIN_TOKEN) return res.status(401).json({ error: 'unauthorized' });
  const q = String(req.query.q || '').trim().toLowerCase();
  const events = await readEventsAsync(50000);
  const seen = new Map(); // uid -> {uid, name, lastSeen}
  for (const e of events) {
    if (!e.uid) continue;
    const uidMatch = !q || e.uid.toLowerCase().includes(q);
    const displayName = e.uname || '';
    const nameHit = !q || displayName.toLowerCase().includes(q);
    if (q && !uidMatch && !nameHit) continue;
    const cur = seen.get(e.uid) || { uid: e.uid, name: displayName, lastSeen: 0 };
    if (displayName) cur.name = displayName;
    if (e.t) cur.lastSeen = Math.max(cur.lastSeen, e.t);
    seen.set(e.uid, cur);
  }
  const results = Array.from(seen.values()).sort((a, b) => b.lastSeen - a.lastSeen).slice(0, 30);
  res.json({ results });
});

// полная карточка игрока: модерация + последние известные данные из событий
app.get('/api/admin/player/:uid', async (req, res) => {
  if (!ADMIN_TOKEN || req.query.token !== ADMIN_TOKEN) return res.status(401).json({ error: 'unauthorized' });
  const uid = req.params.uid;
  try {
    const mod = await getPlayerMod(uid);
    const events = (await readEventsAsync(50000)).filter(e => e.uid === uid);
    let name = uid, country = '', countryCode = '', platform = '', lastSeen = 0;
    let lastCoins = null, lastLevel = null, lastEndlessWave = null;
    for (const e of events) {
      if (e.t) lastSeen = Math.max(lastSeen, e.t);
      if (e.uname) name = e.uname;
      if (e.country) { country = e.country; countryCode = e.countryCode || ''; }
      if (e.name === 'session_start' && e.p) {
        if (e.p.platform) platform = e.p.platform;
        if (e.p.coins != null) lastCoins = e.p.coins;
        if (e.p.unlocked != null) lastLevel = e.p.unlocked;
      }
      if (e.name === 'endless_wave_win' && e.p && e.p.wave != null) {
        lastEndlessWave = Math.max(lastEndlessWave || 0, e.p.wave);
      }
    }
    const paidRec = await getPaid(uid);
    const lbRec = await getLeaderboardEntry(uid);
    res.json({
      uid, name, country, countryCode, platform, lastSeen,
      lastCoins, lastLevel, lastEndlessWave,
      paid: !!(paidRec && paidRec.paid), paidMethod: paidRec ? paidRec.method : null,
      leaderboardBest: lbRec ? lbRec.best : 0,
      eventsCount: events.length,
      moderation: mod
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// изменить модерацию игрока: бан/разбан, блокировка функций, заметки
// тело: {"banned":true,"banReason":"...","blockedFeatures":["leaderboard","payments"],"notes":"..."}
app.post('/api/admin/player/:uid', express.json({ limit: '64kb' }), async (req, res) => {
  if (!ADMIN_TOKEN || req.query.token !== ADMIN_TOKEN) return res.status(401).json({ error: 'unauthorized' });
  const uid = req.params.uid;
  const body = req.body || {};
  const patch = {};
  if (typeof body.banned === 'boolean') patch.banned = body.banned;
  if (typeof body.banReason === 'string') patch.banReason = body.banReason.slice(0, 300);
  if (Array.isArray(body.blockedFeatures)) {
    const allowed = ['leaderboard', 'payments', 'ads_reward', 'endless'];
    patch.blockedFeatures = body.blockedFeatures.filter(f => allowed.includes(f));
  }
  if (typeof body.notes === 'string') patch.notes = body.notes.slice(0, 1000);
  try {
    const rec = await setPlayerMod(uid, patch);
    res.json({ ok: true, moderation: rec });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

/* ═══ Админ: сброс тестовых данных ═══
   POST /api/admin/reset?token=ADMIN_TOKEN
   Тело (необязательно): {"scope":"payments"}, {"scope":"leaderboard"}
   или {"scope":"events"} (полностью чистит лог событий — не разделяется
   по игроку) или {"scope":"all"} (всё вместе, по умолчанию). Можно
   ограничить payments/leaderboard одним игроком: {"uid":"tg12345678"}. */
app.post('/api/admin/reset', express.json(), async (req, res) => {
  if (!ADMIN_TOKEN || req.query.token !== ADMIN_TOKEN) return res.status(401).json({ error: 'unauthorized' });
  const scope = (req.body && req.body.scope) || 'all';
  const uid = req.body && req.body.uid;
  try {
    if (scope === 'payments' || scope === 'all') {
      if (uid) {
        if (USE_REDIS) await redisCmd('DEL', 'paid:' + uid);
        else { const db = readJsonFile(PAID_FILE); delete db[uid]; writeJsonFile(PAID_FILE, db); }
      } else if (USE_REDIS) {
        const keys = await redisCmd('KEYS', 'paid:*');
        for (const k of (keys || [])) await redisCmd('DEL', k);
      } else {
        writeJsonFile(PAID_FILE, {});
      }
    }
    if (scope === 'leaderboard' || scope === 'all') {
      if (uid) {
        if (USE_REDIS) await redisCmd('HDEL', 'leaderboard', uid);
        else { const db = readJsonFile(LEADERBOARD_FILE); delete db[uid]; writeJsonFile(LEADERBOARD_FILE, db); }
      } else if (USE_REDIS) {
        await redisCmd('DEL', 'leaderboard');
      } else {
        writeJsonFile(LEADERBOARD_FILE, {});
      }
    }
    if (scope === 'events' || scope === 'all') {
      // лог событий общий, не по игрокам — uid здесь не учитывается
      if (USE_REDIS) await redisCmd('DEL', 'events_log');
      else fs.writeFileSync(EVENTS_FILE, '');
    }
    res.json({ ok: true, scope, uid: uid || 'all' });
  } catch (e) {
    console.error('admin reset failed:', e.message);
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/stats', async (req, res) => {
  if (ADMIN_TOKEN && req.query.token !== ADMIN_TOKEN) return res.status(401).json({ error: 'unauthorized' });

  const events = await readEventsAsync(50000); // последние 50k событий — с запасом для дашборда
  const byType = {};
  const dailyActive = {}; // day -> Set(uid)
  const usersSeen = new Set();
  const levelStart = {}, levelWin = {}, levelLose = {};
  let adShown = 0, adCompleted = 0, adFailed = 0;
  let purchases = { ton: 0, usdt: 0, stars: 0, demo_unverified: 0 };
  let lastEventTs = 0;

  // страны и IP
  const countryByUser = new Map();      // uid -> {country, countryCode}
  const ipToUids = new Map();           // ip -> Set(uid)
  const ipCountry = new Map();          // ip -> {country, countryCode}
  const ipEvents = new Map();           // ip -> count
  const nameByUid = new Map();          // uid -> отображаемое имя

  // бесконечный режим
  let endlessSessions = 0, endlessWavesTotal = 0, endlessSessionsFinished = 0;
  const endlessWaveHist = {}; // wave -> сколько раз доходили до этой волны
  const levelWinByUid = new Map(); // uid -> кол-во пройденных уровней кампании
  const maxLevelByUid = new Map(); // uid -> максимальный пройденный уровень (индекс)

  // устройства/платформы, сессии, удержание
  const platformCounts = {};
  const sidTimes = new Map();     // sid -> {min, max}
  const daysByUser = new Map();   // uid -> Set(день)

  for (const e of events) {
    byType[e.name] = (byType[e.name] || 0) + 1;
    if (e.uid) usersSeen.add(e.uid);
    if (e.t) lastEventTs = Math.max(lastEventTs, e.t);
    const day = e.t ? new Date(e.t).toISOString().slice(0, 10) : 'unknown';
    if (!dailyActive[day]) dailyActive[day] = new Set();
    if (e.uid) dailyActive[day].add(e.uid);
    if (e.uid && e.t) {
      if (!daysByUser.has(e.uid)) daysByUser.set(e.uid, new Set());
      daysByUser.get(e.uid).add(day);
    }
    if (e.sid && e.t) {
      if (!sidTimes.has(e.sid)) sidTimes.set(e.sid, { min: e.t, max: e.t });
      const rec = sidTimes.get(e.sid);
      rec.min = Math.min(rec.min, e.t); rec.max = Math.max(rec.max, e.t);
    }
    if (e.name === 'session_start' && e.p && e.p.platform) {
      platformCounts[e.p.platform] = (platformCounts[e.p.platform] || 0) + 1;
    }

    if (e.uid && e.uname) nameByUid.set(e.uid, e.uname || nameByUid.get(e.uid) || e.uid);
    if (e.uid && e.country && !countryByUser.has(e.uid)) countryByUser.set(e.uid, { country: e.country, countryCode: e.countryCode });
    if (e.ip) {
      if (!ipToUids.has(e.ip)) ipToUids.set(e.ip, new Set());
      if (e.uid) ipToUids.get(e.ip).add(e.uid);
      if (e.country && !ipCountry.has(e.ip)) ipCountry.set(e.ip, { country: e.country, countryCode: e.countryCode });
      ipEvents.set(e.ip, (ipEvents.get(e.ip) || 0) + 1);
    }

    if (e.name === 'level_start' && e.p && e.p.level != null) levelStart[e.p.level] = (levelStart[e.p.level] || 0) + 1;
    if (e.name === 'level_win' && e.p && e.p.level != null) {
      levelWin[e.p.level] = (levelWin[e.p.level] || 0) + 1;
      if (e.uid) {
        levelWinByUid.set(e.uid, (levelWinByUid.get(e.uid) || 0) + 1);
        const lv = e.p.level;
        if (!maxLevelByUid.has(e.uid) || lv > maxLevelByUid.get(e.uid)) maxLevelByUid.set(e.uid, lv);
      }
    }
    if (e.name === 'level_lose' && e.p && e.p.level != null) levelLose[e.p.level] = (levelLose[e.p.level] || 0) + 1;
    if (e.name === 'ad_shown') adShown++;
    if (e.name === 'ad_completed') adCompleted++;
    if (e.name === 'ad_failed') adFailed++;
    if (e.name === 'purchase_confirmed' && e.p) {
      const v = e.p.verified === 'server' ? (e.p.mode || 'ton') : 'demo_unverified';
      purchases[v] = (purchases[v] || 0) + 1;
    }

    // бесконечный режим
    if (e.name === 'endless_wave_start' && e.p) {
      if (e.p.wave === 1) endlessSessions++;
    }
    if ((e.name === 'endless_wave_win' || e.name === 'endless_wave_lose') && e.p && e.p.wave != null) {
      endlessWavesTotal++;
      endlessWaveHist[e.p.wave] = (endlessWaveHist[e.p.wave] || 0) + 1;
    }
  }

  // самые "залипательные" уровни — где чаще всего проигрывают относительно стартов
  const dropOff = Object.keys(levelStart).map(lv => {
    const starts = levelStart[lv] || 0, wins = levelWin[lv] || 0;
    return { level: +lv, starts, wins, winRate: starts ? +(wins / starts * 100).toFixed(1) : 0 };
  }).sort((a, b) => a.winRate - b.winRate).slice(0, 15);

  const dau = Object.keys(dailyActive).sort().slice(-30).map(day => ({ day, users: dailyActive[day].size }));

  const paidCount = await getPaidCount();

  // страны — по уникальным игрокам
  const countryCounts = {};
  for (const { country, countryCode } of countryByUser.values()) {
    const key = country || 'Неизвестно';
    if (!countryCounts[key]) countryCounts[key] = { country: key, countryCode: countryCode || '', users: 0 };
    countryCounts[key].users++;
  }
  const byCountry = Object.values(countryCounts).sort((a, b) => b.users - a.users).slice(0, 30);

  // подозрительные IP — несколько разных Telegram-аккаунтов с одного адреса (возможная ботоферма)
  const suspiciousIPs = [];
  for (const [ip, uids] of ipToUids.entries()) {
    if (uids.size >= 3) {
      suspiciousIPs.push({
        ip,
        country: (ipCountry.get(ip) || {}).country || 'Неизвестно',
        uniqueAccounts: uids.size,
        accounts: Array.from(uids).slice(0, 20),
        events: ipEvents.get(ip) || 0
      });
    }
  }
  suspiciousIPs.sort((a, b) => b.uniqueAccounts - a.uniqueAccounts);

  // удержание (retention): D1/D7 — вернулся ли игрок через 1 и через 7 дней
  // после первого визита. Считаем только по тем, у кого с первого визита
  // прошло достаточно времени (иначе рано делать вывод).
  function addDaysStr(dayStr, n) {
    const d = new Date(dayStr + 'T00:00:00Z');
    d.setUTCDate(d.getUTCDate() + n);
    return d.toISOString().slice(0, 10);
  }
  const todayStr = new Date().toISOString().slice(0, 10);
  const firstDayByUid = new Map();
  let d1Eligible = 0, d1Retained = 0, d7Eligible = 0, d7Retained = 0;
  for (const [uid, days] of daysByUser.entries()) {
    const sorted = Array.from(days).sort();
    const firstDay = sorted[0];
    firstDayByUid.set(uid, firstDay);
    const d1 = addDaysStr(firstDay, 1), d7 = addDaysStr(firstDay, 7);
    if (d1 <= todayStr) { d1Eligible++; if (days.has(d1)) d1Retained++; }
    if (d7 <= todayStr) { d7Eligible++; if (days.has(d7)) d7Retained++; }
  }
  const retention = {
    d1: d1Eligible ? +(d1Retained / d1Eligible * 100).toFixed(1) : null,
    d1Sample: d1Eligible,
    d7: d7Eligible ? +(d7Retained / d7Eligible * 100).toFixed(1) : null,
    d7Sample: d7Eligible
  };

  // новые/вернувшиеся сегодня
  let newToday = 0, returningToday = 0;
  for (const uid of (dailyActive[todayStr] || new Set())) {
    if (firstDayByUid.get(uid) === todayStr) newToday++; else returningToday++;
  }

  // устройства/платформы (по данным session_start)
  const byPlatform = Object.keys(platformCounts).map(p => ({ platform: p, count: platformCounts[p] }))
    .sort((a, b) => b.count - a.count);

  // средняя длительность сессии (по разбросу времени событий с одним sid)
  let totalSessionMs = 0, sessionCount = 0;
  for (const { min, max } of sidTimes.values()) { sessionCount++; totalSessionMs += (max - min); }
  const avgSessionMinutes = sessionCount ? +(totalSessionMs / sessionCount / 60000).toFixed(1) : 0;

  // бесконечный режим: распределение по волнам + средняя/максимальная волна
  const waveNums = Object.keys(endlessWaveHist).map(Number);
  const maxWaveReached = waveNums.length ? Math.max(...waveNums) : 0;
  const endlessWaveDistribution = Object.keys(endlessWaveHist).map(w => ({ wave: +w, players: endlessWaveHist[w] }))
    .sort((a, b) => a.wave - b.wave).slice(0, 40);

  // топ игроков по бесконечному режиму (тот же источник, что и /api/leaderboard)
  let topEndless = [];
  try { topEndless = await getLeaderboardTop(10); } catch (e) {}

  // топ игроков по числу пройденных уровней кампании
  const topByLevels = Array.from(levelWinByUid.entries())
    .map(([uid, count]) => ({ uid, name: nameByUid.get(uid) || uid, levelsCompleted: count, maxLevel: (maxLevelByUid.get(uid) || 0) + 1 }))
    .sort((a, b) => b.levelsCompleted - a.levelsCompleted)
    .slice(0, 10);

  // воронка прохождения кампании — сколько уникальных игроков дошли хотя бы до уровня N
  const milestones = [1, 5, 10, 25, 50, 100, 150, 200, 250, 300];
  const campaignFunnel = milestones.map(m => {
    let reached = 0;
    for (const maxLv of maxLevelByUid.values()) if (maxLv + 1 >= m) reached++;
    return { level: m, players: reached };
  });

  // примерная выручка (по подтверждённым серверным платежам, без учёта рекламы)
  const revenueEstimate = {
    tonAmount: purchases.ton * (TON_MIN_NANO / 1e9),
    starsAmount: purchases.stars * 100, // цена по умолчанию, см. config.js STARS_PRICE
    note: 'Приблизительно, по числу подтверждённых оплат — без учёта дохода от рекламы'
  };

  res.json({
    totalEvents: events.length,
    uniqueUsers: usersSeen.size,
    lastEventAt: lastEventTs,
    byType,
    dau,
    dropOff,
    ads: { shown: adShown, completed: adCompleted, failed: adFailed, completionRate: adShown ? +(adCompleted / adShown * 100).toFixed(1) : 0 },
    purchases,
    paidTotal: paidCount,
    revenueEstimate,
    byCountry,
    suspiciousIPs: suspiciousIPs.slice(0, 20),
    retention,
    newVsReturningToday: { newToday, returningToday },
    byPlatform,
    avgSessionMinutes,
    endless: {
      sessions: endlessSessions,
      wavesPlayedTotal: endlessWavesTotal,
      avgWavesPerSession: endlessSessions ? +(endlessWavesTotal / endlessSessions).toFixed(1) : 0,
      maxWaveReached,
      distribution: endlessWaveDistribution
    },
    topPlayers: {
      byEndlessWaves: topEndless,
      byLevelsCompleted: topByLevels
    },
    campaignFunnel
  });
});

/* ═══ GET /health — лёгкий пинг для анти-сна на Render (см. README) ═══ */
app.get('/health', (req, res) => res.status(200).send('ok'));

/* ═══ статика: stats.html, admin.html, tonconnect-manifest.json, config.js ═══
   Отдаём по отдельности, а не через express.static на весь каталог —
   так безопаснее (не отдаст случайно server.js или .env, если кто-то
   уберёт папку public и положит всё в корень репозитория, как у вас).
   Каждый файл ищем сначала в public/, если там нет — прямо в корне
   рядом с server.js. Работает при любой раскладке файлов. */
function serveStatic(urlPath, filename) {
  app.get(urlPath, (req, res) => {
    const inPublic = path.join(__dirname, 'public', filename);
    const inRoot = path.join(__dirname, filename);
    const found = fs.existsSync(inPublic) ? inPublic : (fs.existsSync(inRoot) ? inRoot : null);
    if (!found) return res.status(404).send('Файл ' + filename + ' не найден ни в /public, ни в корне репозитория');
    res.sendFile(found);
  });
}
serveStatic('/stats.html', 'stats.html');
serveStatic('/admin.html', 'admin.html');
serveStatic('/tonconnect-manifest.json', 'tonconnect-manifest.json');
serveStatic('/config.js', 'config.js');
serveStatic('/index.html', 'index.html');
// index.html так же открывается и по корневому адресу (/)
app.get('/', (req, res) => {
  const inPublic = path.join(__dirname, 'public', 'index.html');
  const inRoot = path.join(__dirname, 'index.html');
  const found = fs.existsSync(inPublic) ? inPublic : (fs.existsSync(inRoot) ? inRoot : null);
  if (found) res.sendFile(found); else res.status(404).send('index.html не найден');
});

app.listen(PORT, () => console.log(`Crystallium server on :${PORT}`));
