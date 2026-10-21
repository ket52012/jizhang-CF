// 生活记账本 — Cloudflare Worker + D1
// 账号 = 稳定 ID；密码只存哈希（登录校验）+ AES-GCM 加密副本（查看密码用，密钥存 D1 settings）。
// 改密码不丢数据；旧密码进历史表，是找回密码的唯一凭证。改密后机器人推送新密码。
// 每个 IP 最多创建 3 个账本（防爆表）。

async function sha256hex(s) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

// 北京时间工具（UTC+8，按 UTC 字段读）
function bj(ts) { return new Date(ts + 8 * 3600 * 1000); }
function p2(n) { return String(n).padStart(2, '0'); }
function monthKey(ts) { const d = bj(ts); return d.getUTCFullYear() + '-' + p2(d.getUTCMonth() + 1); }
function dayKey(ts) { const d = bj(ts); return monthKey(ts) + '-' + p2(d.getUTCDate()); }
function timeStr(ts) { const d = bj(ts); return p2(d.getUTCHours()) + ':' + p2(d.getUTCMinutes()); }
function fmtC(c) { return '¥' + (c / 100).toFixed(2); }

// ---- 密码加密（AES-GCM，密钥存 D1 settings 表，部署更新不影响） ----
let _encKey = null;
async function getEncKey(env) {
  if (_encKey) return _encKey;
  await env.DB.prepare('CREATE TABLE IF NOT EXISTS settings (k TEXT PRIMARY KEY, v TEXT)').run();
  let row = await env.DB.prepare("SELECT v FROM settings WHERE k='enc_key'").first();
  if (!row) {
    const hex = [...crypto.getRandomValues(new Uint8Array(32))].map((b) => b.toString(16).padStart(2, '0')).join('');
    await env.DB.prepare("INSERT OR IGNORE INTO settings (k, v) VALUES ('enc_key', ?)").bind(hex).run();
    row = await env.DB.prepare("SELECT v FROM settings WHERE k='enc_key'").first();
  }
  const raw = await crypto.subtle.digest('SHA-256', new TextEncoder().encode('jz-enc:' + row.v));
  _encKey = await crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt']);
  return _encKey;
}
function b64encode(bytes) { let s = ''; for (const b of bytes) s += String.fromCharCode(b); return btoa(s); }
function b64decode(s) { const bin = atob(s); const out = new Uint8Array(bin.length); for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i); return out; }
async function encText(env, text) {
  const k = await getEncKey(env);
  if (!k) return '';
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, k, new TextEncoder().encode(text));
  const buf = new Uint8Array(12 + ct.byteLength);
  buf.set(iv); buf.set(new Uint8Array(ct), 12);
  return b64encode(buf);
}
async function decText(env, s) {
  const k = await getEncKey(env);
  if (!k || !s) return '';
  try {
    const buf = b64decode(s);
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: buf.slice(0, 12) }, k, buf.slice(12));
    return new TextDecoder().decode(pt);
  } catch { return ''; }
}

// IP 归一化：IPv6 按 /64 网段算，IPv4 用全址
function ipKey(ip) {
  if (!ip) return '';
  if (!ip.includes(':')) return ip;
  const [head, tail] = ip.split('::');
  const h = head ? head.split(':') : [];
  const t = tail ? tail.split(':') : [];
  const full = [...h, ...Array(8 - h.length - t.length).fill('0'), ...t];
  return full.slice(0, 4).join(':') + '::/64';
}

async function ensureSchema(env) {
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    account TEXT NOT NULL, type TEXT NOT NULL, amount INTEGER NOT NULL,
    note TEXT DEFAULT '', ts INTEGER NOT NULL, month TEXT NOT NULL, day TEXT NOT NULL
  )`).run();
  await env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_acc_month ON entries(account, month)').run();
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS botcfg (
    account TEXT PRIMARY KEY, token TEXT NOT NULL, tg_id TEXT NOT NULL, wh TEXT NOT NULL
  )`).run();
  await env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_botcfg_wh ON botcfg(wh)').run();
  // accounts 升级为稳定 ID 版（旧版 account 列即密码哈希，迁移时 id=pw_hash=旧值，数据无缝衔接）
  const cols = await env.DB.prepare('PRAGMA table_info(accounts)').all().catch(() => null);
  const names = cols && cols.results ? cols.results.map((r) => r.name) : [];
  if (!names.includes('id')) {
    await env.DB.prepare(`CREATE TABLE IF NOT EXISTS accounts_v2 (
      id TEXT PRIMARY KEY, pw_hash TEXT UNIQUE, pw_enc TEXT DEFAULT '', ip TEXT DEFAULT '', ts INTEGER NOT NULL
    )`).run();
    if (names.includes('account')) {
      await env.DB.prepare('INSERT OR IGNORE INTO accounts_v2 (id, pw_hash, ip, ts) SELECT account, account, ip, ts FROM accounts').run();
    }
    await env.DB.prepare('DROP TABLE IF EXISTS accounts').run();
    await env.DB.prepare('ALTER TABLE accounts_v2 RENAME TO accounts').run();
  }
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS pw_history (
    account TEXT NOT NULL, pw_hash TEXT NOT NULL, ts INTEGER NOT NULL
  )`).run();
  await env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_hist_hash ON pw_history(pw_hash)').run();
}

function jsonRes(obj, status) {
  return new Response(JSON.stringify(obj), { status: status || 200, headers: { 'Content-Type': 'application/json' } });
}

function validCents(body) {
  const cents = Math.round(Number(body.amount) * 100);
  return isFinite(cents) && cents > 0 && cents <= 10000000000 ? cents : 0;
}

async function insertEntry(env, account, type, cents, note) {
  const now = Date.now();
  await env.DB.prepare(
    'INSERT INTO entries (account, type, amount, note, ts, month, day) VALUES (?, ?, ?, ?, ?, ?, ?)'
  ).bind(account, type, cents, note, now, monthKey(now), dayKey(now)).run();
}

async function sumsFor(env, account) {
  const now = Date.now();
  const curMonth = monthKey(now), curDay = dayKey(now);
  const agg = async (sql, args) => {
    const r = await env.DB.prepare(sql).bind(...args).all();
    const o = { in: 0, out: 0 };
    for (const row of r.results || []) o[row.type] = row.s;
    return o;
  };
  const today = await agg('SELECT type, COALESCE(SUM(amount),0) AS s FROM entries WHERE account=? AND day=? GROUP BY type', [account, curDay]);
  const month = await agg('SELECT type, COALESCE(SUM(amount),0) AS s FROM entries WHERE account=? AND month=? GROUP BY type', [account, curMonth]);
  const all = await agg('SELECT type, COALESCE(SUM(amount),0) AS s FROM entries WHERE account=? GROUP BY type', [account]);
  const monthsR = await env.DB.prepare(
    `SELECT month, type, COALESCE(SUM(amount),0) AS s, COUNT(*) AS c FROM entries
     WHERE account=? GROUP BY month, type ORDER BY month DESC`
  ).bind(account).all();
  const mmap = {};
  for (const row of monthsR.results || []) {
    if (!mmap[row.month]) mmap[row.month] = { month: row.month, in: 0, out: 0, count: 0 };
    mmap[row.month][row.type] = row.s;
    mmap[row.month].count += row.c;
  }
  return { today, month, all, months: Object.values(mmap), curMonth, curDay };
}

// 改密后给绑定的机器人发新密码
async function pushPwToBot(env, account, newPw) {
  const cfg = await env.DB.prepare('SELECT token, tg_id FROM botcfg WHERE account=?').bind(account).first();
  if (!cfg) return false;
  const r = await tgCall(cfg.token, 'sendMessage', {
    chat_id: cfg.tg_id,
    text: `🔐 你的记账本密码已修改\n新密码：${newPw}\n请妥善保管（这条消息看完可删）`,
  });
  return !!(r && r.ok);
}

// 执行改密：旧哈希进历史，换新哈希 + 新加密副本
async function rotatePassword(env, row, newPw) {
  const newHash = await sha256hex('jz:' + newPw);
  await env.DB.prepare('INSERT INTO pw_history (account, pw_hash, ts) VALUES (?, ?, ?)').bind(row.id, row.pw_hash, Date.now()).run();
  await env.DB.prepare('UPDATE accounts SET pw_hash=?, pw_enc=? WHERE id=?')
    .bind(newHash, await encText(env, newPw), row.id).run();
  return newHash;
}

async function handleApi(env, req, path, body) {
  const now = Date.now();

  // ---- 查看当前密码：凭证 = 任意一个用过的密码（当前的或历史的），只查看不修改 ----
  if (path === '/api/view-pw') {
    const oldPw = String(body.oldPw || '');
    if (!oldPw) return jsonRes({ ok: false, error: '参数不对' }, 400);
    const oldHash = await sha256hex('jz:' + oldPw);
    let row = await env.DB.prepare('SELECT id, pw_enc FROM accounts WHERE pw_hash=?').bind(oldHash).first();
    if (!row) {
      const h = await env.DB.prepare('SELECT account FROM pw_history WHERE pw_hash=? LIMIT 1').bind(oldHash).first();
      if (h) row = await env.DB.prepare('SELECT id, pw_enc FROM accounts WHERE id=?').bind(h.account).first();
    }
    if (!row) return jsonRes({ ok: false, error: '这个密码没有被使用过' }, 404);
    const cur = await decText(env, row.pw_enc);
    if (!cur) return jsonRes({ ok: false, error: '密码暂未同步，请先在已登录的设备上打开一次账本，再回来查看' }, 409);
    return jsonRes({ ok: true, pw: cur });
  }

  const pw = String(body.pw || '');
  if (!pw || pw.length > 100) return jsonRes({ ok: false, error: '密码无效' }, 400);
  const pwHash = await sha256hex('jz:' + pw);

  // 解析账号：哈希找到 → 已有账本；找不到 → 先认领老数据（早期版本直接以密码哈希为 account），再新建
  let row = await env.DB.prepare('SELECT id, pw_hash, pw_enc FROM accounts WHERE pw_hash=?').bind(pwHash).first();
  if (!row) {
    const ip = ipKey(req.headers.get('CF-Connecting-IP') || '');
    const legacy = await env.DB.prepare('SELECT 1 AS x FROM entries WHERE account=? LIMIT 1').bind(pwHash).first()
      || await env.DB.prepare('SELECT 1 AS x FROM botcfg WHERE account=? LIMIT 1').bind(pwHash).first();
    if (legacy) {
      // 老账本认领：id 沿用旧哈希，数据无缝衔接，不占 IP 新建名额
      await env.DB.prepare('INSERT OR IGNORE INTO accounts (id, pw_hash, pw_enc, ip, ts) VALUES (?, ?, ?, ?, ?)')
        .bind(pwHash, pwHash, await encText(env, pw), ip, now).run();
      row = { id: pwHash, pw_hash: pwHash, pw_enc: '' };
    } else {
      if (ip) {
        const cnt = await env.DB.prepare('SELECT COUNT(*) AS c FROM accounts WHERE ip=?').bind(ip).first();
        if (cnt && cnt.c >= 3) return jsonRes({ ok: false, code: 'IP_LIMIT', error: '该网络已创建 3 个账本，达到上限' }, 403);
      }
      const id = crypto.randomUUID();
      await env.DB.prepare('INSERT INTO accounts (id, pw_hash, pw_enc, ip, ts) VALUES (?, ?, ?, ?, ?)')
        .bind(id, pwHash, await encText(env, pw), ip, now).run();
      row = { id, pw_hash: pwHash, pw_enc: '' };
    }
  }
  const account = row.id;

  // 加密副本自愈：缺失或解不开（老账号/密钥更换）就用本次登录密码重写
  if (!row.pw_enc || !(await decText(env, row.pw_enc))) {
    await env.DB.prepare('UPDATE accounts SET pw_enc=? WHERE id=?').bind(await encText(env, pw), account).run();
  }

  // ---- 修改密码（当前密码即 body.pw，已校验存在） ----
  if (path === '/api/change-pw') {
    const newPw = String(body.newPw || '');
    if (!newPw || newPw.length > 100) return jsonRes({ ok: false, error: '新密码不对' }, 400);
    if (newPw === pw) return jsonRes({ ok: false, error: '新密码和旧的一样' }, 400);
    await rotatePassword(env, row, newPw);
    const pushed = await pushPwToBot(env, account, newPw);
    return jsonRes({ ok: true, pushed });
  }

  if (path === '/api/summary') {
    const s = await sumsFor(env, account);
    return jsonRes({ ok: true, ...s });
  }

  if (path === '/api/entries') {
    const month = String(body.month || monthKey(now));
    if (!/^\d{4}-\d{2}$/.test(month)) return jsonRes({ ok: false, error: '月份格式不对' }, 400);
    const r = await env.DB.prepare(
      'SELECT id, type, amount, note, ts, day FROM entries WHERE account=? AND month=? ORDER BY ts DESC, id DESC'
    ).bind(account, month).all();
    return jsonRes({ ok: true, entries: r.results || [] });
  }

  if (path === '/api/add') {
    const type = body.type === 'in' ? 'in' : 'out';
    const cents = validCents(body);
    if (!cents) return jsonRes({ ok: false, error: '金额不对' }, 400);
    await insertEntry(env, account, type, cents, String(body.note || '').slice(0, 100));
    return jsonRes({ ok: true });
  }

  if (path === '/api/edit') {
    const id = Number(body.id);
    const cents = validCents(body);
    const type = body.type === 'in' ? 'in' : 'out';
    if (!id || !cents) return jsonRes({ ok: false, error: '参数不对' }, 400);
    const note = String(body.note || '').slice(0, 100);
    const r = await env.DB.prepare(
      'UPDATE entries SET amount=?, note=?, type=? WHERE id=? AND account=?'
    ).bind(cents, note, type, id, account).run();
    if (!r.meta || r.meta.changes === 0) return jsonRes({ ok: false, error: '密码不对或记录不存在' }, 403);
    return jsonRes({ ok: true });
  }

  if (path === '/api/delete') {
    const id = Number(body.id);
    if (!id) return jsonRes({ ok: false, error: '参数不对' }, 400);
    const r = await env.DB.prepare('DELETE FROM entries WHERE id=? AND account=?').bind(id, account).run();
    if (!r.meta || r.meta.changes === 0) return jsonRes({ ok: false, error: '密码不对或记录不存在' }, 403);
    return jsonRes({ ok: true });
  }

  if (path === '/api/delete-period') {
    let r;
    if (body.scope === 'month') {
      const month = String(body.key || '');
      if (!/^\d{4}-\d{2}$/.test(month)) return jsonRes({ ok: false, error: '月份格式不对' }, 400);
      r = await env.DB.prepare('DELETE FROM entries WHERE account=? AND month=?').bind(account, month).run();
    } else if (body.scope === 'year') {
      const year = String(body.key || '');
      if (!/^\d{4}$/.test(year)) return jsonRes({ ok: false, error: '年份格式不对' }, 400);
      r = await env.DB.prepare('DELETE FROM entries WHERE account=? AND month LIKE ?').bind(account, year + '-%').run();
    } else {
      return jsonRes({ ok: false, error: '范围不对' }, 400);
    }
    return jsonRes({ ok: true, deleted: r.meta ? r.meta.changes : 0 });
  }

  // ---- Telegram 机器人配置 ----
  if (path === '/api/bot-get') {
    const c = await env.DB.prepare('SELECT token, tg_id FROM botcfg WHERE account=?').bind(account).first();
    if (!c) return jsonRes({ ok: true, bound: false });
    return jsonRes({ ok: true, bound: true, tgId: c.tg_id, tokenTail: String(c.token).slice(-4) });
  }

  if (path === '/api/bot-save') {
    const token = String(body.token || '').trim();
    const tgId = String(body.tgId || '').trim();
    if (!/^\d+:[A-Za-z0-9_-]{20,}$/.test(token)) return jsonRes({ ok: false, error: 'Token 格式不对' }, 400);
    if (!/^\d{5,}$/.test(tgId)) return jsonRes({ ok: false, error: 'Telegram ID 格式不对（纯数字）' }, 400);
    const wh = await sha256hex('whid:' + account);
    await env.DB.prepare(
      'INSERT INTO botcfg (account, token, tg_id, wh) VALUES (?, ?, ?, ?) ON CONFLICT(account) DO UPDATE SET token=excluded.token, tg_id=excluded.tg_id, wh=excluded.wh'
    ).bind(account, token, tgId, wh).run();
    const origin = new URL(req.url).origin;
    const tgRes = await fetch(`https://api.telegram.org/bot${token}/setWebhook`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: `${origin}/tg/${wh}`, allowed_updates: ['message', 'callback_query'] }),
    }).then((r) => r.json()).catch(() => null);
    if (!tgRes || !tgRes.ok) {
      return jsonRes({ ok: false, error: '绑定失败：Telegram 拒绝了 webhook（' + ((tgRes && tgRes.description) || '网络错误') + '），请检查 Token' }, 400);
    }
    return jsonRes({ ok: true });
  }

  if (path === '/api/bot-del') {
    const c = await env.DB.prepare('SELECT token FROM botcfg WHERE account=?').bind(account).first();
    if (c) {
      await fetch(`https://api.telegram.org/bot${c.token}/deleteWebhook`, { method: 'POST' }).catch(() => {});
      await env.DB.prepare('DELETE FROM botcfg WHERE account=?').bind(account).run();
    }
    return jsonRes({ ok: true });
  }

  return jsonRes({ ok: false, error: '未知接口' }, 404);
}

// ---- Telegram webhook ----
async function tgCall(token, method, params) {
  const r = await fetch(`https://api.telegram.org/bot${token}/${method}`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(params),
  });
  return r.json().catch(() => ({}));
}

const BILL_KB = {
  inline_keyboard: [
    [{ text: '📅 本月账单', callback_data: 'm' }, { text: '📚 全部账单', callback_data: 'a' }],
    [{ text: '🔐 查看当前密码', callback_data: 'pw' }],
  ],
};

async function monthBillText(env, account) {
  const curMonth = monthKey(Date.now());
  const r = await env.DB.prepare(
    'SELECT type, amount, note, ts, day FROM entries WHERE account=? AND month=? ORDER BY ts ASC, id ASC'
  ).bind(account, curMonth).all();
  const list = r.results || [];
  let tin = 0, tout = 0;
  const lines = [`📅 ${curMonth} 月账单（共 ${list.length} 笔）`];
  const show = list.slice(-100);
  if (list.length > 100) lines.push('（仅显示最近 100 笔）');
  for (const e of list) { if (e.type === 'in') tin += e.amount; else tout += e.amount; }
  for (const e of show) {
    lines.push(`${e.day.slice(5)} ${timeStr(e.ts)} ${e.note || (e.type === 'in' ? '收入' : '支出')} ${e.type === 'in' ? '+' : '-'}${fmtC(e.amount)}`);
  }
  lines.push(`———\n总收入 ${fmtC(tin)} · 总支出 ${fmtC(tout)} · 结余 ${fmtC(tin - tout)}`);
  return lines.join('\n');
}

async function allBillText(env, account) {
  const s = await sumsFor(env, account);
  const lines = ['📚 全部账单'];
  if (!s.months.length) lines.push('暂无记录');
  const byMonth = s.months.slice().sort((a, b) => (a.month < b.month ? -1 : 1));
  for (const m of byMonth) {
    lines.push(`${m.month}：收 ${fmtC(m.in)} · 支 ${fmtC(m.out)}（${m.count} 笔）`);
  }
  lines.push(`———\n总收入 ${fmtC(s.all.in)} · 总支出 ${fmtC(s.all.out)} · 结余 ${fmtC(s.all.in - s.all.out)}`);
  return lines.join('\n');
}

async function handleTg(env, wh, u) {
  const cfg = await env.DB.prepare('SELECT account, token, tg_id FROM botcfg WHERE wh=?').bind(wh).first();
  if (!cfg) return;
  const token = cfg.token;

  let chatId = null, fromId = null, text = '', cq = null;
  if (u.message) {
    chatId = u.message.chat.id; fromId = u.message.from && u.message.from.id;
    text = String(u.message.text || '').trim();
    if (u.message.chat.type !== 'private') return;
  } else if (u.callback_query) {
    cq = u.callback_query;
    chatId = cq.message.chat.id; fromId = cq.from.id;
  } else return;

  if (String(fromId) !== String(cfg.tg_id)) return; // 只认绑定的 ID

  const sendPw = async () => {
    const row = await env.DB.prepare('SELECT pw_enc FROM accounts WHERE id=?').bind(cfg.account).first();
    const cur = row ? await decText(env, row.pw_enc) : '';
    await tgCall(token, 'sendMessage', {
      chat_id: chatId,
      text: cur ? `🔐 你当前的记账本密码是：${cur}\n（看完建议删掉这条消息）` : '暂未记录密码，请先在网页登录一次，之后就能在这里查看。',
      reply_markup: BILL_KB,
    });
  };

  if (cq) {
    await tgCall(token, 'answerCallbackQuery', { callback_query_id: cq.id });
    if (cq.data === 'pw') { await sendPw(); return; }
    const t = cq.data === 'm' ? await monthBillText(env, cfg.account) : await allBillText(env, cfg.account);
    await tgCall(token, 'sendMessage', { chat_id: chatId, text: t, reply_markup: BILL_KB });
    return;
  }

  if (text === '/start' || text === '菜单') {
    await tgCall(token, 'sendMessage', {
      chat_id: chatId,
      text: '📒 生活记账本\n\n直接发消息就能记账：\n• 外卖-15 → 支出 15 元\n• 卖东西+30 → 收入 30 元\n\n点下面按钮看账单、查密码 👇',
      reply_markup: BILL_KB,
    });
    return;
  }
  if (text === '本月账单' || text === '/month') {
    await tgCall(token, 'sendMessage', { chat_id: chatId, text: await monthBillText(env, cfg.account), reply_markup: BILL_KB });
    return;
  }
  if (text === '全部账单' || text === '/all') {
    await tgCall(token, 'sendMessage', { chat_id: chatId, text: await allBillText(env, cfg.account), reply_markup: BILL_KB });
    return;
  }
  if (text === '查看密码' || text === '/pw') { await sendPw(); return; }

  const norm = text.replace(/＋/g, '+').replace(/－/g, '-');
  const m = norm.match(/^([\s\S]+?)([+\-])(\d+(?:\.\d{1,2})?)$/);
  if (m) {
    const note = m[1].trim().slice(0, 100);
    const cents = Math.round(Number(m[3]) * 100);
    if (note && cents > 0 && cents <= 10000000000) {
      const type = m[2] === '+' ? 'in' : 'out';
      await insertEntry(env, cfg.account, type, cents, note);
      const s = await sumsFor(env, cfg.account);
      await tgCall(token, 'sendMessage', {
        chat_id: chatId,
        text: `✅ 已计入：${note} ${type === 'in' ? '收入' : '支出'} ${fmtC(cents)}\n\n本月：收入 ${fmtC(s.month.in)} · 支出 ${fmtC(s.month.out)}\n全部：收入 ${fmtC(s.all.in)} · 支出 ${fmtC(s.all.out)}`,
        reply_markup: BILL_KB,
      });
      return;
    }
  }
  await tgCall(token, 'sendMessage', {
    chat_id: chatId,
    text: '格式不对。发"备注-金额"记支出、"备注+金额"记收入，比如：外卖-15、工资+8000',
    reply_markup: BILL_KB,
  });
}

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    if (url.pathname.startsWith('/tg/') && req.method === 'POST') {
      try {
        await ensureSchema(env);
        await handleTg(env, url.pathname.slice(4), await req.json());
      } catch (e) { console.log('tg err', String(e).slice(0, 200)); }
      return new Response('ok');
    }
    if (url.pathname.startsWith('/api/') && req.method === 'POST') {
      try {
        await ensureSchema(env);
        return await handleApi(env, req, url.pathname, await req.json());
      } catch (e) {
        return jsonRes({ ok: false, error: String((e && e.message) || e).slice(0, 200) }, 500);
      }
    }
    if (req.method === 'GET' && url.pathname === '/') {
      return new Response(HTML_PAGE, { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
    }
    return new Response('not found', { status: 404 });
  },
};

const HTML_PAGE = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no">
<title>生活记账本</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/html2canvas/1.4.1/html2canvas.min.js"></script>
<style>
* { margin:0; padding:0; box-sizing:border-box; -webkit-tap-highlight-color:transparent; }
body {
  font-family:-apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif;
  min-height:100vh; color:#1c2733; padding:16px 12px 40px;
  background:linear-gradient(135deg,#8fb0ff 0%,#b79aff 35%,#ff9fd0 70%,#ffc98f 100%);
  background-attachment:fixed;
}
#pcanvas, #mcanvas { position:fixed; inset:0; width:100%; height:100%; z-index:0; pointer-events:none; }
.wrap { max-width:860px; margin:0 auto; position:relative; z-index:2; }
.glass {
  background:rgba(255,255,255,.48);
  backdrop-filter:blur(20px) saturate(1.5); -webkit-backdrop-filter:blur(20px) saturate(1.5);
  border:1px solid rgba(255,255,255,.6); border-radius:20px;
  box-shadow:0 10px 36px rgba(90,60,160,.2);
}
.hidden { display:none !important; }
.slogan { font-size:13px; color:#54687f; letter-spacing:1px; }
.grad-text {
  background:linear-gradient(90deg,#4158d0,#c850c0,#ff8c5a);
  -webkit-background-clip:text; background-clip:text; -webkit-text-fill-color:transparent; color:transparent;
}

/* 登录 */
#loginView { max-width:420px; margin:9vh auto 0; padding:30px 24px; position:relative; overflow:hidden; }
#loginView::before {
  content:''; position:absolute; inset:0; pointer-events:none;
  background:radial-gradient(420px 200px at 20% 0%,rgba(255,255,255,.5),transparent 60%);
}
#loginView h2 { font-size:23px; text-align:center; margin-bottom:6px; letter-spacing:3px; }
#loginView .slogan { display:block; text-align:center; margin-bottom:16px; }
#loginView p { font-size:13px; color:#5a6a7d; text-align:center; line-height:1.7; margin-bottom:18px; position:relative; }
#loginView .inp, #loginView .btn { position:relative; }
input, button { font-family:inherit; }
.inp {
  width:100%; padding:13px 14px; font-size:16px; border-radius:12px;
  border:1px solid rgba(255,255,255,.7); background:rgba(255,255,255,.68);
  outline:none; margin-bottom:12px; color:#1c2733; transition:border-color .2s, background .2s;
}
.inp:focus { border-color:#7a9bff; background:rgba(255,255,255,.9); }
.btn {
  width:100%; padding:13px; font-size:16px; border:none; border-radius:12px; cursor:pointer;
  background:linear-gradient(135deg,#5f7cff,#9a5fff); color:#fff; font-weight:600; letter-spacing:2px;
  box-shadow:0 6px 18px rgba(110,90,255,.35); transition:transform .15s, box-shadow .15s;
}
.btn:hover { box-shadow:0 8px 24px rgba(110,90,255,.45); }
.btn:active { transform:scale(.98); }
.btn.ghost { background:rgba(255,255,255,.6); color:#46586c; letter-spacing:0; box-shadow:none; }
.btn.small { width:auto; padding:8px 16px; font-size:14px; }
.btn.danger { background:linear-gradient(135deg,#f0564f,#e23b3b); letter-spacing:0; box-shadow:0 6px 18px rgba(226,59,59,.3); }
.center-link { display:block; text-align:center; margin-top:14px; font-size:13px; color:#54687f; background:none; border:none; cursor:pointer; text-decoration:underline; width:100%; }

/* 顶部栏 */
.topbar { display:flex; justify-content:space-between; align-items:center; padding:6px 4px 12px; gap:8px; flex-wrap:wrap; }
.topbar .t { font-size:21px; font-weight:800; letter-spacing:2px; }
.topbar .slogan { display:block; font-size:12px; font-weight:400; letter-spacing:1px; margin-top:2px; -webkit-text-fill-color:#54687f; }
.link { background:none; border:none; color:#54687f; font-size:13px; cursor:pointer; text-decoration:underline; margin-left:10px; }

/* 统计卡 */
.cards { display:grid; grid-template-columns:repeat(3,1fr); gap:10px; margin-bottom:12px; }
.card { padding:14px 12px; text-align:center; transition:transform .2s, box-shadow .2s; }
.card:hover { transform:translateY(-2px); box-shadow:0 14px 40px rgba(90,60,160,.26); }
.card .lab { font-size:13px; color:#5a6a7d; margin-bottom:8px; font-weight:600; }
.card .row { font-size:13px; line-height:1.9; }
.money-in { color:#0a9d58; font-weight:700; }
.money-out { color:#e23b3b; font-weight:700; }
.big { font-size:17px; }

/* 面板与表单 */
.panel { padding:16px; margin-bottom:12px; }
.toggle { display:flex; gap:10px; margin-bottom:12px; }
.toggle button {
  flex:1; padding:11px; font-size:15px; border-radius:12px; cursor:pointer;
  border:1px solid rgba(255,255,255,.7); background:rgba(255,255,255,.4); color:#46586c; font-weight:600; transition:all .15s;
}
.toggle button.on-out { background:#e23b3b; color:#fff; border-color:#e23b3b; }
.toggle button.on-in { background:#0a9d58; color:#fff; border-color:#0a9d58; }
.form-row { display:flex; gap:10px; }
.form-row .note { flex:1; }
.form-row .amt { flex:0 0 36%; }
.form-row .inp { margin-bottom:0; }
.tip { font-size:13px; color:#5a6a7d; line-height:1.8; margin-bottom:12px; }

/* 明细 */
.sec-title { font-size:15px; font-weight:700; padding:4px 6px 10px; }
.entry {
  display:flex; align-items:center; gap:8px; padding:11px 12px; margin-bottom:8px;
  background:rgba(255,255,255,.42); border:1px solid rgba(255,255,255,.5); border-radius:14px;
}
.entry .dot { width:9px; height:9px; border-radius:50%; flex:0 0 auto; }
.dot.out { background:#e23b3b; } .dot.in { background:#0a9d58; }
.entry .mid { flex:1; min-width:0; }
.entry .note { font-size:15px; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
.entry .time { font-size:12px; color:#7488a0; }
.entry .amt { font-size:16px; font-weight:700; white-space:nowrap; }
.entry .act { background:rgba(255,255,255,.6); border:1px solid rgba(255,255,255,.8); border-radius:9px; padding:6px 10px; font-size:13px; cursor:pointer; color:#46586c; flex:0 0 auto; }
.entry .act.del { color:#e23b3b; }
.empty { text-align:center; color:#7488a0; font-size:14px; padding:22px 0; }

/* 月/年列表行 */
.month-row {
  display:flex; justify-content:space-between; align-items:center; padding:13px 14px; margin-bottom:8px;
  background:rgba(255,255,255,.42); border:1px solid rgba(255,255,255,.5); border-radius:14px; cursor:pointer; gap:8px; flex-wrap:wrap;
  transition:background .15s, transform .15s;
}
.month-row:hover { background:rgba(255,255,255,.62); transform:translateY(-1px); }
.month-row:active { background:rgba(255,255,255,.65); }
.month-row .m { font-size:16px; font-weight:700; }
.month-row .s { font-size:13px; }

/* 账单页 */
#billCard {
  background:linear-gradient(160deg,#fdfdff,#eef2ff 55%,#ffeef6);
  border-radius:20px; padding:22px 18px; box-shadow:0 8px 32px rgba(90,60,160,.18);
}
#billCard h2 { text-align:center; font-size:21px; letter-spacing:2px; margin-bottom:4px; }
#billCard .bsub { text-align:center; font-size:12px; color:#7488a0; margin-bottom:16px; }
.btable { width:100%; border-collapse:collapse; font-size:14px; }
.btable th { text-align:left; padding:8px 6px; border-bottom:2px solid #c9d4ea; color:#46586c; }
.btable td { padding:8px 6px; border-bottom:1px solid #e3e9f5; vertical-align:top; }
.btable .r { text-align:right; white-space:nowrap; }
.btable tr.clickable { cursor:pointer; }
.btotal { margin-top:16px; padding:14px 12px; background:rgba(95,124,255,.1); border-radius:14px; font-size:15px; line-height:2; }
.btotal .r { float:right; font-weight:700; }

/* 弹窗 */
.mask { position:fixed; inset:0; background:rgba(40,40,70,.45); display:flex; align-items:center; justify-content:center; z-index:99; padding:18px; }
.modal { width:100%; max-width:400px; padding:22px 18px; background:rgba(255,255,255,.9); backdrop-filter:blur(20px); border-radius:20px; box-shadow:0 12px 40px rgba(0,0,0,.25); }
.modal h3 { font-size:17px; margin-bottom:14px; text-align:center; }
.modal .desc { font-size:14px; color:#46586c; text-align:center; margin-bottom:14px; line-height:1.6; }
.modal .btnrow { display:flex; gap:10px; margin-top:6px; }
.modal .btnrow .btn { flex:1; }
#shotImg { width:100%; border-radius:14px; margin-top:12px; }

@media (max-width:640px) {
  .cards { grid-template-columns:1fr 1fr 1fr; gap:8px; }
  .card { padding:10px 6px; }
  .card .row { font-size:12px; }
  .big { font-size:14px; }
  .form-row { flex-direction:column; }
  .form-row .amt { flex:none; }
  .topbar .t { font-size:18px; }
}
</style>
</head>
<body>
<canvas id="pcanvas"></canvas>
<canvas id="mcanvas" class="hidden"></canvas>
<div class="wrap">

  <!-- 登录页（主页入口） -->
  <div id="loginView" class="glass">
    <div id="loginForm">
      <h2>📒 <span class="grad-text">生活记账本</span></h2>
      <span class="slogan">看清每一笔账，活得更明白；省钱，是普通人最稳的致富路。</span>
      <p>输入你的专属密码即可打开你的账本。<br>密码就是账号，不同密码数据完全独立，<br>请牢记，输错会进入一个空账本。</p>
      <form id="loginF">
      <input id="loginPw" class="inp" type="password" placeholder="请输入专属密码" autocomplete="current-password">
      <button class="btn" id="loginBtn">进入账本</button>
      </form>
      <button class="center-link" id="toRecover">忘记密码？用以前用过的密码找回</button>
    </div>
    <div id="recoverForm" class="hidden">
      <h2>🔑 找回密码</h2>
      <span class="slogan">输入任意一个以前用过的密码，查看当前密码</span>
      <form id="recF">
      <input id="recOld" class="inp" type="password" placeholder="以前用过的密码（任意一个）" style="margin-top:16px;">
      <button class="btn" id="recoverBtn">查看当前密码</button>
      </form>
      <div id="recResult" class="hidden" style="margin-top:16px;">
        <p style="font-size:13px;color:#5a6a7d;text-align:center;">你当前的密码是</p>
        <div id="recPwText" style="font-size:22px;font-weight:800;text-align:center;letter-spacing:1px;padding:10px 0;word-break:break-all;"></div>
        <button class="btn" id="recLoginBtn">用此密码登录</button>
      </div>
      <button class="center-link" id="toLogin">← 返回登录</button>
    </div>
  </div>

  <!-- 主页 -->
  <div id="mainView" class="hidden">
    <div class="topbar">
      <div class="t">📒 <span class="grad-text">生活记账本</span><span class="slogan">看清每一笔账，活得更明白</span></div>
      <div>
        <button class="link" id="changePwBtn" style="margin-left:0;">修改密码</button>
        <button class="link" id="logoutBtn">退出登录</button>
      </div>
    </div>

    <div class="cards">
      <div class="card glass">
        <div class="lab">今日</div>
        <div class="row">收入 <span class="money-in big" id="tIn">¥0.00</span></div>
        <div class="row">支出 <span class="money-out big" id="tOut">¥0.00</span></div>
      </div>
      <div class="card glass">
        <div class="lab">本月</div>
        <div class="row">收入 <span class="money-in big" id="mIn">¥0.00</span></div>
        <div class="row">支出 <span class="money-out big" id="mOut">¥0.00</span></div>
      </div>
      <div class="card glass">
        <div class="lab">全部</div>
        <div class="row">收入 <span class="money-in big" id="aIn">¥0.00</span></div>
        <div class="row">支出 <span class="money-out big" id="aOut">¥0.00</span></div>
      </div>
    </div>

    <div class="panel glass">
      <form id="addF">
      <div class="toggle">
        <button type="button" id="tgOut" class="on-out">💸 支出</button>
        <button type="button" id="tgIn">💰 收入</button>
      </div>
      <div class="form-row">
        <input id="noteInp" class="inp note" type="text" maxlength="100" placeholder="备注，如：午饭、工资">
        <input id="amtInp" class="inp amt" type="number" inputmode="decimal" step="0.01" min="0" placeholder="金额（元）">
      </div>
      <button class="btn" id="addBtn" style="margin-top:12px;">记一笔</button>
      </form>
    </div>

    <div class="panel glass">
      <div class="sec-title">本月明细</div>
      <div id="curList"></div>
    </div>

    <div class="panel glass">
      <div class="sec-title">月账单（点开查看）</div>
      <div id="monthList"></div>
    </div>

    <div class="panel glass">
      <div class="sec-title">年账单 / 全部账单</div>
      <div id="yearList"></div>
    </div>

    <div class="panel glass">
      <div class="sec-title">🤖 Telegram 记账机器人</div>
      <div id="botUnbound">
        <p class="tip">每个人用自己的机器人，记账只进你自己的账本，不会串到别人那里。</p>
        <p class="tip"><b>怎么拿 Token：</b><br>
        1. 在 Telegram 搜 @BotFather，点「开始」<br>
        2. 发送 /newbot<br>
        3. 给机器人起个显示名（随便写，如：我的记账）<br>
        4. 再起个用户名，必须以 bot 结尾（如 mybook_bot），重名就换一个<br>
        5. 它回复里 "Use this token" 那串长字符就是 Token，复制好</p>
        <p class="tip"><b>怎么拿你的 ID：</b><br>
        1. 在 Telegram 搜 @userinfobot，点「开始」<br>
        2. 它回复的 Id 后面那串数字，就是你的 ID</p>
        <p class="tip">两个都填下面，点保存。再私聊你刚建的机器人发 /start，就能记账了：<br>
        发"外卖-15"记支出，"卖东西+30"记收入；按钮可看账单、查密码。</p>
        <input id="botToken" class="inp" type="text" placeholder="Bot Token，如 123456:AAE...">
        <input id="botTgId" class="inp" type="text" inputmode="numeric" placeholder="你的 Telegram 数字 ID">
        <button class="btn" id="botSaveBtn">保存并绑定</button>
      </div>
      <div id="botBound" class="hidden">
        <p class="tip" id="botStatus"></p>
        <p class="tip">现在去 Telegram 私聊你的机器人，发 /start 试试：<br>发"外卖-15"记支出，"卖东西+30"记收入，点按钮看账单、查密码。</p>
        <button class="btn danger" id="botDelBtn">解绑机器人</button>
      </div>
    </div>
  </div>

  <!-- 账单页（月 / 年 / 全部共用） -->
  <div id="billView" class="hidden">
    <div class="topbar">
      <button class="btn ghost small" id="backBtn">← 返回</button>
      <div>
        <button class="btn small" id="shotBtn" style="width:auto;">📸 生成长截图</button>
        <button class="btn danger small hidden" id="delPeriodBtn">🗑 删除</button>
      </div>
    </div>
    <div id="billCard">
      <h2 id="billTitle">账单</h2>
      <div class="bsub">生活记账本 · 看清每一笔账，活得更明白 · 北京时间</div>
      <div id="billBodyWrap"></div>
      <div class="btotal" id="billTotal"></div>
    </div>
    <img id="shotImg" class="hidden" alt="账单长截图">
    <p id="shotTip" class="hidden" style="text-align:center;font-size:13px;color:#fff;margin-top:8px;">长按图片即可保存</p>
  </div>
</div>

<!-- 修改密码弹窗 -->
<div id="pwMask" class="mask hidden">
  <div class="modal">
    <h3>修改密码</h3>
    <form id="pwF">
    <input id="pwCur" class="inp" type="password" placeholder="当前密码">
    <input id="pwNew" class="inp" type="password" placeholder="新密码">
    <input id="pwNew2" class="inp" type="password" placeholder="再输一次新密码">
    <p class="desc">修改后如果绑了机器人，新密码会推送到你的 Telegram。</p>
    <div class="btnrow">
      <button type="button" class="btn ghost" id="pwCancel">取消</button>
      <button class="btn" id="pwSave">确认修改</button>
    </div>
    </form>
  </div>
</div>

<!-- 编辑弹窗：先验密码，再改 -->
<div id="editMask" class="mask hidden">
  <div class="modal">
    <div id="editStep1">
      <h3>修改需验证密码</h3>
      <form id="editF1">
      <input id="editPw" class="inp" type="password" placeholder="请再次输入专属密码">
      <div class="btnrow">
        <button type="button" class="btn ghost" id="editCancel1">取消</button>
        <button class="btn" id="editVerify">验证</button>
      </div>
      </form>
    </div>
    <div id="editStep2" class="hidden">
      <h3>修改这笔账</h3>
      <form id="editF2">
      <div class="toggle">
        <button type="button" id="eTgOut">💸 支出</button>
        <button type="button" id="eTgIn">💰 收入</button>
      </div>
      <input id="editNote" class="inp" type="text" maxlength="100" placeholder="备注">
      <input id="editAmt" class="inp" type="number" inputmode="decimal" step="0.01" min="0" placeholder="金额（元）">
      <div class="btnrow">
        <button type="button" class="btn ghost" id="editCancel2">取消</button>
        <button class="btn" id="editSave">保存修改</button>
      </div>
      </form>
    </div>
  </div>
</div>

<!-- 删除弹窗：验密码后确认 -->
<div id="delMask" class="mask hidden">
  <div class="modal">
    <h3>删除需验证密码</h3>
    <p class="desc" id="delDesc"></p>
    <form id="delF">
    <input id="delPw" class="inp" type="password" placeholder="请输入专属密码">
    <div class="btnrow">
      <button type="button" class="btn ghost" id="delCancel">取消</button>
      <button class="btn danger" id="delConfirm">确认删除</button>
    </div>
    </form>
  </div>
</div>

<script>
var PW = localStorage.getItem('jz_pw') || '';
var curType = 'out';
var editType = 'out';
var summary = null;
var editId = null;
var pendingDel = null;
var billMode = '';
var billKey = '';

function $(id) { return document.getElementById(id); }
function fmt(c) { return '¥' + (c / 100).toFixed(2); }
function yuan(c) { return (c / 100).toFixed(2); }
function esc(s) {
  return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}
function api(path, body) {
  return fetch(path, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })
    .then(function (r) { return r.json(); });
}
function bjParts(ts) {
  var d = new Date(ts + 8 * 3600 * 1000);
  function p(n) { return String(n).padStart(2, '0'); }
  return { day: d.getUTCFullYear() + '-' + p(d.getUTCMonth() + 1) + '-' + p(d.getUTCDate()), hm: p(d.getUTCHours()) + ':' + p(d.getUTCMinutes()) };
}
function submitOn(id, fn) { $(id).addEventListener('submit', function (e) { e.preventDefault(); fn(); }); }

// ---------- 特效画布开关 ----------
function fxSync() {
  var onLogin = !$('loginView').classList.contains('hidden');
  $('pcanvas').classList.toggle('hidden', !onLogin);
  $('mcanvas').classList.toggle('hidden', onLogin);
}

// ---------- 登录 / 找回 ----------
function doLogin() {
  var v = $('loginPw').value.trim();
  if (!v) { alert('请输入密码'); return; }
  PW = v;
  localStorage.setItem('jz_pw', PW);
  enterMain();
}
function enterMain() {
  $('loginView').classList.add('hidden');
  $('billView').classList.add('hidden');
  $('mainView').classList.remove('hidden');
  fxSync();
  refresh();
  loadBot();
}
function forceLogout() {
  localStorage.removeItem('jz_pw');
  PW = '';
  $('mainView').classList.add('hidden');
  $('billView').classList.add('hidden');
  $('loginView').classList.remove('hidden');
  $('loginForm').classList.remove('hidden');
  $('recoverForm').classList.add('hidden');
  fxSync();
}
submitOn('loginF', doLogin);
$('logoutBtn').onclick = forceLogout;
$('toRecover').onclick = function () {
  $('loginForm').classList.add('hidden');
  $('recoverForm').classList.remove('hidden');
  $('recResult').classList.add('hidden');
  recFoundPw = '';
};
$('toLogin').onclick = function () {
  $('recoverForm').classList.add('hidden');
  $('loginForm').classList.remove('hidden');
};
var recFoundPw = '';
function doRecover() {
  var oldPw = $('recOld').value;
  if (!oldPw) { alert('请输入以前用过的密码'); return; }
  api('/api/view-pw', { oldPw: oldPw }).then(function (r) {
    if (!r.ok) { alert(r.error || '查看失败'); return; }
    recFoundPw = r.pw;
    $('recPwText').textContent = r.pw;
    $('recResult').classList.remove('hidden');
  });
}
submitOn('recF', doRecover);
$('recLoginBtn').onclick = function () {
  if (!recFoundPw) return;
  PW = recFoundPw;
  localStorage.setItem('jz_pw', PW);
  enterMain();
};

// ---------- 修改密码 ----------
$('changePwBtn').onclick = function () {
  $('pwCur').value = ''; $('pwNew').value = ''; $('pwNew2').value = '';
  $('pwMask').classList.remove('hidden');
  $('pwCur').focus();
};
$('pwCancel').onclick = function () { $('pwMask').classList.add('hidden'); };
function doChangePw() {
  var cur = $('pwCur').value, n1 = $('pwNew').value, n2 = $('pwNew2').value;
  if (cur !== PW) { alert('当前密码不对'); return; }
  if (!n1) { alert('请输入新密码'); return; }
  if (n1 !== n2) { alert('两次新密码不一致'); return; }
  api('/api/change-pw', { pw: cur, newPw: n1 }).then(function (r) {
    if (!r.ok) { alert(r.error || '修改失败'); return; }
    PW = n1;
    localStorage.setItem('jz_pw', PW);
    $('pwMask').classList.add('hidden');
    alert('密码修改成功' + (r.pushed ? '，新密码已推送到你的 Telegram 机器人' : ''));
  });
}
submitOn('pwF', doChangePw);

// ---------- 记账表单 ----------
function setType(t) {
  curType = t;
  $('tgOut').className = t === 'out' ? 'on-out' : '';
  $('tgIn').className = t === 'in' ? 'on-in' : '';
}
$('tgOut').onclick = function () { setType('out'); };
$('tgIn').onclick = function () { setType('in'); };

function doAdd() {
  var amt = parseFloat($('amtInp').value);
  if (!amt || amt <= 0) { alert('请输入正确金额'); return; }
  api('/api/add', { pw: PW, type: curType, amount: amt, note: $('noteInp').value.trim() }).then(function (r) {
    if (!r.ok) { alert(r.error || '记账失败'); return; }
    $('amtInp').value = ''; $('noteInp').value = '';
    $('noteInp').focus();
    refresh();
  });
}
submitOn('addF', doAdd);

// ---------- 主页渲染 ----------
function refresh() {
  api('/api/summary', { pw: PW }).then(function (s) {
    if (!s.ok) {
      if (s.code === 'IP_LIMIT') { alert(s.error); forceLogout(); return; }
      alert(s.error || '加载失败');
      return;
    }
    summary = s;
    $('tIn').textContent = fmt(s.today.in); $('tOut').textContent = fmt(s.today.out);
    $('mIn').textContent = fmt(s.month.in); $('mOut').textContent = fmt(s.month.out);
    $('aIn').textContent = fmt(s.all.in); $('aOut').textContent = fmt(s.all.out);
    renderMonths(s.months);
    renderYears(s.months);
    loadEntries(s.curMonth, $('curList'));
  });
}

function entryHtml(e) {
  var p = bjParts(e.ts);
  var sign = e.type === 'in' ? '+' : '-';
  var cls = e.type === 'in' ? 'money-in' : 'money-out';
  return '<div class="entry">' +
    '<div class="dot ' + e.type + '"></div>' +
    '<div class="mid"><div class="note">' + esc(e.note || (e.type === 'in' ? '收入' : '支出')) + '</div>' +
    '<div class="time">' + p.day + ' ' + p.hm + '</div></div>' +
    '<div class="amt ' + cls + '">' + sign + fmt(e.amount) + '</div>' +
    '<button class="act" data-edit="' + e.id + '" data-type="' + e.type + '" data-amt="' + (e.amount / 100) + '" data-note="' + esc(e.note || '') + '">修改</button>' +
    '<button class="act del" data-del="' + e.id + '">删除</button>' +
    '</div>';
}

function bindActions(container) {
  var eb = container.querySelectorAll('[data-edit]');
  for (var i = 0; i < eb.length; i++) {
    eb[i].onclick = function () {
      editId = Number(this.getAttribute('data-edit'));
      setEditType(this.getAttribute('data-type'));
      $('editAmt').value = this.getAttribute('data-amt');
      $('editNote').value = this.getAttribute('data-note');
      $('editPw').value = '';
      $('editStep1').classList.remove('hidden');
      $('editStep2').classList.add('hidden');
      $('editMask').classList.remove('hidden');
      $('editPw').focus();
    };
  }
  var db = container.querySelectorAll('[data-del]');
  for (var j = 0; j < db.length; j++) {
    db[j].onclick = function () {
      openDel({ kind: 'entry', id: Number(this.getAttribute('data-del')) }, '确定删除这一笔账？删了不可恢复。');
    };
  }
}

function loadEntries(month, container) {
  api('/api/entries', { pw: PW, month: month }).then(function (r) {
    if (!r.ok || !r.entries.length) {
      container.innerHTML = '<div class="empty">暂无记录</div>';
      return;
    }
    var html = '';
    for (var i = 0; i < r.entries.length; i++) html += entryHtml(r.entries[i]);
    container.innerHTML = html;
    bindActions(container);
  });
}

function renderMonths(months) {
  var box = $('monthList');
  if (!months.length) { box.innerHTML = '<div class="empty">暂无记录</div>'; return; }
  var html = '';
  for (var i = 0; i < months.length; i++) {
    var m = months[i];
    html += '<div class="month-row" data-month="' + m.month + '">' +
      '<div><span class="m">' + m.month + '</span> <span class="s" style="color:#7488a0;">' + m.count + ' 笔</span></div>' +
      '<div class="s">收入 <span class="money-in">' + fmt(m.in) + '</span> · 支出 <span class="money-out">' + fmt(m.out) + '</span></div>' +
      '</div>';
  }
  box.innerHTML = html;
  var rows = box.querySelectorAll('[data-month]');
  for (var j = 0; j < rows.length; j++) {
    rows[j].onclick = function () { openMonthBill(this.getAttribute('data-month')); };
  }
}

function groupYears(months) {
  var map = {}, order = [];
  for (var i = 0; i < months.length; i++) {
    var y = months[i].month.slice(0, 4);
    if (!map[y]) { map[y] = { year: y, in: 0, out: 0, count: 0, list: [] }; order.push(y); }
    map[y].in += months[i].in; map[y].out += months[i].out; map[y].count += months[i].count;
    map[y].list.push(months[i]);
  }
  return order.map(function (y) { return map[y]; });
}

function renderYears(months) {
  var box = $('yearList');
  if (!months.length) { box.innerHTML = '<div class="empty">暂无记录</div>'; return; }
  var years = groupYears(months);
  var html = '';
  for (var i = 0; i < years.length; i++) {
    var y = years[i];
    html += '<div class="month-row" data-year="' + y.year + '">' +
      '<div><span class="m">' + y.year + ' 年</span> <span class="s" style="color:#7488a0;">' + y.count + ' 笔</span></div>' +
      '<div class="s">收入 <span class="money-in">' + fmt(y.in) + '</span> · 支出 <span class="money-out">' + fmt(y.out) + '</span></div>' +
      '</div>';
  }
  html += '<div class="month-row" data-all="1">' +
    '<div><span class="m">全部账单</span></div>' +
    '<div class="s">收入 <span class="money-in">' + fmt(summary.all.in) + '</span> · 支出 <span class="money-out">' + fmt(summary.all.out) + '</span></div>' +
    '</div>';
  box.innerHTML = html;
  var rows = box.querySelectorAll('[data-year]');
  for (var j = 0; j < rows.length; j++) {
    rows[j].onclick = function () { openYearBill(this.getAttribute('data-year')); };
  }
  box.querySelector('[data-all]').onclick = function () { openAllBill(); };
}

// ---------- 编辑 ----------
function setEditType(t) {
  editType = t;
  $('eTgOut').className = t === 'out' ? 'on-out' : '';
  $('eTgIn').className = t === 'in' ? 'on-in' : '';
}
$('eTgOut').onclick = function () { setEditType('out'); };
$('eTgIn').onclick = function () { setEditType('in'); };

function closeEdit() { $('editMask').classList.add('hidden'); editId = null; }
$('editCancel1').onclick = closeEdit;
$('editCancel2').onclick = closeEdit;
function doVerify() {
  if ($('editPw').value !== PW) { alert('密码不对'); return; }
  $('editStep1').classList.add('hidden');
  $('editStep2').classList.remove('hidden');
}
submitOn('editF1', doVerify);
function doSaveEdit() {
  var amt = parseFloat($('editAmt').value);
  if (!amt || amt <= 0) { alert('请输入正确金额'); return; }
  api('/api/edit', { pw: $('editPw').value, id: editId, type: editType, amount: amt, note: $('editNote').value.trim() }).then(function (r) {
    if (!r.ok) { alert(r.error || '修改失败'); return; }
    closeEdit();
    refresh();
    if (billMode === 'month') openMonthBill(billKey, true);
  });
}
submitOn('editF2', doSaveEdit);

// ---------- 删除 ----------
function openDel(target, desc) {
  pendingDel = target;
  $('delDesc').textContent = desc;
  $('delPw').value = '';
  $('delMask').classList.remove('hidden');
  $('delPw').focus();
}
function closeDel() { $('delMask').classList.add('hidden'); pendingDel = null; }
$('delCancel').onclick = closeDel;
function doDel() {
  if ($('delPw').value !== PW) { alert('密码不对'); return; }
  var t = pendingDel;
  if (!t) { closeDel(); return; }
  if (t.kind === 'entry') {
    api('/api/delete', { pw: $('delPw').value, id: t.id }).then(function (r) {
      if (!r.ok) { alert(r.error || '删除失败'); return; }
      closeDel(); refresh();
      if (billMode === 'month') openMonthBill(billKey, true);
    });
  } else {
    api('/api/delete-period', { pw: $('delPw').value, scope: t.kind, key: t.key }).then(function (r) {
      if (!r.ok) { alert(r.error || '删除失败'); return; }
      closeDel();
      backToMain();
      refresh();
    });
  }
}
submitOn('delF', doDel);

// ---------- 账单页 ----------
function billHead(title) {
  $('mainView').classList.add('hidden');
  $('billView').classList.remove('hidden');
  $('shotImg').classList.add('hidden');
  $('shotTip').classList.add('hidden');
  $('billTitle').textContent = title;
  window.scrollTo(0, 0);
}
function totalsHtml(tin, tout, labelIn, labelOut, labelNet) {
  return labelIn + ' <span class="r money-in">' + fmt(tin) + '</span><br>' +
    labelOut + ' <span class="r money-out">' + fmt(tout) + '</span><br>' +
    labelNet + ' <span class="r">' + fmt(tin - tout) + '</span>';
}

function openMonthBill(month, keepView) {
  billMode = 'month'; billKey = month;
  if (!keepView) billHead(month + ' 月账单');
  $('delPeriodBtn').classList.remove('hidden');
  $('delPeriodBtn').textContent = '🗑 删除本月账单';
  api('/api/entries', { pw: PW, month: month }).then(function (r) {
    var list = (r.entries || []).slice().reverse();
    var html = '<table class="btable"><thead><tr><th style="width:24%;">日期</th><th>备注</th><th class="r" style="width:24%;">金额（元）</th><th style="width:17%;"></th></tr></thead><tbody>';
    var tin = 0, tout = 0;
    for (var i = 0; i < list.length; i++) {
      var e = list[i], p = bjParts(e.ts);
      if (e.type === 'in') tin += e.amount; else tout += e.amount;
      html += '<tr><td>' + p.day.slice(5) + ' ' + p.hm + '</td><td>' + esc(e.note || (e.type === 'in' ? '收入' : '支出')) + '</td>' +
        '<td class="r ' + (e.type === 'in' ? 'money-in' : 'money-out') + '">' + (e.type === 'in' ? '+' : '-') + yuan(e.amount) + '</td>' +
        '<td class="r"><button class="act" style="background:#eef2ff;border:1px solid #d5def5;border-radius:8px;padding:4px 8px;font-size:12px;cursor:pointer;" data-edit="' + e.id + '" data-type="' + e.type + '" data-amt="' + (e.amount / 100) + '" data-note="' + esc(e.note || '') + '">改</button> ' +
        '<button class="act" style="background:#fdeeee;border:1px solid #f5d5d5;border-radius:8px;padding:4px 8px;font-size:12px;cursor:pointer;color:#e23b3b;" data-del="' + e.id + '">删</button></td></tr>';
    }
    html += '</tbody></table>';
    if (!list.length) html = '<div class="empty">暂无记录</div>';
    $('billBodyWrap').innerHTML = html;
    $('billTotal').innerHTML = totalsHtml(tin, tout, '总收入', '总支出', '结余');
    bindActions($('billBodyWrap'));
  });
}

function openYearBill(year) {
  billMode = 'year'; billKey = year;
  billHead(year + ' 年账单');
  $('delPeriodBtn').classList.remove('hidden');
  $('delPeriodBtn').textContent = '🗑 删除本年账单';
  var years = groupYears(summary.months);
  var y = null;
  for (var i = 0; i < years.length; i++) if (years[i].year === year) y = years[i];
  if (!y) { $('billBodyWrap').innerHTML = '<div class="empty">暂无记录</div>'; $('billTotal').innerHTML = ''; return; }
  var list = y.list.slice().sort(function (a, b) { return a.month < b.month ? -1 : 1; });
  var html = '<table class="btable"><thead><tr><th>月份</th><th class="r">收入（元）</th><th class="r">支出（元）</th><th class="r">结余（元）</th></tr></thead><tbody>';
  for (var j = 0; j < list.length; j++) {
    var m = list[j];
    html += '<tr class="clickable" data-month="' + m.month + '"><td>' + m.month.slice(5) + '月（' + m.count + ' 笔）</td>' +
      '<td class="r money-in">' + yuan(m.in) + '</td><td class="r money-out">' + yuan(m.out) + '</td><td class="r">' + yuan(m.in - m.out) + '</td></tr>';
  }
  html += '</tbody></table><p style="font-size:12px;color:#7488a0;margin-top:10px;">点某个月可查看该月明细账单</p>';
  $('billBodyWrap').innerHTML = html;
  $('billTotal').innerHTML = totalsHtml(y.in, y.out, '全年总收入', '全年总支出', '全年结余');
  var rows = $('billBodyWrap').querySelectorAll('[data-month]');
  for (var k = 0; k < rows.length; k++) {
    rows[k].onclick = function () { openMonthBill(this.getAttribute('data-month')); };
  }
}

function openAllBill() {
  billMode = 'all'; billKey = '';
  billHead('全部账单');
  $('delPeriodBtn').classList.add('hidden');
  var years = groupYears(summary.months);
  var html = '<table class="btable"><thead><tr><th>年份</th><th class="r">收入（元）</th><th class="r">支出（元）</th><th class="r">结余（元）</th></tr></thead><tbody>';
  var tin = 0, tout = 0;
  for (var i = 0; i < years.length; i++) {
    var y = years[i];
    tin += y.in; tout += y.out;
    html += '<tr class="clickable" data-year="' + y.year + '"><td>' + y.year + ' 年（' + y.count + ' 笔）</td>' +
      '<td class="r money-in">' + yuan(y.in) + '</td><td class="r money-out">' + yuan(y.out) + '</td><td class="r">' + yuan(y.in - y.out) + '</td></tr>';
  }
  html += '</tbody></table><p style="font-size:12px;color:#7488a0;margin-top:10px;">点某年可查看该年账单</p>';
  if (!years.length) html = '<div class="empty">暂无记录</div>';
  $('billBodyWrap').innerHTML = html;
  $('billTotal').innerHTML = totalsHtml(tin, tout, '全部总收入', '全部总支出', '全部结余');
  var rows = $('billBodyWrap').querySelectorAll('[data-year]');
  for (var j = 0; j < rows.length; j++) {
    rows[j].onclick = function () { openYearBill(this.getAttribute('data-year')); };
  }
}

function backToMain() {
  billMode = ''; billKey = '';
  $('billView').classList.add('hidden');
  $('mainView').classList.remove('hidden');
}
$('backBtn').onclick = backToMain;

$('delPeriodBtn').onclick = function () {
  if (billMode === 'month') openDel({ kind: 'month', key: billKey }, '确定删除 ' + billKey + ' 整月账单？该月所有记录都会删掉，不可恢复。');
  else if (billMode === 'year') openDel({ kind: 'year', key: billKey }, '确定删除 ' + billKey + ' 整年账单？该年所有记录都会删掉，不可恢复。');
};

$('shotBtn').onclick = function () {
  $('shotBtn').textContent = '生成中…';
  html2canvas($('billCard'), { scale: 2, useCORS: true, backgroundColor: '#eef2ff' }).then(function (canvas) {
    var img = $('shotImg');
    img.src = canvas.toDataURL('image/png');
    img.classList.remove('hidden');
    $('shotTip').classList.remove('hidden');
    $('shotBtn').textContent = '📸 生成长截图';
    img.scrollIntoView({ behavior: 'smooth' });
  }).catch(function () {
    $('shotBtn').textContent = '📸 生成长截图';
    alert('截图生成失败，请重试');
  });
};

// ---------- Telegram 机器人配置 ----------
function loadBot() {
  api('/api/bot-get', { pw: PW }).then(function (r) {
    if (!r.ok) return;
    if (r.bound) {
      $('botUnbound').classList.add('hidden');
      $('botBound').classList.remove('hidden');
      $('botStatus').textContent = '✅ 已绑定：Telegram ID ' + r.tgId + '（Token 尾号 ' + r.tokenTail + '）';
    } else {
      $('botUnbound').classList.remove('hidden');
      $('botBound').classList.add('hidden');
    }
  });
}
$('botSaveBtn').onclick = function () {
  var token = $('botToken').value.trim();
  var tgId = $('botTgId').value.trim();
  if (!token || !tgId) { alert('Token 和 ID 都要填'); return; }
  api('/api/bot-save', { pw: PW, token: token, tgId: tgId }).then(function (r) {
    if (!r.ok) { alert(r.error || '绑定失败'); return; }
    alert('绑定成功！去 Telegram 私聊你的机器人发 /start 试试');
    loadBot();
  });
};
$('botDelBtn').onclick = function () {
  if (!confirm('确定解绑机器人？')) return;
  api('/api/bot-del', { pw: PW }).then(function (r) {
    if (!r.ok) { alert(r.error || '解绑失败'); return; }
    loadBot();
  });
};

// ---------- 登录页聚散粒子 ----------
(function () {
  var cv = $('pcanvas'), ctx = cv.getContext('2d');
  var W = 0, H = 0, pts = [], gather = false, tick = 0;
  var N = 70;
  function resize() {
    W = cv.width = window.innerWidth;
    H = cv.height = window.innerHeight;
    assignTargets();
  }
  function assignTargets() {
    var cx = W / 2, cy = H / 2, R = Math.min(W, H) * 0.33;
    for (var i = 0; i < pts.length; i++) {
      var a = (i / pts.length) * Math.PI * 2;
      var rr = R * (0.55 + 0.45 * ((i * 37 % 10) / 10));
      pts[i].gx = cx + Math.cos(a) * rr;
      pts[i].gy = cy + Math.sin(a) * rr * 0.82;
    }
  }
  for (var i = 0; i < N; i++) {
    pts.push({ x: Math.random() * 2000, y: Math.random() * 1200, vx: 0, vy: 0, gx: 0, gy: 0, r: 1.4 + Math.random() * 1.8 });
  }
  resize();
  window.addEventListener('resize', resize);
  function loop() {
    requestAnimationFrame(loop);
    if (cv.classList.contains('hidden')) return;
    tick++;
    if (tick % 330 === 0) gather = !gather; // 约5秒聚、5秒散
    ctx.clearRect(0, 0, W, H);
    var i, j, p;
    for (i = 0; i < pts.length; i++) {
      p = pts[i];
      if (gather) {
        p.vx += (p.gx - p.x) * 0.006;
        p.vy += (p.gy - p.y) * 0.006;
        p.vx *= 0.92; p.vy *= 0.92;
      } else {
        p.vx += (Math.random() - 0.5) * 0.06;
        p.vy += (Math.random() - 0.5) * 0.06;
        p.vx *= 0.985; p.vy *= 0.985;
      }
      p.x += p.vx; p.y += p.vy;
      if (p.x < -20) p.x = W + 20; if (p.x > W + 20) p.x = -20;
      if (p.y < -20) p.y = H + 20; if (p.y > H + 20) p.y = -20;
      ctx.beginPath();
      ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
      ctx.fillStyle = 'rgba(255,255,255,0.75)';
      ctx.fill();
    }
    ctx.lineWidth = 0.6;
    for (i = 0; i < pts.length; i++) {
      for (j = i + 1; j < pts.length; j++) {
        var dx = pts[i].x - pts[j].x, dy = pts[i].y - pts[j].y;
        var d2 = dx * dx + dy * dy;
        if (d2 < 8100) {
          ctx.strokeStyle = 'rgba(255,255,255,' + (0.28 * (1 - d2 / 8100)) + ')';
          ctx.beginPath();
          ctx.moveTo(pts[i].x, pts[i].y);
          ctx.lineTo(pts[j].x, pts[j].y);
          ctx.stroke();
        }
      }
    }
  }
  loop();
})();

// ---------- 记账页流星 ----------
(function () {
  var cv = $('mcanvas'), ctx = cv.getContext('2d');
  var W = 0, H = 0, meteors = [], next = 60;
  function resize() { W = cv.width = window.innerWidth; H = cv.height = window.innerHeight; }
  resize();
  window.addEventListener('resize', resize);
  function spawn() {
    meteors.push({
      x: W * (0.35 + Math.random() * 0.65), y: Math.random() * H * 0.25,
      vx: -(5.5 + Math.random() * 4), vy: 3 + Math.random() * 2.2,
      len: 90 + Math.random() * 110, life: 1
    });
  }
  function loop() {
    requestAnimationFrame(loop);
    if (cv.classList.contains('hidden')) return;
    ctx.clearRect(0, 0, W, H);
    if (--next <= 0) { spawn(); next = 110 + Math.random() * 160; }
    for (var i = meteors.length - 1; i >= 0; i--) {
      var m = meteors[i];
      m.x += m.vx; m.y += m.vy; m.life -= 0.008;
      if (m.life <= 0 || m.x < -m.len || m.y > H + m.len) { meteors.splice(i, 1); continue; }
      var tailX = m.x - m.vx * (m.len / 7), tailY = m.y - m.vy * (m.len / 7);
      var g = ctx.createLinearGradient(m.x, m.y, tailX, tailY);
      g.addColorStop(0, 'rgba(255,255,255,' + (0.9 * m.life) + ')');
      g.addColorStop(1, 'rgba(255,255,255,0)');
      ctx.strokeStyle = g;
      ctx.lineWidth = 2.2;
      ctx.lineCap = 'round';
      ctx.beginPath();
      ctx.moveTo(m.x, m.y);
      ctx.lineTo(tailX, tailY);
      ctx.stroke();
      ctx.beginPath();
      ctx.arc(m.x, m.y, 2.1, 0, Math.PI * 2);
      ctx.fillStyle = 'rgba(255,255,255,' + (0.95 * m.life) + ')';
      ctx.fill();
    }
  }
  loop();
})();

// ---------- 启动 ----------
fxSync();
if (PW) enterMain();
</script>
</body>
</html>`;
