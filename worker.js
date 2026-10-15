// SNEAKERDROP API — Cloudflare Worker
// Secrets: SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY (or SUPABASE_SECRET_KEY),
// TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID

const corsHeaders = {
  'Access-Control-Allow-Origin': 'https://sneakerdrop-shop.pages.dev',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  'Vary': 'Origin',
};

function respond(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...corsHeaders, 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' },
  });
}

function sbConfig(env) {
  const url = String(env.SUPABASE_URL || '').replace(/\/$/, '');
  const key = env.SUPABASE_SERVICE_ROLE_KEY || env.SUPABASE_SECRET_KEY || env.SUPABASE_SERVICE_KEY;
  if (!url || !key) throw new Error('Supabase variables are not configured');
  return { url, key };
}

async function sbRequest(env, path, options = {}) {
  const { url, key } = sbConfig(env);
  const res = await fetch(`${url}/rest/v1/${path}`, {
    ...options,
    headers: {
      apikey: key,
      Authorization: `Bearer ${key}`,
      'Content-Type': 'application/json',
      ...(options.headers || {}),
    },
  });
  const raw = await res.text();
  let data;
  try { data = raw ? JSON.parse(raw) : null; } catch { data = raw; }
  if (!res.ok) {
    console.error('Supabase error', res.status, typeof data === 'object' ? data?.code : 'unknown');
    throw new Error(`Database request failed (${res.status})`);
  }
  return data;
}

function str(value, max = 200) { return String(value ?? '').trim().slice(0, max); }
function required(value, max = 200) { const s = str(value, max); if (!s) throw new Error('Заполните обязательные поля'); return s; }
function money(value) { const n = Number(value); return Number.isFinite(n) ? n : 0; }
function escapeHtml(value) { return String(value).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }

async function telegramUser(env, initData) {
  if (!initData || !env.TELEGRAM_BOT_TOKEN) return null;
  const params = new URLSearchParams(initData);
  const hash = params.get('hash');
  const authDate = Number(params.get('auth_date'));
  if (!hash || !Number.isFinite(authDate) || Math.abs(Date.now() / 1000 - authDate) > 86400) return null;
  params.delete('hash');
  const checkString = [...params.entries()].sort(([a],[b]) => a.localeCompare(b)).map(([k,v]) => `${k}=${v}`).join('\n');
  const enc = new TextEncoder();
  const base = await crypto.subtle.importKey('raw', enc.encode('WebAppData'), {name:'HMAC',hash:'SHA-256'}, false, ['sign']);
  const secret = await crypto.subtle.sign('HMAC', base, enc.encode(env.TELEGRAM_BOT_TOKEN));
  const signing = await crypto.subtle.importKey('raw', secret, {name:'HMAC',hash:'SHA-256'}, false, ['sign']);
  const signed = new Uint8Array(await crypto.subtle.sign('HMAC', signing, enc.encode(checkString)));
  const actual = [...signed].map(x => x.toString(16).padStart(2,'0')).join('');
  if (actual.length !== hash.length) return null;
  let diff = 0;
  for (let i = 0; i < hash.length; i++) diff |= actual.charCodeAt(i) ^ hash.toLowerCase().charCodeAt(i);
  if (diff !== 0) return null;
  try { const user = JSON.parse(params.get('user') || 'null'); return user && Number.isSafeInteger(user.id) ? user : null; }
  catch { return null; }
}

async function listProducts(env) {
  const data = await sbRequest(env, 'products?select=id,name,price,description,image_url,category,sizes,active&active=eq.true&order=created_at.desc');
  return respond(data || []);
}

async function sendNotification(env, order, customer, items, delivery, address) {
  if (!env.TELEGRAM_BOT_TOKEN || !env.TELEGRAM_CHAT_ID) {
    console.warn('Telegram notification variables not configured');
    return;
  }
  const itemText = items.map(x => `• ${escapeHtml(x.name)} | ${escapeHtml(x.size)} | ${x.quantity} шт. × ${x.price} ₽`).join('\n');
  const message = `<b>Новый заказ SNEAKERDROP</b>\nНомер: <code>${escapeHtml(order.id)}</code>\n\n` +
    `Покупатель: ${escapeHtml(customer.name)}\nТелефон: ${escapeHtml(customer.phone)}\n` +
    `Город: ${escapeHtml(customer.city)}\nДоставка: ${escapeHtml(delivery)}\n` +
    `Адрес/ПВЗ: ${escapeHtml(address)}\n\n${itemText}\n\n<b>Итого: ${order.total} ₽</b>\nСтатус: Новый`;
  const res = await fetch(`https://api.telegram.org/bot${env.TELEGRAM_BOT_TOKEN}/sendMessage`, {
    method: 'POST', headers: {'Content-Type':'application/json'},
    body: JSON.stringify({chat_id:env.TELEGRAM_CHAT_ID, text:message, parse_mode:'HTML'}),
  });
  if (!res.ok) console.error('Telegram sendMessage failed', res.status);
}

async function createOrder(request, env) {
  let input;
  try { input = await request.json(); } catch { return respond({error:'Неверный формат заказа'},400); }
  if (!input || typeof input !== 'object') return respond({error:'Неверный заказ'},400);
  const customer = {
    name: required(input.customer_name ?? input.customerName ?? input.name),
    phone: required(input.phone ?? input.customer_phone ?? input.customerPhone, 50),
    city: required(input.city ?? input.customer_city, 120),
  };
  const delivery = required(input.delivery ?? input.delivery_method ?? input.deliveryMethod, 120);
  const address = str(input.address ?? input.pickup_point ?? input.pickupPoint ?? input.delivery_address ?? input.pvz, 500);
  const sourceItems = input.items ?? input.cart;
  if (!Array.isArray(sourceItems) || sourceItems.length < 1 || sourceItems.length > 30) return respond({error:'Корзина пуста или слишком большая'},400);

  const requested = sourceItems.map(x => ({
    id: str(x.product_id ?? x.productId ?? x.id, 80),
    size: str(x.size, 20),
    quantity: Number(x.quantity ?? x.qty ?? 1),
  }));
  if (requested.some(x => !x.id || !x.size || !Number.isInteger(x.quantity) || x.quantity < 1 || x.quantity > 20))
    return respond({error:'Проверьте товары, размеры и количество'},400);
  const ids = [...new Set(requested.map(x => x.id))];
  const filters = ids.map(x => `"${x.replace(/["\\]/g,'')}\"`).join(',');
  const products = await sbRequest(env, `products?select=id,name,price,sizes,active&id=in.(${encodeURIComponent(filters)})`);
  const byId = new Map(products.map(x => [String(x.id), x]));
  const items = [];
  for (const x of requested) {
    const product = byId.get(x.id);
    if (!product || !product.active) return respond({error:'Один из товаров больше не продаётся'},409);
    const availability = product.sizes?.[x.size];
    if (availability === undefined || availability === false || availability === 0 || availability === '0')
      return respond({error:`Размер ${x.size} недоступен для ${product.name}`},409);
    if (typeof availability === 'number' && x.quantity > availability)
      return respond({error:`Недостаточно товара ${product.name}, размер ${x.size}`},409);
    const price = money(product.price);
    if (price <= 0) return respond({error:'Некорректная цена товара'},409);
    items.push({product_id:x.id, name:product.name, size:x.size, quantity:x.quantity, price});
  }
  const total = items.reduce((sum, x) => sum + x.price * x.quantity, 0);
  const initData = str(input.initData ?? input.init_data ?? request.headers.get('X-Telegram-Init-Data'), 10000);
  const user = await telegramUser(env, initData);

  // Only use columns known to be present in the SNEAKERDROP orders table.
  const row = {
    total, items, status:'new',
    customer_name:customer.name, phone:customer.phone, city:customer.city,
    delivery, telegram_user_id:user?.id ?? null,
  };
  // The pickup point is included in the notification; save it when the existing schema supports it.
  // Avoid inserting unknown optional column names that would reject the entire order.
  const inserted = await sbRequest(env, 'orders?select=id,total,status', {
    method:'POST', headers:{Prefer:'return=representation'}, body:JSON.stringify(row),
  });
  const order = inserted?.[0];
  if (!order?.id) throw new Error('Order was not saved');
  try { await sendNotification(env, order, customer, items, delivery, address); }
  catch (error) { console.error('Telegram notification error', String(error)); }
  return respond({success:true, id:order.id, order_id:order.id, orderId:order.id, total:order.total, status:order.status},201);
}

async function myOrders(request, env) {
  const auth = request.headers.get('Authorization') || '';
  const initData = auth.startsWith('tma ') ? auth.slice(4) : request.headers.get('X-Telegram-Init-Data');
  const user = await telegramUser(env, initData);
  if (!user) return respond({error:'Откройте магазин через Telegram'},401);
  const rows = await sbRequest(env, `orders?select=id,total,items,status,created_at&telegram_user_id=eq.${user.id}&order=created_at.desc&limit=50`);
  return respond(rows || []);
}

export default {
  async fetch(request, env) {
    if (request.method === 'OPTIONS') return new Response(null, {status:204, headers:corsHeaders});
    try {
      const path = new URL(request.url).pathname.replace(/\/$/,'') || '/';
      if (request.method === 'GET' && path === '/') return respond({status:'ok',service:'sneakerdrop-api',catalog:'/products',orders:'/orders'});
      if (request.method === 'GET' && path === '/products') return await listProducts(env);
      if (request.method === 'POST' && path === '/orders') return await createOrder(request, env);
      if (request.method === 'GET' && path === '/my-orders') return await myOrders(request, env);
      return respond({error:'Not found'},404);
    } catch (error) {
      console.error('Worker error', String(error));
      return respond({error:error.message === 'Заполните обязательные поля' ? error.message : 'Не удалось обработать запрос'},
        error.message === 'Заполните обязательные поля' ? 400 : 500);
    }
  },
};
