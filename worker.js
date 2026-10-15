const ALLOWED_ORIGIN = 'https://sneakerdrop-shop.pages.dev';

function corsHeaders(request) {
  const origin = request.headers.get('Origin') || '';
  const allowed = origin === ALLOWED_ORIGIN ||
    /^https:\/\/[a-z0-9-]+\.sneakerdrop-shop\.pages\.dev$/.test(origin);

  return {
    'Access-Control-Allow-Origin': allowed ? origin : ALLOWED_ORIGIN,
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Telegram-Init-Data',
    'Vary': 'Origin'
  };
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store'
    }
  });
}

class ApiError extends Error {
  constructor(message, status = 400) {
    super(message);
    this.status = status;
  }
}

function supabaseConfig(env) {
  const url = String(env.SUPABASE_URL || '')
    .trim()
    .replace(/\/+$/, '');

  const key = String(
    env.SUPABASE_SERVICE_ROLE_KEY ||
    env.SUPABASE_SECRET_KEY ||
    env.SUPABASE_SERVICE_KEY ||
    ''
  ).trim();

  if (!/^https:\/\/[a-z0-9-]+\.supabase\.co$/i.test(url)) {
    throw new Error('SUPABASE_URL is missing or invalid');
  }

  if (!key) {
    throw new Error('Supabase secret key is missing');
  }

  return { url, key };
}

async function supabase(env, path, options = {}) {
  const { url, key } = supabaseConfig(env);

  const headers = {
    apikey: key,
    'Content-Type': 'application/json',
    ...(key.startsWith('sb_secret_')
      ? {}
      : { Authorization: `Bearer ${key}` }),
    ...(options.headers || {})
  };

  let response;

  try {
    response = await fetch(`${url}/rest/v1/${path}`, {
      ...options,
      headers
    });
  } catch (error) {
    console.error('Supabase network error', String(error));
    throw new Error('Supabase connection failed');
  }

  const raw = await response.text();
  let body;

  try {
    body = raw ? JSON.parse(raw) : null;
  } catch {
    body = raw;
  }

  if (!response.ok) {
    console.error(
      'Supabase request failed',
      response.status,
      body && typeof body === 'object'
        ? String(body.code || body.error || 'unknown').slice(0, 100)
        : 'unknown'
    );

    throw new Error(`Supabase HTTP ${response.status}`);
  }

  return body;
}

function clean(value, max = 200) {
  return String(value ?? '').trim().slice(0, max);
}

function required(value, max = 200) {
  const result = clean(value, max);

  if (!result) {
    throw new ApiError('Заполните обязательные поля');
  }

  return result;
}

function html(value) {
  return String(value).replace(/[&<>"']/g, ch => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;'
  })[ch]);
}

async function telegramUser(env, initData) {
  if (!initData || !env.TELEGRAM_BOT_TOKEN) {
    return null;
  }

  const params = new URLSearchParams(initData);
  const hash = params.get('hash');
  const authDate = Number(params.get('auth_date'));

  if (
    !hash ||
    !/^[0-9a-f]{64}$/i.test(hash) ||
    !Number.isFinite(authDate) ||
    authDate <= 0 ||
    Math.abs(Date.now() / 1000 - authDate) > 86400
  ) {
    return null;
  }

  params.delete('hash');
  params.delete('signature');

  const checkString = [...params.entries()]
    .sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0)
    .map(([key, value]) => `${key}=${value}`)
    .join('\n');

  const encoder = new TextEncoder();

  const baseKey = await crypto.subtle.importKey(
    'raw',
    encoder.encode('WebAppData'),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );

  const secret = await crypto.subtle.sign(
    'HMAC',
    baseKey,
    encoder.encode(env.TELEGRAM_BOT_TOKEN)
  );

  const signingKey = await crypto.subtle.importKey(
    'raw',
    secret,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );

  const signed = new Uint8Array(
    await crypto.subtle.sign(
      'HMAC',
      signingKey,
      encoder.encode(checkString)
    )
  );

  const calculated = [...signed]
    .map(byte => byte.toString(16).padStart(2, '0'))
    .join('');

  let difference = 0;

  for (let i = 0; i < hash.length; i++) {
    difference |= calculated.charCodeAt(i) ^
      hash.toLowerCase().charCodeAt(i);
  }

  if (difference !== 0) {
    return null;
  }

  try {
    const user = JSON.parse(params.get('user') || 'null');

    return user && Number.isSafeInteger(user.id)
      ? user
      : null;
  } catch {
    return null;
  }
}

async function products(env) {
  const result = await supabase(
    env,
    'products?select=id,name,price,description,image_url,category,sizes,active&active=eq.true&order=created_at.desc'
  );

  return json(Array.isArray(result) ? result : []);
}

async function notifySeller(
  env,
  order,
  customer,
  items,
  delivery,
  pickupPoint
) {
  if (!env.TELEGRAM_BOT_TOKEN || !env.TELEGRAM_CHAT_ID) {
    return;
  }

  const details = items.map(item =>
    `\u2022 ${html(item.name)} | ${html(item.size)} | ${item.quantity} \u0448\u0442. \u00d7 ${item.price} \u20bd`
  ).join('\n');

  const text =
    `<b>\u041d\u043e\u0432\u044b\u0439 \u0437\u0430\u043a\u0430\u0437 SNEAKERDROP</b>\n` +
    `\u041d\u043e\u043c\u0435\u0440: <code>${html(order.id)}</code>\n\n` +
    `\u041f\u043e\u043a\u0443\u043f\u0430\u0442\u0435\u043b\u044c: ${html(customer.name)}\n` +
    `\u0422\u0435\u043b\u0435\u0444\u043e\u043d: ${html(customer.phone)}\n` +
    `\u0413\u043e\u0440\u043e\u0434: ${html(customer.city)}\n` +
    `\u0414\u043e\u0441\u0442\u0430\u0432\u043a\u0430: ${html(delivery)}\n` +
    `\u0410\u0434\u0440\u0435\u0441/\u041f\u0412\u0417: ${html(pickupPoint)}\n\n` +
    `${details}\n\n` +
    `<b>\u0418\u0442\u043e\u0433\u043e: ${order.total} \u20bd</b>\n` +
    `\u0421\u0442\u0430\u0442\u0443\u0441: \u041d\u043e\u0432\u044b\u0439`;

  const response = await fetch(
    `https://api.telegram.org/bot${env.TELEGRAM_BOT_TOKEN}/sendMessage`,
    {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json; charset=utf-8'
      },
      body: JSON.stringify({
        chat_id: env.TELEGRAM_CHAT_ID,
        text,
        parse_mode: 'HTML'
      })
    }
  );

  if (!response.ok) {
    console.error(
      'Telegram notification failed',
      response.status
    );
  }
}

async function createOrder(request, env) {
  let input;

  try {
    input = await request.json();
  } catch {
    throw new ApiError('Неверный формат заказа');
  }

  if (
    !input ||
    typeof input !== 'object' ||
    Array.isArray(input)
  ) {
    throw new ApiError('Неверный заказ');
  }

  const customer = {
    name: required(
      input.customer_name ??
      input.customerName ??
      input.name
    ),
    phone: required(
      input.phone ??
      input.customer_phone ??
      input.customerPhone,
      50
    ),
    city: required(
      input.city ??
      input.customer_city,
      120
    )
  };

  const delivery = required(
    input.delivery ??
    input.delivery_service ??
    input.delivery_method ??
    input.deliveryMethod,
    120
  );

  const pickupPoint = required(
    input.address ??
    input.pickup_point ??
    input.pickupPoint ??
    input.pickup ??
    input.pickup_address ??
    input.delivery_address ??
    input.pvz,
    500
  );

  const sourceItems = input.items ?? input.cart;

  if (
    !Array.isArray(sourceItems) ||
    !sourceItems.length ||
    sourceItems.length > 30
  ) {
    throw new ApiError('Корзина пуста или слишком большая');
  }

  const requested = sourceItems.map(item => ({
    id: clean(
      item?.product_id ??
      item?.productId ??
      item?.id,
      80
    ),
    size: clean(item?.size, 20),
    quantity: Number(
      item?.quantity ??
      item?.qty ??
      1
    )
  }));

  if (requested.some(item =>
    !/^[0-9a-fA-F-]{36}$/.test(item.id) ||
    !item.size ||
    !Number.isInteger(item.quantity) ||
    item.quantity < 1 ||
    item.quantity > 20
  )) {
    throw new ApiError(
      'Проверьте товары, размеры и количество'
    );
  }

  const ids = [...new Set(
    requested.map(item => item.id)
  )];

  const catalog = await supabase(
    env,
    `products?select=id,name,price,sizes,active&id=in.(${encodeURIComponent(ids.join(','))})`
  );

  const byId = new Map(
    (catalog || []).map(item => [
      String(item.id),
      item
    ])
  );

  const items = [];

  for (const item of requested) {
    const product = byId.get(item.id);

    if (!product || !product.active) {
      throw new ApiError(
        'Один из товаров больше не продаётся',
        409
      );
    }

    const availability = product.sizes?.[item.size];

    if (
      availability === undefined ||
      availability === false ||
      availability === 0 ||
      availability === '0'
    ) {
      throw new ApiError(
        `Размер ${item.size} недоступен для ${product.name}`,
        409
      );
    }

    if (
      typeof availability === 'number' &&
      item.quantity > availability
    ) {
      throw new ApiError(
        `Недостаточно товара ${product.name}, размер ${item.size}`,
        409
      );
    }

    const price = Number(product.price);

    if (!Number.isFinite(price) || price <= 0) {
      throw new ApiError(
        'Некорректная цена товара',
        409
      );
    }

    items.push({
      product_id: item.id,
      name: product.name,
      size: item.size,
      quantity: item.quantity,
      price
    });
  }

  const total = items.reduce(
    (sum, item) =>
      sum + item.price * item.quantity,
    0
  );

  const initData = clean(
    input.initData ??
    input.init_data ??
    input.telegram_init_data ??
    request.headers.get('X-Telegram-Init-Data'),
    10000
  );

  const user = await telegramUser(env, initData);

  const row = {
    total,
    items,
    status: 'new',
    customer_name: customer.name,
    phone: customer.phone,
    city: customer.city,
    delivery_service: delivery,
    pickup_point: pickupPoint,
    telegram_user_id: user?.id ?? null
  };

  const inserted = await supabase(
    env,
    'orders?select=id,total,status',
    {
      method: 'POST',
      headers: {
        Prefer: 'return=representation'
      },
      body: JSON.stringify(row)
    }
  );

  const order = inserted?.[0];

  if (!order?.id) {
    throw new Error('Order was not saved');
  }

  try {
    await notifySeller(
      env,
      order,
      customer,
      items,
      delivery,
      pickupPoint
    );
  } catch (error) {
    console.error(
      'Telegram notification error',
      String(error)
    );
  }

  return json({
    success: true,
    id: order.id,
    order_id: order.id,
    orderId: order.id,
    total: order.total,
    status: order.status
  }, 201);
}

async function myOrders(request, env) {
  const authorization =
    request.headers.get('Authorization') || '';

  const initData = authorization.startsWith('tma ')
    ? authorization.slice(4)
    : request.headers.get('X-Telegram-Init-Data');

  const user = await telegramUser(env, initData);

  if (!user) {
    throw new ApiError(
      'Откройте магазин через Telegram',
      401
    );
  }

  const rows = await supabase(
    env,
    `orders?select=id,total,items,status,created_at&telegram_user_id=eq.${user.id}&order=created_at.desc&limit=50`
  );

  return json(Array.isArray(rows) ? rows : []);
}

export default {
  async fetch(request, env) {
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        status: 204,
        headers: corsHeaders(request)
      });
    }

    let response;

    try {
      const path =
        new URL(request.url).pathname.replace(/\/$/, '') || '/';

      if (
        request.method === 'GET' &&
        path === '/'
      ) {
        response = json({
          status: 'ok',
          service: 'sneakerdrop-api',
          catalog: '/products',
          orders: '/orders'
        });

      } else if (
        request.method === 'GET' &&
        path === '/products'
      ) {
        response = await products(env);

      } else if (
        request.method === 'POST' &&
        path === '/orders'
      ) {
        response = await createOrder(request, env);

      } else if (
        request.method === 'GET' &&
        path === '/my-orders'
      ) {
        response = await myOrders(request, env);

      } else {
        response = json({
          error: 'Not found'
        }, 404);
      }

    } catch (error) {
      console.error(
        'Worker error',
        String(error)
      );

      if (error instanceof ApiError) {
        response = json({
          error: error.message
        }, error.status);
      } else {
        response = json({
          error: 'Не удалось обработать запрос'
        }, 500);
      }
    }

    const headers = new Headers(response.headers);

    for (const [key, value] of Object.entries(corsHeaders(request))) {
      headers.set(key, value);
    }

    return new Response(response.body, {
      status: response.status,
      headers
    });
  }
};
