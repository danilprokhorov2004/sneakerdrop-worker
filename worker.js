const ALLOWED_ORIGIN = 'https://sneakerdrop-shop.pages.dev';

const STATUSES = {
  new: 'Новый',
  confirmed: 'Подтверждён',
  shipped: 'Отправлен',
  delivered: 'Доставлен',
  cancelled: 'Отменён'
};

const STATUS_BUTTONS = [
  [
    { text: '✅ Подтвердить', status: 'confirmed' },
    { text: '🚚 Отправлен', status: 'shipped' }
  ],
  [
    { text: '📦 Доставлен', status: 'delivered' },
    { text: '❌ Отменить', status: 'cancelled' }
  ]
];

function corsHeaders(request) {
  const origin = request.headers.get('Origin') || '';

  const allowed =
    origin === ALLOWED_ORIGIN ||
    /^https:\/\/[a-z0-9-]+\.sneakerdrop-shop\.pages\.dev$/.test(origin);

  return {
    'Access-Control-Allow-Origin':
      allowed ? origin : ALLOWED_ORIGIN,
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers':
      'Content-Type, Authorization, X-Telegram-Init-Data',
    Vary: 'Origin'
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

  const response = await fetch(
    `${url}/rest/v1/${path}`,
    {
      ...options,
      headers
    }
  );

  const raw = await response.text();
  let body;

  try {
    body = raw ? JSON.parse(raw) : null;
  } catch {
    body = raw;
  }

  if (!response.ok) {
    console.error(
      'Supabase error',
      response.status,
      body && typeof body === 'object'
        ? String(body.code || body.error || 'unknown')
        : 'unknown'
    );

    throw new Error(`Supabase HTTP ${response.status}`);
  }

  return body;
}

// Telegram Mini App authorization.
// Сохраняем signature при проверке hash.
async function telegramAuthResult(env, initData) {
  if (!initData) {
    return {
      user: null,
      reason: 'INIT_DATA_MISSING'
    };
  }

  if (!env.TELEGRAM_BOT_TOKEN) {
    return {
      user: null,
      reason: 'BOT_TOKEN_MISSING'
    };
  }

  const params = new URLSearchParams(initData);
  const hash = params.get('hash');
  const authDate = Number(params.get('auth_date'));

  if (!hash || !/^[0-9a-f]{64}$/i.test(hash)) {
    return {
      user: null,
      reason: 'HASH_MISSING_OR_INVALID'
    };
  }

  if (!Number.isFinite(authDate) || authDate <= 0) {
    return {
      user: null,
      reason: 'AUTH_DATE_INVALID'
    };
  }

  if (Math.abs(Date.now() / 1000 - authDate) > 86400) {
    return {
      user: null,
      reason: 'INIT_DATA_EXPIRED'
    };
  }

  params.delete('hash');

  const checkString = [...params.entries()]
    .sort(([a], [b]) =>
      a < b ? -1 : a > b ? 1 : 0
    )
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
  const expectedHash = hash.toLowerCase();

  for (let i = 0; i < expectedHash.length; i++) {
    difference |=
      calculated.charCodeAt(i) ^
      expectedHash.charCodeAt(i);
  }

  if (difference !== 0) {
    return {
      user: null,
      reason: 'SIGNATURE_MISMATCH'
    };
  }

  try {
    const user = JSON.parse(
      params.get('user') || 'null'
    );

    if (!user || !Number.isSafeInteger(user.id)) {
      return {
        user: null,
        reason: 'USER_ID_MISSING'
      };
    }

    return { user, reason: null };
  } catch {
    return {
      user: null,
      reason: 'USER_DATA_INVALID'
    };
  }
}

async function telegramUser(env, initData) {
  return (await telegramAuthResult(env, initData)).user;
}

// Получение товаров
async function products(env) {
  const result = await supabase(
    env,
    'products?select=id,name,price,description,image_url,category,sizes,active&active=eq.true&order=created_at.desc'
  );

  return json(Array.isArray(result) ? result : []);
}

// Telegram Bot API
async function telegramApi(env, method, payload) {
  if (!env.TELEGRAM_BOT_TOKEN) {
    throw new Error('TELEGRAM_BOT_TOKEN missing');
  }

  const response = await fetch(
    `https://api.telegram.org/bot${env.TELEGRAM_BOT_TOKEN}/${method}`,
    {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json; charset=utf-8'
      },
      body: JSON.stringify(payload)
    }
  );

  if (!response.ok) {
    console.error(
      'Telegram API HTTP error',
      method,
      response.status
    );

    throw new Error('Telegram API request failed');
  }

  const data = await response.json();

  if (!data.ok) {
    throw new Error('Telegram API returned error');
  }

  return data.result;
}

function orderKeyboard(orderId) {
  return {
    inline_keyboard: STATUS_BUTTONS.map(row =>
      row.map(button => ({
        text: button.text,
        callback_data: `order:${orderId}:${button.status}`
      }))
    )
  };
}

function orderNotificationText(
  order,
  customer,
  items,
  delivery,
  pickupPoint,
  status = 'new'
) {
  const details = items.map(item =>
    `• ${html(item.name)} | ${html(item.size)} | ` +
    `${item.quantity} шт. × ${item.price} ₽`
  ).join('\n');

  return (
    `<b>Заказ SNEAKERDROP</b>\n` +
    `Номер: <code>${html(order.id)}</code>\n\n` +
    `Покупатель: ${html(customer.name)}\n` +
    `Телефон: ${html(customer.phone)}\n` +
    `Город: ${html(customer.city)}\n` +
    `Доставка: ${html(delivery)}\n` +
    `Адрес/ПВЗ: ${html(pickupPoint)}\n\n` +
    `${details}\n\n` +
    `<b>Итого: ${order.total} ₽</b>\n` +
    `<b>Статус: ${STATUSES[status] || status}</b>`
  );
}

// Уведомление о новом заказе
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

  const text = orderNotificationText(
    order,
    customer,
    items,
    delivery,
    pickupPoint
  );

  await telegramApi(env, 'sendMessage', {
    chat_id: env.TELEGRAM_CHAT_ID,
    text,
    parse_mode: 'HTML',
    reply_markup: orderKeyboard(order.id)
  });
}

// Оформление заказа
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
      item?.quantity ?? item?.qty ?? 1
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

  const ids = [
    ...new Set(requested.map(item => item.id))
  ];

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

    const availability =
      product.sizes?.[item.size];

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

// Мои заказы
async function myOrders(request, env) {
  const authorization =
    request.headers.get('Authorization') || '';

  const initData = authorization.startsWith('tma ')
    ? authorization.slice(4)
    : request.headers.get('X-Telegram-Init-Data');

  const result = await telegramAuthResult(
    env,
    initData
  );

  if (!result.user) {
    throw new ApiError(
      `Telegram auth: ${result.reason}`,
      401
    );
  }

  const rows = await supabase(
    env,
    `orders?select=id,total,items,status,created_at&telegram_user_id=eq.${result.user.id}&order=created_at.desc&limit=50`
  );

  return json(
    Array.isArray(rows) ? rows : []
  );
}

// Обработка нажатий кнопок
async function handleTelegramWebhook(request, env) {
  const configuredSecret = String(
    env.TELEGRAM_WEBHOOK_SECRET || ''
  ).trim();

  if (!configuredSecret) {
    throw new ApiError(
      'Webhook secret not configured',
      503
    );
  }

  const providedSecret = request.headers.get(
    'X-Telegram-Bot-Api-Secret-Token'
  ) || '';

  if (providedSecret !== configuredSecret) {
    throw new ApiError('Forbidden', 403);
  }

  const update = await request.json();
  const callback = update.callback_query;

  if (!callback) {
    return json({ ok: true });
  }

  const adminId = String(
    env.TELEGRAM_CHAT_ID || ''
  );

  const senderId = String(
    callback.from?.id || ''
  );

  const chatId = String(
    callback.message?.chat?.id || ''
  );

  if (
    !adminId ||
    senderId !== adminId ||
    chatId !== adminId ||
    callback.message?.chat?.type !== 'private'
  ) {
    await telegramApi(
      env,
      'answerCallbackQuery',
      {
        callback_query_id: callback.id,
        text: 'Нет доступа',
        show_alert: true
      }
    );

    return json({ ok: true });
  }

  const match =
    /^order:([0-9a-fA-F-]{36}):(confirmed|shipped|delivered|cancelled)$/
      .exec(callback.data || '');

  if (!match) {
    await telegramApi(
      env,
      'answerCallbackQuery',
      {
        callback_query_id: callback.id,
        text: 'Неизвестная команда'
      }
    );

    return json({ ok: true });
  }

  const orderId = match[1];
  const newStatus = match[2];

  const orders = await supabase(
    env,
    `orders?select=id,total,items,status,customer_name,phone,city,delivery_service,pickup_point&id=eq.${orderId}&limit=1`
  );

  const order = orders?.[0];

  if (!order) {
    await telegramApi(
      env,
      'answerCallbackQuery',
      {
        callback_query_id: callback.id,
        text: 'Заказ не найден',
        show_alert: true
      }
    );

    return json({ ok: true });
  }

  if (order.status === newStatus) {
    await telegramApi(
      env,
      'answerCallbackQuery',
      {
        callback_query_id: callback.id,
        text: 'Этот статус уже установлен'
      }
    );

    return json({ ok: true });
  }

  await supabase(
    env,
    `orders?id=eq.${orderId}`,
    {
      method: 'PATCH',
      headers: {
        Prefer: 'return=minimal'
      },
      body: JSON.stringify({
        status: newStatus
      })
    }
  );

  const customer = {
    name: order.customer_name,
    phone: order.phone,
    city: order.city
  };

  const text = orderNotificationText(
    order,
    customer,
    order.items || [],
    order.delivery_service,
    order.pickup_point,
    newStatus
  );

  try {
    await telegramApi(
      env,
      'editMessageText',
      {
        chat_id: callback.message.chat.id,
        message_id: callback.message.message_id,
        text,
        parse_mode: 'HTML',
        reply_markup: orderKeyboard(orderId)
      }
    );
  } catch (error) {
    console.error(
      'Telegram message update failed',
      String(error)
    );
  }

  await telegramApi(
    env,
    'answerCallbackQuery',
    {
      callback_query_id: callback.id,
      text: `Статус: ${STATUSES[newStatus]}`
    }
  );

  return json({ ok: true });
}

// Главный обработчик запросов
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
        response = await createOrder(
          request,
          env
        );

      } else if (
        request.method === 'GET' &&
        path === '/my-orders'
      ) {
        response = await myOrders(
          request,
          env
        );

      } else if (
        request.method === 'POST' &&
        path === '/telegram-webhook'
      ) {
        response = await handleTelegramWebhook(
          request,
          env
        );

      // ВРЕМЕННЫЙ МАРШРУТ ДЛЯ ПОДКЛЮЧЕНИЯ WEBHOOK
      } else if (
        request.method === 'POST' &&
        path === '/setup-webhook'
      ) {
        const auth = request.headers.get(
          'Authorization'
        );

        if (
          !env.TELEGRAM_WEBHOOK_SECRET ||
          auth !== `Bearer ${env.TELEGRAM_WEBHOOK_SECRET}`
        ) {
          throw new ApiError(
            'Forbidden',
            403
          );
        }

        const webhookUrl =
          'https://sneakerdrop-api.danil-prokhorov-2004.workers.dev/telegram-webhook';

        const result = await telegramApi(
          env,
          'setWebhook',
          {
            url: webhookUrl,
            secret_token: env.TELEGRAM_WEBHOOK_SECRET,
            allowed_updates: [
              'callback_query'
            ],
            drop_pending_updates: true
          }
        );

        response = json({
          ok: result,
          webhook: webhookUrl
        });

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

    const headers = new Headers(
      response.headers
    );

    for (
      const [key, value]
      of Object.entries(corsHeaders(request))
    ) {
      headers.set(key, value);
    }

    return new Response(
      response.body,
      {
        status: response.status,
        headers
      }
    );
  }
};
