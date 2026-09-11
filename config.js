/* ═══════════════════════════════════════════════════════════════════
   CRYSTALLIUM — Конфигурация приложения
   ═══════════════════════════════════════════════════════════════════ */
window.APP_CONFIG = {
  // Идентификатор рекламного блока в AdsGram
  ADSGRAM_BLOCK_ID: "47308",
  
  // Режим отладки рекламы (поставьте true для тестирования в обычном браузере на ПК)
  ADSGRAM_DEBUG: false,

  // TonConnect
  TON_MANIFEST: "https://crystallium-bot.onrender.com/tonconnect-manifest.json",

  // Оплата TON / USDT / Stars
  ENABLE_USDT: false,
  TON_PRICE_NANO: 1500000000,
  TON_PRICE_LABEL: "1.5 TON",
  STARS_INVOICE: "",
  STARS_PRICE: 100,

  // Сервер проверки платежей и аналитики на Render
  PAY_API: "https://crystallium-bot.onrender.com",

  // Флаг обязательной проверки платежей (поставлен false для предотвращения ошибок из-за засыпания бесплатного сервера Render)
  REQUIRE_SERVER_PAYMENT: false,

  // Эндпоинт отправки аналитики
  ANALYTICS_ENDPOINT: "https://crystallium-bot.onrender.com/api/events"
};
