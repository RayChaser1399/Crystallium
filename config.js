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

  // Ваш TON-кошелёк (мерчант) — сюда приходят платежи за отключение рекламы
  TON_ADDR: "UQDD75z4Q_jxvFd8O3lMgWEuBtRiIK_CCC6RZI1RYABbnG-K",

  // Оплата TON / USDT / Stars
  ENABLE_USDT: false,
  TON_PRICE_NANO: 1500000000,
  TON_PRICE_LABEL: "1.5 TON",
  STARS_INVOICE: "",
  STARS_PRICE: 100,

  // Сервер проверки платежей и аналитики на Render
  PAY_API: "https://crystallium-bot.onrender.com",

  // Раньше этот флаг включал/выключал бесплатную демо-активацию без
  // сервера. Демо-ветку теперь убрали из кода совсем — без PAY_API
  // кнопка "Я оплатил" просто покажет ошибку, бесплатно активировать
  // "без рекламы" больше нельзя в принципе. Поле оставлено для
  // обратной совместимости, на работу сейчас не влияет.
  REQUIRE_SERVER_PAYMENT: true,

  // Эндпоинт отправки аналитики
  ANALYTICS_ENDPOINT: "https://crystallium-bot.onrender.com/api/events"
};
