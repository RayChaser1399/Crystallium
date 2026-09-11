/* ═══════════════════════════════════════════════════════════════════
   CRYSTALLIUM — продакшен-конфигурация
   Единственный файл, который нужно редактировать при смене настроек
   монетизации. После правки — перезалейте на сервер (index.html
   трогать не надо).
   ═══════════════════════════════════════════════════════════════════ */
window.APP_CONFIG = {

  /* AdsGram: реклама включена, blockId получен из кабинета adsgram.ai */
  ADSGRAM_BLOCK_ID: "47308",
  ADSGRAM_DEBUG: false,

  /* TonConnect: манифест отдаётся тем же сервером на Render */
  TON_MANIFEST: "https://crystallium-bot.onrender.com/tonconnect-manifest.json",

  /* USDT (jetton) выключен — проверка jetton-платежей на сервере не
     реализована. Не включайте без доработки server.js (см. README). */
  ENABLE_USDT: false,

  /* Цена «убрать рекламу» в TON */
  TON_PRICE_NANO: 1500000000,
  TON_PRICE_LABEL: "1.5 TON",

  /* Telegram Stars пока выключен — кнопка скрыта в интерфейсе.
     Включить: вписать сюда slug из createInvoiceLink (см. README,
     раздел Telegram Stars) и поставить STARS_INVOICE непустым. */
  STARS_INVOICE: "",
  STARS_PRICE: 100,

  /* Сервер проверки платежей и аналитики — ваш Render-сервис */
  PAY_API: "https://crystallium-bot.onrender.com",

  /* Продакшен: демо-активация «без рекламы» без сервера запрещена —
     «без рекламы» включается только после подтверждённого сервером
     платежа. Работает, только если PAY_API реально отвечает на
     /api/status (проверьте перед раздачей ссылки игрокам!). */
  REQUIRE_SERVER_PAYMENT: true,

  /* Аналитика шлётся на тот же сервер */
  ANALYTICS_ENDPOINT: "https://crystallium-bot.onrender.com/api/events"

};
