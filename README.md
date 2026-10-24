# Ветка `bot` — хостинг бота «Автопоход»

Отдельно от сайта. Cloudflare Pages-проект `wolfich-bot` (продакшен-ветка `bot`) → https://wolfich-bot.pages.dev

- `owner.bin` — зашифрованный модуль бота (программа 1.14+ берёт его отсюда; 1.12 — через переадресацию с wolfich-test.pages.dev).
- `tg.html` — пульт в Telegram.
- `.github/workflows/mirror.yml` — при каждом пуше в `bot` копирует owner.bin и tg.html в бакет Yandex `wolfich-mirror` (секреты YC_KEY_ID / YC_SECRET / YC_BUCKET репозитория).

Сайт (ветки test/main) файлов бота больше не содержит.
