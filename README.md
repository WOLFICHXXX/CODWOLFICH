# Ветка `bot` — хостинг бота «Автопоход»

Отдельно от сайта. Cloudflare Pages-проект `wolfich-bot` (продакшен-ветка `bot`) → https://wolfich-bot.pages.dev

- `owner.bin` — зашифрованный модуль бота (программа 1.14+ берёт его отсюда; 1.12 — через переадресацию с wolfich-test.pages.dev).
- `tg.html` — пульт в Telegram.
- `get/` — страница скачивания программы https://wolfich-bot.pages.dev/get/ (зеркало: https://storage.yandexcloud.net/wolfich-mirror/get/index.html). Архив собирается в браузере из `get/app/*` + текущего `owner.bin`, поэтому всегда свежий.
- `guide/` — полное руководство https://wolfich-bot.pages.dev/guide/ (зеркало: https://storage.yandexcloud.net/wolfich-mirror/guide/index.html); кнопки «Открыть руководство» и «📖 Полное руководство» в боте ведут сюда.
- `version.json` — номер модуля для страницы; обновлять при каждом выпуске.
- `.github/workflows/mirror.yml` — при каждом пуше в `bot` копирует owner.bin и tg.html в бакет Yandex `wolfich-mirror` (секреты YC_KEY_ID / YC_SECRET / YC_BUCKET репозитория).

Сайт (ветки test/main) файлов бота больше не содержит.
