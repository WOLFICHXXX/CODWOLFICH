# Cloudflare Workers

`wolfich-license/worker.js` и `wolfich-notify/worker.js` — копия кода Worker'ов, как он развёрнут в Cloudflare.
Выкладка — через коннектор Cloudflare API (PUT /accounts/<id>/workers/scripts/<имя>/content — только код,
привязки KV/D1, переменные и секреты не трогаются). Перед правкой код всегда забирается из Cloudflare заново.
