# Cloudflare Workers

`wolfich-license/worker.js` и `wolfich-notify/worker.js` — код Worker'ов как он развёрнут в Cloudflare.
Выкладка и синхронизация — workflow `.github/workflows/cfworkers.yml`:

- заливка в `test` с изменением `cloudflare/<имя>/worker.js` — выкладывает этот Worker (только код: привязки KV/D1, переменные и секреты остаются как есть);
  перед выкладкой проверяется, что в Cloudflare лежит та же версия, что была в репозитории до изменения. Если код меняли в панели Cloudflare —
  выкладка останавливается, сначала нужен `pull`;
- вручную (Actions → «Cloudflare Workers» → Run workflow): `check` — проверить доступ, `pull` — забрать код из Cloudflare в репозиторий,
  `deploy` — выложить код из репозитория принудительно.

Секреты репозитория: `CF_API_TOKEN` (токен с правом Workers Scripts: Edit), `CF_ACCOUNT_ID`.
