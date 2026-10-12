# AI Crawler Access for Wordfence

WordPress-плагин для диагностики доступа AI-краулеров и журналов Wordfence Live Traffic, настройки robots.txt без обхода WAF.

**Версия:** 1.2.1 · **Автор:** Valery Molodtsov · GPL-2.0-or-later.

- [Карточка на ворд-пресс.рф](https://ворд-пресс.рф/plugins/ai-crawler-access-for-wordfence/)
- [GitHub Releases](https://github.com/noice-man/wp-ai-crawler-access-for-wordfence/releases)
- [Установочный архив версии 1.2.1](https://github.com/noice-man/wp-ai-crawler-access-for-wordfence/releases/download/v1.2.1/ai-crawler-access-for-wordfence-v1.2.1.zip)

## Обновления

С версии 1.2.1 используется WPR Update Hub, сервер https://xn----ctbgf6biedka.xn--p1ai. Устанавливайте версию с SDK вручную поверх старой, затем WordPress сможет проверять обновления через Hub. Автообновления включаются отдельно администратором в списке плагинов, телеметрия по умолчанию выключена.

## Ограничения

Обнаруженный по User-Agent бот не обязательно подтверждён. Некоторые запросы блокируются до WordPress и не попадают в журнал. Плагин не вносит IP краулеров в глобальные исключения WAF.
