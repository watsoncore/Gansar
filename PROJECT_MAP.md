# Карта проекта

## Запуск и orchestration

- `main.py` вызывает `app.main.main`.
- `app/main.py` содержит интерактивное меню, переключение языка, очередь, статус источников и экспорт. Страница «О проекте» открывается из `htmlG/about.html`.
- `app/nft_cli.py` разрешает поисковый ввод, связывает NFT с owner dossier и обрабатывает resume, incremental refresh и повторный экспорт. Основной поиск использует максимальный поддерживаемый режим.
- `app/search_runtime.py` и `app/search_worker.py` управляют выполнением и checkpoints. Каталоги `.search_sessions` — рабочие данные, а не исходный код.

## Сбор и анализ

- `app/sources/` — collectors и adapters, включая TON, TRON, EVM, BTC, DOGE и Solana. `app/sources/manager.py` управляет источниками; registry задаёт доступные adapters.
- `app/aggregator/analyzer.py` координирует сбор, объединение результатов, аналитику и создание графа.
- `app/models/report.py` определяет модели отчёта, операций, активов и состояния источников.
- `app/ton_nft/` содержит существующий TON NFT engine; `app/ton_attribution/` — контекст TON-контрактов и отношений.
- `app/attribution/` — сервисные сведения, evidence, правила атрибуции, маршруты и гипотезы. Каталоги `app/attribution/assets` содержат production-данные и не являются временными дампами.
- `app/utils/` — нормализация адресов и активов, HTTP, DNS/identity и вспомогательные функции.

## HTML и графы

- `app/graph/builder.py` формирует graph payload.
- `app/exporters/html.py` — обёртка основного HTML-экспорта; `html_exporter.py` строит представления разделов отчёта.
- `app/exporters/investigation_template.html` содержит интерфейс отчёта, 2D-сеть, 3D-представление, дерево транзакций и инспектор.
- `app/exporters/assets/` содержит JavaScript, CSS, иконки, логотипы и vendor-компоненты с лицензиями и provenance. Эти файлы нужны при запуске из исходников.
- `app/exporters/pdf.py` и `pdf_exporter.py` выполняют необязательный PDF-экспорт.

## Медиа и конфигурация

- `htmlG/` — About, его стили, скрипты, media manifest и ресурсы. Инструкции по файлам находятся в `htmlG/MEDIA_GUIDE.md`.
- `app/exporters/assets/report-backgrounds/` и `app/exporters/assets/report-logos/` содержат постоянные фон и MP4-логотип отчёта. Экспортёр копирует их рядом с HTML в `fon/` и `logo/`. Одноимённые корневые папки — необязательные локальные настройки оформления; `output/fon` и `output/logo` содержат ресурсы созданного отчёта и не являются мусором. `icon_crypto/` и `cryptobot.png` используются существующими сервисными логотипами.
- `requirements.txt` и `pyproject.toml` описывают зависимости. Рекомендуемый запуск из checkout приведён в README.
- Переменные окружения читаются конкретными adapters; автоматического чтения `.env` нет.

## Тесты и локальные данные

`tests/` содержит исходники тестов и небольшие fixtures, включая `tests/fixtures/attribution/` и `tests/fixtures/cross_chain/`. Replay-тесты с необязательными локальными captures могут пропускаться без этих материалов.

`output/`, `.search_sessions/`, `validation/` и исторические case notes исключены из публикации. Они могут содержать расследования, evidence, базы и checkpoints. Исключение из Git не означает разрешение на удаление этих файлов. Некоторые старые технические журналы ссылаются на локальные артефакты и сохраняются в рабочей папке. Десять проверенных пользовательских PNG из `screenshots/` опубликованы и используются в README.

Команды запуска и проверки перечислены в [README](README.md).
