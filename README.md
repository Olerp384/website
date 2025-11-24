# Каталог стендов (REST + UI)

Внутреннее веб-приложение для каталогизации стендов, серверов и артефактов. Реализованы роли гостя (чтение) и администратора (CRUD через токен), REST API `/api/v1/...`, хранение в SQLite, контейнеризация и минимальный фронтенд на чистом JS, работающий через API.

## Стек
- Node.js + Express, SQLite (better-sqlite3), JWT авторизация, bcryptjs, multer (загрузка файлов).
- Фронт: статические файлы в `public/` с fetch-запросами к REST API.

## Быстрый старт локально
1) Скопируйте `.env.example` в `.env` и при необходимости измените секреты/порты. По умолчанию создаётся админ `admin/admin`.
2) Установите зависимости:
```bash
npm install
```
3) Запуск:
```bash
npm start
```
Приложение будет на `http://localhost:3000`. UI: `/` (список стендов, карточка, вкладки). API здоровье: `GET /api/v1/health`.

## Docker / docker-compose
```bash
docker-compose up --build
```
Тома монтируются для данных/файлов: `./data`, `./storage`, `./logs`. Настройте переменные окружения для секретов (`JWT_SECRET`, `ADMIN_USERNAME`, `ADMIN_PASSWORD`, `DATABASE_PATH`, `STORAGE_ROOT`).

## Ключевые эндпоинты (все JSON)
- Аутентификация: `POST /api/v1/auth/login {username,password}` → `{token}`, `POST /api/v1/auth/logout`.
- Стенды: `GET/POST /api/v1/stands`, `GET/PUT/DELETE /api/v1/stands/:id`, фильтры `q,status,tag`.
- Документы: `GET/POST /api/v1/stands/:stand_id/documents` (multipart), `GET/PUT/DELETE /api/v1/documents/:id`, скачивание `/documents/:id/download`, inline контент `GET/PUT /documents/:id/content`.
- Серверы: `GET/POST /api/v1/stands/:stand_id/servers`, глобально `GET /api/v1/servers` + фильтры, `GET/PUT/DELETE /api/v1/servers/:id`.
- ВМ: `GET/POST /api/v1/stands/:stand_id/vms`, глобально `GET /api/v1/vms`, `GET/PUT/DELETE /api/v1/vms/:id`; группы ВМ: аналогично `/vm-groups`.
- Дистрибутивы: `GET/POST /api/v1/stands/:stand_id/distributions`, `GET/PUT/DELETE /api/v1/distributions/:id`, версии `GET/POST /api/v1/distributions/:id/versions`, `GET/PUT/DELETE /api/v1/distribution-versions/:id`, скачивание `/distribution-versions/:id/download`.
- Схема: `GET/PUT /api/v1/stands/:stand_id/graph`, а также CRUD для узлов/рёбер.
- Поиск: `GET /api/v1/search?q=...&type=stand|vm|server|distribution|document`.

Все изменяющие операции требуют заголовок `Authorization: Bearer <token>` (админ). Пароли хешируются, логирование действий админа пишется в `logs/app.log` (JSONL).

## UI
Страница `public/index.html`:
- Список стендов с фильтрами, создание стенда (для админа).
- Карточка стенда с вкладками: инфо (редактирование), документы (загрузка, скачивание, inline-редактирование), железо, ВМ (быстрая SSH-ссылка `ssh://`), дистрибутивы (версии с загрузкой/скачиванием), схема (редактирование JSON-модели).
- Авторизация в хедере — токен сохраняется в localStorage и добавляется ко всем запросам.

## Структура
- `server.js` — приложение Express, миграции SQLite, все REST-роуты, загрузка файлов, логирование.
- `public/` — статика UI.
- `data/` — SQLite база (создаётся автоматически).
- `storage/documents/` — файлы документов/версий (монтируется в docker-compose).
- `logs/app.log` — журнал ошибок и аудита.
