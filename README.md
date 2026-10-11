# КУпАП + Фабули — сервер з спільною БД і захищеною адмінкою

## Що всередині

- **Публічний сайт** — `/` (ваш довідник)
- **Адмінка** — `/admin` (лише з паролем, посилання на сайті **немає**)
- **SQLite** — спільна база для всіх відвідувачів
- **API** — `/api/...`
- **Завантаження картинок** — `/uploads/...`

## Локальний запуск

```bash
cd kupfab-server
npm install
ADMIN_PASSWORD='ваш_надійний_пароль' node server.js
```

Відкрийте:

- Сайт: http://localhost:3000  
- Адмінка: http://localhost:3000/admin  

## Змінні середовища

| Змінна | Опис |
|--------|------|
| `PORT` | Порт (за замовчуванням 3000) |
| `ADMIN_PASSWORD` | Пароль входу в адмінку (**обов’язково змінити**) |
| `ADMIN_SECRET` | Секрет для підпису сесії (довгий випадковий рядок) |
| `NODE_ENV` | `production` на хостингу |

## Деплой на Railway / Render / Fly.io

### Railway

1. Створіть проєкт з цієї папки (GitHub або CLI).
2. Variables:
   - `ADMIN_PASSWORD` = ваш пароль
   - `ADMIN_SECRET` = випадковий рядок (32+ символів)
3. Start command: `npm start`
4. Після деплою: `https://ваш-проєкт.up.railway.app` і `/admin`

### Render

1. **New → Web Service** → підключіть репозиторій.
2. Build: `npm install`
3. Start: `npm start`
4. Додайте env `ADMIN_PASSWORD`, `ADMIN_SECRET`.

### Важливо для SQLite на хостингу

На безкоштовних тарифах файлова система інколи ефемерна (після рестарту БД може скинутись).

- **Railway / Render disk** — підключіть persistent volume на папку `data/`.
- Або перенесіть БД на **Turso** / **Postgres** (наступний крок).

## Безпека адмінки

- URL `/admin` **немає** в меню публічного сайту — знаєте лише ви.
- Вхід тільки з паролем (`ADMIN_PASSWORD`).
- Сесія 7 днів (cookie + Bearer token).
- API змін (`POST/PUT/DELETE`) без токена повертає **401**.

Рекомендація: додатково обмежити `/admin` IP або Cloudflare Access.

## Структура

```
kupfab-server/
  server.js
  package.json
  data/
    seed.json      # початкове заповнення
    kupfab.db      # SQLite (з’явиться після старту)
  public/
    site/index.html
    admin/index.html
    uploads/
```
