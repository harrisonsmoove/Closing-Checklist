# Closing Checklist: Schlotzsky's University

A phone-friendly nightly closing checklist. Managers unlock it with a store PIN, tap tasks as they close, and see each other's checkmarks within a few seconds. The owner unlocks list editing with a separate owner PIN. A fresh list starts every morning at 5 AM (Central time), and each night is saved to History.

It runs on DigitalOcean App Platform with a development database. No accounts or sign-ins are needed beyond the PINs.

## Settings

Set these in DigitalOcean under your app's **Settings → Environment variables**.

| Name | Required | What it is |
| --- | --- | --- |
| `STORE_PIN` | Yes | PIN closing managers type in. Use 6 or more digits. |
| `OWNER_PIN` | Yes | Different PIN that also unlocks editing the task list. |
| `DATABASE_URL` | Yes | `${db.DATABASE_URL}`, where `db` is your dev database's name. |
| `RESTAURANT_NAME` | No | Name at the top of the app. Default: Schlotzsky's University. |
| `TIMEZONE` | No | Time zone for the 5 AM reset. Default: `America/Chicago`. |

Changing either PIN signs every phone out, so everyone types the new PIN once.

## Files

- `server.js`: the web server and API. It creates its database tables on first run and loads the default 46 tasks.
- `public/index.html`: the app page.
- `package.json` and `package-lock.json`: what DigitalOcean installs.

## Run it on your own computer (optional)

Requires Node.js 22 and a PostgreSQL database.

```
npm install
STORE_PIN=246810 OWNER_PIN=135790 DATABASE_URL=postgresql://user:password@localhost:5432/closing npm start
```

Then open http://localhost:8080.
