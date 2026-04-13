# DefectDojo (local)

`django-DefectDojo/` is gitignored here (huge upstream tree). Clone when you need the stack:

```bash
git clone --depth 1 https://github.com/DefectDojo/django-DefectDojo.git labs/lab10/setup/django-DefectDojo
cd labs/lab10/setup/django-DefectDojo
./docker/docker-compose-check.sh || true
docker compose pull && docker compose up -d
docker compose ps
```

UI: `http://localhost:8080` — admin password: `docker compose logs initializer | grep "Admin password:"`  
API key: Profile → API v2 Key, or `docker compose exec uwsgi python manage.py drf_create_token admin`

```bash
cd labs/lab10/setup/django-DefectDojo && docker compose down
```

To refresh `labs/lab10/report/dojo-report.html` from the engagement report page (after Dojo is up): set `DD_PASSWORD` to the admin UI password, then from repo root run `python3 labs/lab10/report/fetch_ui_engagement_report.py` (optional: `DD_ENGAGEMENT_ID`, `DD_BASE`).
