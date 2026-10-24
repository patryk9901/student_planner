# Student Planner

Lekka aplikacja do planowania semestru: konta użytkowników, semestry, przedmioty, wydarzenia, kalendarz, statusy i średnia ocen.

## Uruchomienie lokalne

```powershell
python -m pip install -r requirements.txt
python -m uvicorn app.main:app --reload
```

Otwórz `http://localhost:8001`.

## Docker

```powershell
docker compose up --build
```

PostgreSQL działa jako osobny kontener, a dane są przechowywane w wolumenie `postgres_data`. Aplikacja jest dostępna pod `http://localhost:8001`.

## Tailscale

Konfiguracja sidecara jest w `docker-compose.tailscale.yml`. Po ustawieniu `TS_AUTHKEY` w pliku `.env` uruchom:

```powershell
docker compose -f docker-compose.yml -f docker-compose.tailscale.yml up -d --build
```

Tailscale wystawi aplikację przez `tailscale serve` na prywatnej sieci tailnet. Auth key nie jest zapisany w repozytorium.

## Przyjęte założenia MVP

- rejestracja przez login, email i hasło oraz logowanie przez login i hasło;
- każdy użytkownik ma pustą instancję po rejestracji;
- dane każdego użytkownika są izolowane w PostgreSQL;
- semestr ma nazwę i rok akademicki;
- postęp przedmiotu jest liczony jako procent zaliczonych wydarzeń;
- ocena jest dostępna po ukończeniu wszystkich wydarzeń przedmiotu;
- wydarzenia mają status: nierozpoczęte, w toku, zaliczone oraz typ/formę zaliczenia i komentarz.
