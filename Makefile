COMPOSE=docker compose

up:
	$(COMPOSE) up --build -d

down:
	$(COMPOSE) down

logs:
	$(COMPOSE) logs -f --tail=100

test:
	$(COMPOSE) exec backend pytest backend/tests -q

scan:
	bash scripts/run-scan.sh

lint:
	$(COMPOSE) exec backend ruff check backend engine ismsp
	$(COMPOSE) exec backend black --check backend engine ismsp

migrate:
	$(COMPOSE) exec backend alembic upgrade head

seed:
	$(COMPOSE) exec backend python scripts/seed-dummy-data.py
