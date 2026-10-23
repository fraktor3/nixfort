# NIXFORT — commands for the controller VM (nx-controller). Windows: use only `make test` equivalents in README.
COMPOSE = docker compose

.PHONY: help env tls keys up down restart logs ps createadmin itest selfcheck test lint shell

help:
	@echo "env | tls | keys | up | down | restart | logs | ps | createadmin | selfcheck | itest | test | lint"

env:            ## create .env with random secrets
	python3 deploy/gen-env.py

tls:            ## self-signed TLS certificate for nginx
	sh deploy/gen-selfsigned.sh

keys:           ## controller SSH key for the node agent (readable by container uid 10001)
	@mkdir -p secrets
	@if [ ! -f secrets/controller_ed25519 ]; then ssh-keygen -q -t ed25519 -N "" -C nixfort-controller -f secrets/controller_ed25519; fi
	sudo chown 10001:10001 secrets/controller_ed25519 && sudo chmod 400 secrets/controller_ed25519
	@echo "public key: secrets/controller_ed25519.pub"

up:
	$(COMPOSE) up -d --build

down:
	$(COMPOSE) down

restart:
	$(COMPOSE) restart web worker-readonly worker-mutation beat

logs:
	$(COMPOSE) logs -f --tail=100

ps:
	$(COMPOSE) ps

createadmin:
	$(COMPOSE) exec web python manage.py createadmin

selfcheck:      ## end-to-end check of the running controller (DB, Redis auth, both queues, tools, key)
	$(COMPOSE) exec web python manage.py selfcheck
	$(COMPOSE) exec worker-mutation python manage.py selfcheck --key

itest:          ## all tests inside the web container (PostgreSQL + Redis available)
	$(COMPOSE) exec -e DJANGO_SETTINGS_MODULE=config.settings.test web /usr/local/bin/entrypoint.sh pytest -q -p no:cacheprovider

test:           ## unit tests on the host (needs a venv with .[dev])
	pytest -q -m "not integration"

lint:
	ruff check . && ruff format --check .
