# NIXFORT

Self-hosted веб-приложение для аудита, контролируемого усиления и доказательной проверки безопасности Linux-сегмента сети. Выпускная квалификационная работа.

**Начни отсюда:** [`docs/PROJECT_CONTEXT.md`](docs/PROJECT_CONTEXT.md) → [`docs/STATUS.md`](docs/STATUS.md) → [`docs/WORKFLOW.md`](docs/WORKFLOW.md).
Для ИИ-исполнителя (Cursor): [`AGENTS.md`](AGENTS.md).

## Состав репозитория
| Каталог | Что внутри |
|---|---|
| `app/` | Django-приложение контроллера (веб, фоновые задания) |
| `agent/` | Узловой агент (Python stdlib), устанавливается на управляемые узлы |
| `deploy/` | Dockerfile, nginx, entrypoint, генераторы секретов/сертификата |
| `docs/` | Архитектура, протокол, проверки, безопасность, план, карточки задач |
| `lab/` | Отчёты и сценарии испытательного стенда |
| `thesis/` | Материалы текста ВКР |

## Запуск контроллера (nx-controller, Ubuntu 24.04 + Docker)
```bash
make env            # .env со случайными секретами
make tls            # самоподписанный сертификат для nginx
make keys           # SSH-ключ контроллера для агента (доступен контейнеру uid 10001)
make up             # сборка и запуск: postgres, redis, web, 2 воркера, beat, nginx
make ps             # все сервисы healthy/running
make createadmin    # первый администратор (один раз)
```
Веб-интерфейс: `https://10.77.0.10` (со стенда) или `https://127.0.0.1:8443` (с Windows через проброс порта).

## Тесты
```bash
make itest                              # на контроллере, внутри контейнера
pytest -q                               # локально (venv с pip install -e ".[dev]")
cd agent && python3 -m unittest discover -s tests -t .   # агент, только stdlib
```
