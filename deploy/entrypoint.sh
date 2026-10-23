#!/bin/sh
# Role-based entrypoint. Never runs as root (USER nixfort in the image).
set -eu
ROLE="${1:-web}"
case "$ROLE" in
  web)
    python manage.py migrate --noinput
    python manage.py collectstatic --noinput -v0
    exec gunicorn config.wsgi:application --bind 0.0.0.0:8000 --workers 3 --timeout 60 \
         --forwarded-allow-ips='*' --access-logfile - --error-logfile -
    ;;
  worker-readonly)
    exec celery -A config worker -Q readonly -c 4 -n readonly@%h --loglevel=INFO
    ;;
  worker-mutation)
    exec celery -A config worker -Q mutation -c 1 -n mutation@%h --loglevel=INFO
    ;;
  beat)
    exec celery -A config beat --schedule /var/lib/nixfort/celerybeat-schedule --loglevel=INFO
    ;;
  manage)
    shift
    exec python manage.py "$@"
    ;;
  pytest)
    shift
    cd /srv/nixfort && exec pytest "$@"
    ;;
  *)
    echo "unknown role: $ROLE" >&2
    exit 64
    ;;
esac
