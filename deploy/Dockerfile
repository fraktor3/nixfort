# NIXFORT controller image (web / workers / beat). Same OS family as managed nodes.
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# nmap/tshark: fixed-profile adapters; pango/harfbuzz/fonts: WeasyPrint PDF with Cyrillic.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      python3 python3-venv ca-certificates nmap tshark \
      libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz0b libharfbuzz-subset0 fonts-dejavu-core \
 && rm -rf /var/lib/apt/lists/*

RUN useradd --system --uid 10001 --create-home --home-dir /home/nixfort nixfort

WORKDIR /srv/nixfort
COPY pyproject.toml ./
ARG INSTALL_DEV=1
RUN python3 -m venv /opt/venv \
 && /opt/venv/bin/pip install --no-cache-dir --upgrade pip \
 && if [ "$INSTALL_DEV" = "1" ]; then /opt/venv/bin/pip install --no-cache-dir ".[pdf,dev]"; \
    else /opt/venv/bin/pip install --no-cache-dir ".[pdf]"; fi

COPY app/ ./app/
COPY agent/ ./agent/
COPY conftest.py ./
COPY tests/ ./tests/
COPY deploy/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod 0755 /usr/local/bin/entrypoint.sh \
 && mkdir -p /var/lib/nixfort /srv/nixfort/app/staticfiles \
 && chown -R nixfort:nixfort /var/lib/nixfort /srv/nixfort/app/staticfiles

ENV PATH=/opt/venv/bin:$PATH \
    DJANGO_SETTINGS_MODULE=config.settings.prod \
    NIXFORT_DATA_DIR=/var/lib/nixfort

USER nixfort
WORKDIR /srv/nixfort/app
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["web"]
