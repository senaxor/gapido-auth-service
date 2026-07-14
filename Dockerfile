FROM python:3.12-slim

# Never run as root inside the container.
RUN useradd --create-home --shell /usr/sbin/nologin app

WORKDIR /app
COPY pyproject.toml ./
COPY src ./src
RUN pip install --no-cache-dir . && rm -rf /root/.cache

USER app

# Overridden to `python -m gapido_auth.worker` for the worker container.
CMD ["python", "-m", "gapido_auth.server"]
