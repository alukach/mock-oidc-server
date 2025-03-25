FROM python:3.13-slim

EXPOSE 8000

WORKDIR /app

RUN apt-get update && apt-get install -y gcc libpq-dev

COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

COPY app .
COPY pyproject.toml .
COPY uv.lock .

ENV PYTHONUNBUFFERED=1

RUN uv sync --no-dev --locked

CMD ["uv", "run", "--locked", "--no-dev", "python", "-m", "app"]
