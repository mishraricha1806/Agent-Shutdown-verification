FROM python:3.13.7-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN groupadd --gid 10001 asv \
    && useradd --uid 10001 --gid asv --no-create-home --shell /usr/sbin/nologin asv \
    && mkdir -p /data \
    && chown asv:asv /data

COPY --chown=asv:asv asv/ /app/asv/

USER 10001:10001
EXPOSE 8080

ENTRYPOINT ["python3", "-m", "asv.server"]
CMD ["--host", "0.0.0.0", "--port", "8080", "--database", "/data/asv.db"]
