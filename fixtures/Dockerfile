FROM python:3.13.7-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /fixture

RUN groupadd --gid 10002 fixture \
    && useradd --uid 10002 --gid fixture --no-create-home --shell /usr/sbin/nologin fixture

COPY --chown=fixture:fixture adversarial_agent.py /fixture/adversarial_agent.py
USER 10002:10002
ENTRYPOINT ["python3", "/fixture/adversarial_agent.py"]
