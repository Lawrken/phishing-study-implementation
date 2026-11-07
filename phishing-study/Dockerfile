FROM mcr.microsoft.com/playwright/python:v1.63.0-noble

WORKDIR /opt/study
COPY pyproject.toml ./
COPY study ./study
RUN python -m pip install --no-cache-dir '.[analysis]' \
    && python -m pip freeze > /opt/study/installed-dependencies.txt

ENV PYTHONPATH=/workspace PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
WORKDIR /workspace
CMD ["bash", "scripts/validate-linux.sh"]
