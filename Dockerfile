FROM python:3.12-slim
RUN useradd -m -u 10001 codeguard
WORKDIR /app
COPY pyproject.toml README.md ./
COPY codeguard ./codeguard
RUN pip install --no-cache-dir .
USER codeguard
ENV CODEGUARD_SANDBOX=none CODEGUARD_DATA=/data
EXPOSE 8080
# NOTE: inside this container customer tests are NOT executed (no Docker sandbox available) - scan-only mode.
CMD ["python", "-m", "codeguard", "serve", "--host", "0.0.0.0", "--port", "8080"]
