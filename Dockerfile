FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    HOST=0.0.0.0 \
    PORT=8080 \
    DATA_DIR=/data

WORKDIR /app

# 纯标准库实现，无第三方依赖；仅拷贝源码与测试
COPY app/ ./app/
COPY tests/ ./tests/
COPY scripts/ ./scripts/

RUN mkdir -p /data && python -m compileall -q app tests scripts

EXPOSE 8080

HEALTHCHECK --interval=5s --timeout=3s --start-period=3s --retries=10 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=2)" || exit 1

CMD ["python", "-m", "app.server"]
