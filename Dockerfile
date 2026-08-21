FROM python:3.12-alpine

RUN apk add --no-cache \
    fping \
    tcpdump \
    traceroute \
    bind-tools \
    iproute2 \
    tzdata \
    && rm -rf /var/cache/apk/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY src/ /app/src/
COPY templates/ /app/templates/
COPY scripts/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh \
    && mkdir -p /data/reports/incidents /data/logs /data/captures

ENV PYTHONPATH=/app/src \
    PYTHONUNBUFFERED=1 \
    NETDIAG_DATA=/data \
    NETDIAG_CONFIG=/app/config.yaml

ENTRYPOINT ["/entrypoint.sh"]
CMD ["analyzer"]
