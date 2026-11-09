FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        nmap \
        openssh-client \
        python3 \
        sshpass && \
    rm -rf /var/lib/apt/lists/*

ENV PYTHONUNBUFFERED=1

WORKDIR /app

COPY . /app

CMD ["python3", "tv_monitor.py"]
