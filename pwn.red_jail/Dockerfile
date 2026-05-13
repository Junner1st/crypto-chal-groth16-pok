FROM python:3.13-slim AS base

RUN pip install --no-cache-dir py_ecc==8.0.0
WORKDIR /app
COPY server.py run
RUN chmod +x /app/run

FROM pwn.red/jail
COPY --from=base / /srv
ENV JAIL_TIME=300 JAIL_MEM=256M JAIL_CPU=1000 JAIL_ENV_PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
