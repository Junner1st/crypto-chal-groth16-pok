FROM python:3.13-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends xinetd \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir py_ecc==8.0.0 \
    && useradd --create-home --home-dir /home/ctf --shell /usr/sbin/nologin ctf

WORKDIR /app
COPY share/server.py /app/server.py
COPY run /app/run
COPY xinetd.conf /etc/xinetd.conf
COPY groth16-pok.xinetd /etc/xinetd.d/groth16-pok

RUN chmod 0555 /app/run /app/server.py \
    && chown -R root:root /app /etc/xinetd.conf /etc/xinetd.d/groth16-pok

EXPOSE 5000

USER ctf

CMD ["xinetd", "-dontfork", "-f", "/etc/xinetd.conf"]