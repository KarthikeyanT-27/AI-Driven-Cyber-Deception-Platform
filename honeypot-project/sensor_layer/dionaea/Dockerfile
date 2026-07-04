# Dionaea malware/exploit-capture honeypot.
# Overlays a log_json ihandler config so every capture event lands as a
# structured JSON line that Filebeat can tail.
FROM dinotools/dionaea:latest

USER root
RUN apt-get update \
    && apt-get install -y --no-install-recommends netcat-traditional \
    && rm -rf /var/lib/apt/lists/* || true

COPY ihandlers-enabled/log_json.yaml /etc/dionaea/ihandlers-enabled/log_json.yaml
COPY dionaea.cfg /etc/dionaea/dionaea.cfg

RUN mkdir -p /opt/dionaea/var/log/dionaea

EXPOSE 21 80 445
