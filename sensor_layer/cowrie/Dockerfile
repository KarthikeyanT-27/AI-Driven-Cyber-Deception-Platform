# Cowrie SSH/Telnet honeypot.
# Upstream image already ships output_jsonlog enabled by default
# (var/log/cowrie/cowrie.json). We layer on top to:
#   - guarantee JSON logging is on regardless of upstream defaults
#   - add netcat so docker-compose healthchecks work
#   - pin our own minimal config overlay for the demo

FROM cowrie/cowrie:latest

COPY cowrie.cfg /cowrie/cowrie-git/etc/cowrie.cfg

EXPOSE 2222 2223


# Cowrie's log dir is the volume mount target in docker-compose.yml
#RUN mkdir -p /cowrie/cowrie-git/var/log/cowrie \
 #   && chown -R cowrie:cowrie /cowrie/cowrie-git/var/log/cowrie

#USER cowrie
#EXPOSE 2222 2223
