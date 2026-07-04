FROM docker.elastic.co/beats/filebeat:8.13.4

USER root
COPY filebeat.yml /usr/share/filebeat/filebeat.yml
RUN chown root:filebeat /usr/share/filebeat/filebeat.yml \
    && chmod go-w /usr/share/filebeat/filebeat.yml

USER filebeat
