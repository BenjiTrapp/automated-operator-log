FROM ubuntu:latest
RUN apt-get update && apt-get install -y auditd systemctl

COPY audit.rules /etc/audit/rules.d/audit.rules

CMD ["/bin/bash"]