FROM alpine:3.19

RUN apk add --no-cache \
        nmap \
        nmap-nping \
        nmap-scripts \
        curl \
        ffuf \
        jq \
        grep \
        ripgrep \
        bash \
        ca-certificates \
    && mkdir -p /app/workspace /app/reports /app/rules /app/payloads \
    && chown -R nobody:nobody /app

COPY angular2-rules.json /app/rules/angular2-rules.json
COPY angular2-payloads.json /app/payloads/angular2-payloads.json
COPY angularjs-rules.json /app/rules/angularjs-rules.json
COPY angularjs-payloads.json /app/payloads/angularjs-payloads.json
# Legacy compat symlinks (orchestrator v2.0 fallback)
COPY angular-rules.json /app/rules/angular-rules.json
COPY angular-payloads.json /app/payloads/angular-payloads.json

USER nobody
WORKDIR /app/workspace

CMD ["/bin/bash"]