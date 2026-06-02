FROM nginx:latest

RUN apt-get update && apt-get install -y openssl procps && \
    rm -rf /var/lib/apt/lists/*

# Self-signed TLS cert
RUN openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
      -keyout /etc/nginx/server.key -out /etc/nginx/server.crt \
      -days 3650 -nodes -subj "/CN=localhost"

# Small static files (attack doesn't need them, but realistic config)
RUN echo "ok" > /srv/index.html && \
    dd if=/dev/urandom of=/srv/small.bin bs=1k count=4 2>/dev/null

COPY nginx.conf /etc/nginx/nginx.conf

EXPOSE 443/tcp
CMD ["nginx", "-g", "daemon off;"]
