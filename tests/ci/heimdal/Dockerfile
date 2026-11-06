FROM debian:bookworm-slim
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends heimdal-kdc heimdal-clients && rm -rf /var/lib/apt/lists/*
COPY krb5.conf /etc/krb5.conf
COPY kdc.conf /etc/heimdal-kdc/kdc.conf
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
EXPOSE 88
CMD ["/entrypoint.sh"]
