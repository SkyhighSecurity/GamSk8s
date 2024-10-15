ARG BASE_IMAGE=redhat/ubi9
ARG BASE_TAG=9.4

FROM ${BASE_IMAGE}:${BASE_TAG}
LABEL org.opencontainers.image.source https://github.com/skyhighsecurity/gamsk8s

WORKDIR /

RUN dnf update -y --nodocs && \
    dnf upgrade -y --nodocs && \
    ## use native/builtin libnet
    dnf -y clean all && \ 
    rm -rf /var/cache/dnf

COPY gam /gam
COPY scripts/entrypoint.sh /usr/local/bin/

RUN chmod go-w /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

EXPOSE 8080/tcp

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
