# These three ARGs must point to an Iron Bank image - the BASE_REGISTRY should always be what is written below; please use \
# '--build-arg' when building locally to replace these values
# If your container is not based on either the ubi7/ubi8 Iron Bank images, then it should be based on a different Iron Bank image
# Note that you will not be able to pull containers from nexus-docker-secure.levelup-dev.io into your local dev machine 
ARG BASE_IMAGE=redhat/ubi9
ARG BASE_TAG=9.4

# FROM statement must reference the base image using the three ARGs established
#FROM ${BASE_REGISTRY}/${BASE_IMAGE}:${BASE_TAG} as base
FROM ${BASE_IMAGE}:${BASE_TAG}

WORKDIR /

# Update and clean up
RUN dnf update -y --nodocs && \
    dnf upgrade -y --nodocs && \
    ## dnf install -y --nodocs libnet && \
    dnf -y clean all && \ 
    rm -rf /var/cache/dnf

COPY gam /gam
COPY scripts/entrypoint.sh /usr/local/bin/

RUN chmod go-w /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

EXPOSE 8080/tcp

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
