#################
# Build Step
#################

FROM alpine:latest as build

RUN apk add --no-cache git make busybox-static dumb-init

# Copy and set permissions for binaries and scripts in build stage
ARG TARGETPLATFORM
COPY assets/start.sh /tmp/start.sh
COPY assets/default-config.cfg /tmp/default-config.cfg
COPY assets/gl.db /tmp/gl.db
COPY assets/$TARGETPLATFORM/glauth /tmp/glauth

# Set execute permissions in build stage where chmod is available
RUN chmod +x /tmp/glauth /tmp/start.sh

#################
# Run Step
#################

FROM gcr.io/distroless/base-debian12 as run

LABEL maintainers="Ben Yanke <ben@benyanke.com>, Jörn Friedrich Dreyer <jfd@butonic.de>, Chris F Ravenscroft <chris@voilaweb.com>" \
      org.opencontainers.image.title="GLauth" \
      org.opencontainers.image.description="A simple LDAP server for development, home use, or CI pipelines" \
      org.opencontainers.image.authors="Ben Yanke, Jörn Friedrich Dreyer, Chris F Ravenscroft" \
      org.opencontainers.image.source="https://github.com/glauth/glauth" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="latest" \
      org.opencontainers.image.url="https://github.com/glauth/glauth"

# Copy docker specific scripts and binaries from build container with correct permissions
COPY --from=build /tmp/start.sh /app/docker/start.sh
COPY --from=build /tmp/default-config.cfg /app/docker/default-config.cfg
COPY --from=build /tmp/gl.db /app/docker/gl.db
COPY --from=build /tmp/glauth /app/glauth

# Just what we need
COPY --from=build /usr/bin/dumb-init /usr/bin/dumb-init
COPY --from=build /bin/busybox.static /bin/sh
COPY --from=build /bin/busybox.static /bin/ln
COPY --from=build /bin/busybox.static /bin/rm
RUN ln /bin/sh /usr/bin/cp && ln /bin/sh /usr/bin/mkdir && rm /bin/ln /bin/rm

# Expose web and LDAP ports
EXPOSE 389 636 5555

ENTRYPOINT ["/usr/bin/dumb-init", "--"]
CMD ["/bin/sh", "/app/docker/start.sh"] 