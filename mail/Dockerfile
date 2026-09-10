# Copyright (c) Privasys. All rights reserved.
# Licensed under the GNU Affero General Public License v3.0.
#
# The measured image. Its digest is the connector's identity: a holder approves
# an app id, and the platform pins the digest behind it, so what is built here
# is what a wallet screen is talking about.

FROM golang:1.26-alpine AS build
WORKDIR /src

# Dependencies first, as their own layer, so a source change does not re-fetch
# the module graph. -mod=readonly because a build that can edit go.mod can
# quietly ship a different dependency than the one that was reviewed.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Static, stripped, and with the build paths trimmed. -trimpath matters beyond
# tidiness: absolute paths from the build machine make the binary, and so the
# image digest, depend on where it happened to be built.
ENV CGO_ENABLED=0 GOOS=linux
RUN go build -mod=readonly -trimpath -ldflags="-s -w" \
      -o /out/mail-connector ./cmd/mail-connector

# ---------------------------------------------------------------------------

FROM alpine:3.21

# Certificates only. Nothing else: no shell utilities to be borrowed, no
# package manager left armed. A connector holds a mailbox credential, so the
# image should contain the least that can still serve.
RUN apk add --no-cache ca-certificates tzdata \
 && addgroup -g 10001 -S app \
 && adduser -u 10001 -S -G app app

COPY --from=build /out/mail-connector /usr/local/bin/mail-connector

USER 10001:10001

# The platform allocates the port and passes it as $PORT. 8080 is reserved and
# an app that hard-codes a port does not start; EXPOSE here is documentation
# for a local run, not a promise about the deployment.
ENV PORT=8000
EXPOSE 8000

# The manifest travels with the image, so the control plane learns the tool
# catalogue from the thing that was actually built rather than from something
# uploaded beside it.
#
# It arrives as a build argument rather than being pasted here, because a
# second copy of the catalogue in this file would drift from privasys.json and
# nothing would notice until an agent called a tool that did not exist. Build
# with ./build.sh, which reads the one copy. A build without it produces an
# image the control plane will not accept, which is the right way to fail.
ARG MANIFEST
LABEL org.privasys.manifest=$MANIFEST
LABEL org.opencontainers.image.source="https://github.com/Privasys/connectors"
LABEL org.opencontainers.image.title="Privasys Mail Connector"
LABEL org.opencontainers.image.description="Reads one mailbox on behalf of one attested agent, under a capability the holder approved. Cannot send."
LABEL org.opencontainers.image.licenses="AGPL-3.0-only"

ENTRYPOINT ["/usr/local/bin/mail-connector"]
