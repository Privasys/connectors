# Copyright (c) Privasys. All rights reserved.
# Licensed under the GNU Affero General Public License v3.0.
#
# The measured image. Its digest is the connector's identity: a holder approves
# an app id, and the platform pins the digest behind it, so what is built here
# is what a wallet screen is talking about.

FROM golang:1.26-alpine AS build
WORKDIR /build/files

# Dependencies first, as their own layer, so a source change does not re-fetch
# the module graph. -mod=readonly because a build that can edit go.mod can
# quietly ship a different dependency than the one that was reviewed.
# The sdk is built from this repository beside the connector (a replace
# directive in go.mod), so its module file is needed before the download and
# its source before the build.
COPY sdk/go.mod /build/sdk/go.mod
COPY files/go.mod files/go.sum ./
RUN go mod download

COPY sdk /build/sdk
COPY files .

# Static, stripped, and with the build paths trimmed. -trimpath matters beyond
# tidiness: absolute paths from the build machine make the binary, and so the
# image digest, depend on where it happened to be built.
ENV CGO_ENABLED=0 GOOS=linux
RUN go build -mod=readonly -trimpath -ldflags="-s -w" \
      -o /out/files-connector ./cmd/files-connector

# ---------------------------------------------------------------------------

FROM alpine:3.21

# Certificates only. Nothing else: no shell utilities to be borrowed, no
# package manager left armed. A connector holds file-store sign-ins in its
# memory while it runs, so the image should contain the least that can still
# serve.
RUN apk add --no-cache ca-certificates tzdata

COPY --from=build /out/files-connector /usr/local/bin/files-connector

# No USER directive, deliberately, and it cost a failed deploy to learn why.
#
# The platform mounts the app's encrypted volume at /data owned by root, so a
# container that drops to an unprivileged uid cannot create the one directory
# it needs (the configuration file; no holder data ever goes there) and fails
# at configure time with a permission error that looks nothing like its
# cause. Enclave app containers run as uid 0 WITHOUT CAP_SYS_ADMIN and with a
# masked /proc; the enclave, not the uid, is the tenancy boundary here.
#
# Revisit if the runtime ever hands the volume over with an owner: dropping
# privilege inside the container would be worth having, it is simply not
# something this image can arrange on its own.

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
# The two sign-in routes are the only ones a plain browser reaches: the holder's
# phone opens /v1/oauth/start in a system browser, and the provider redirects
# back to /v1/oauth/callback. Every other path stays sealed, so the gateway sees
# no file and no credential. Declared here because the label is measured: a
# verifier reads from the image exactly which paths this connector serves in the
# clear. Both are GET, which is all the runtime exempts.
LABEL org.privasys.static-unsealed-prefixes="/v1/oauth/"
LABEL org.opencontainers.image.source="https://github.com/Privasys/connectors"
LABEL org.opencontainers.image.title="Privasys Files Connector"
LABEL org.opencontainers.image.description="Reads one file store (OneDrive and SharePoint, or Google Drive) on behalf of one attested agent, under a capability the holder approved, and writes only into its own folder there. Never deletes, moves, renames or shares."
LABEL org.opencontainers.image.licenses="AGPL-3.0-only"

ENTRYPOINT ["/usr/local/bin/files-connector"]
