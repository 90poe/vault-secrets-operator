FROM alpine:latest as build

RUN apk update && apk add bash

COPY ./bin/manager-linux-* /tmp/

RUN bash -c 'ARCH=$(uname -m); \
    [ "$ARCH" == "aarch64" ] && ARCH=arm64 || ARCH=amd64; \
    cp /tmp/manager-linux-$ARCH /manager'

# Use distroless as minimal base image to package the manager binary
# Refer to https://github.com/GoogleContainerTools/distroless for more details
FROM gcr.io/distroless/static:nonroot

COPY --from=build /manager /manager

USER nonroot:nonroot

ENTRYPOINT ["/manager"]
