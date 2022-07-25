FROM debian:latest as build

RUN apt update && apt install -y upx-ucl

COPY ./bin/manager-linux-* /tmp/

RUN bash -c 'ARCH=$(uname -m); \
    [ "$ARCH" == "aarch64" ] && ARCH=arm64 || ARCH=amd64; \
    upx -o /manager /tmp/manager-linux-$ARCH'

# Use distroless as minimal base image to package the manager binary
# Refer to https://github.com/GoogleContainerTools/distroless for more details
FROM gcr.io/distroless/static:nonroot

COPY --from=build /manager /manager

USER nonroot:nonroot

ENTRYPOINT ["/manager"]
