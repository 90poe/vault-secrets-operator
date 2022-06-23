# Copy artifact
FROM debian:latest as builder

COPY bin/manager-linux-* /
RUN bash -c 'apt-get update && apt-get install -y upx; \
    ARCH=$(uname -m); \
    [[ "$ARCH" == "aarch64" ]] && ARCH=arm64 || ARCH=amd64; \
    upx -o /manager /manager-linux-$ARCH'

# Use distroless as minimal base image to package the manager binary
# Refer to https://github.com/GoogleContainerTools/distroless for more details
FROM gcr.io/distroless/static:nonroot
WORKDIR /
COPY --from=builder /manager .
USER 65532:65532

ENTRYPOINT ["/manager"]
