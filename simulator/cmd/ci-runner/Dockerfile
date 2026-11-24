# The simulated GitHub Actions runner: ci-runner plus the tools the demo
# workflow's steps run (bash, kubectl, tbot). Build context: ./simulator.

FROM golang:1.27 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/ci-runner ./cmd/ci-runner

FROM debian:trixie-slim
ARG TARGETARCH
# Matches k3s (v1.33) within kubectl's supported version skew.
# Checksums from https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/<arch>/kubectl.sha256;
# update them with the version.
ARG KUBECTL_VERSION=v1.33.5
ARG KUBECTL_SHA256_amd64=6a12d6c39e4a611a3687ee24d8c733961bb4bae1ae975f5204400c0a6930c6fc
ARG KUBECTL_SHA256_arm64=6db7c5d846c3b3ddfd39f3137a93fe96af3938860eefdbf2429805ee1656e381
RUN apt-get update \
 && apt-get install -y --no-install-recommends bash ca-certificates curl jq \
 && rm -rf /var/lib/apt/lists/*
RUN set -eu; \
    case "${TARGETARCH}" in \
      amd64) sha="${KUBECTL_SHA256_amd64}" ;; \
      arm64) sha="${KUBECTL_SHA256_arm64}" ;; \
      *) echo "unsupported TARGETARCH: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    curl -fsSLo /usr/local/bin/kubectl "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/${TARGETARCH}/kubectl"; \
    echo "${sha}  /usr/local/bin/kubectl" | sha256sum --check; \
    chmod +x /usr/local/bin/kubectl
COPY --from=public.ecr.aws/gravitational/teleport-ent-distroless-debug:18.11.7 /usr/local/bin/tbot /usr/local/bin/tbot
COPY --from=build /out/ci-runner /usr/local/bin/ci-runner
ENTRYPOINT ["/usr/local/bin/ci-runner"]
