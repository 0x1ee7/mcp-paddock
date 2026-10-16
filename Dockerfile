# syntax=docker/dockerfile:1
FROM golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/ ./cmd/...

# Static binaries on distroless: no shell, no package manager, non-root.
FROM gcr.io/distroless/static:nonroot
COPY --from=build /out/ /
COPY config/policy.yaml /config/policy.yaml
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/gateway"]
CMD ["-config", "/config/policy.yaml"]
