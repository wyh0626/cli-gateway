FROM golang:1.25.12 AS build
ARG VERSION=0.3.0-dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/cli-gateway ./cmd/cli-gateway \
    && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X github.com/wyh0626/cli-gateway/client/internal/app.version=${VERSION}" -o /out/cg ./client/cmd/cg \
    && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/devissuer ./cmd/devissuer \
    && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/demoapi ./cmd/demoapi \
    && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/loadtest ./cmd/loadtest \
    && mkdir -p /out/downloads \
    && GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X github.com/wyh0626/cli-gateway/client/internal/app.version=${VERSION}" -o /out/downloads/cg-darwin-amd64 ./client/cmd/cg \
    && GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X github.com/wyh0626/cli-gateway/client/internal/app.version=${VERSION}" -o /out/downloads/cg-darwin-arm64 ./client/cmd/cg \
    && GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X github.com/wyh0626/cli-gateway/client/internal/app.version=${VERSION}" -o /out/downloads/cg-linux-amd64 ./client/cmd/cg \
    && GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X github.com/wyh0626/cli-gateway/client/internal/app.version=${VERSION}" -o /out/downloads/cg-linux-arm64 ./client/cmd/cg \
    && cd /out/downloads \
    && for file in cg-*; do sha256sum "$file" > "$file.sha256"; done \
    && mkdir -p /out/data \
    && chown 65532:65532 /out/data

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/cli-gateway /out/cg /out/devissuer /out/demoapi /out/loadtest /usr/local/bin/
COPY --from=build /out/downloads/ /usr/local/share/cli-gateway/downloads/
COPY --from=build --chown=nonroot:nonroot /out/data/ /var/lib/cli-gateway/
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/cli-gateway"]
CMD ["-manifest", "/etc/cli-gateway/manifest.yaml"]
