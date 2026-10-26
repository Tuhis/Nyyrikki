# nyyrikkid image (docs/06 D1): one static binary on distroless, non-root.
# Base images are pinned by digest; Renovate proposes updates.
FROM golang:1.26-bookworm@sha256:632dff7351799a5a9954a48dc06670ade72ee44e8c351cdc0e5a57af2fea21af AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY cmd ./cmd
COPY internal ./internal
ARG VERSION=dev
RUN CGO_ENABLED=0 GOFLAGS=-mod=readonly go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/nyyrikkid ./cmd/nyyrikkid

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /out/nyyrikkid /usr/local/bin/nyyrikkid
USER 65532:65532
EXPOSE 8443 8081
ENTRYPOINT ["/usr/local/bin/nyyrikkid"]
CMD ["--config", "/etc/nyyrikki/config.yaml"]
