# nyyrikkid image (docs/06 D1): one static binary on distroless, non-root,
# with the licence texts of what is compiled into it (docs/09 D3).
# Base images are pinned by digest; Renovate proposes updates.
# The build stage runs on the build host's platform and cross-compiles
# (CGO is off and SQLite is pure Go), so a multi-platform build needs no
# emulation.
FROM --platform=$BUILDPLATFORM golang:1.26-bookworm@sha256:632dff7351799a5a9954a48dc06670ade72ee44e8c351cdc0e5a57af2fea21af AS build
WORKDIR /src
# go-licenses, for the licence notices (docs/09 D3). Keep the version equal
# to GO_LICENSES_VERSION in .github/workflows/ci.yml; the CI image job
# checks that they match. Built for the build host: it only runs here.
ARG GO_LICENSES_VERSION=v2.0.1
RUN GOBIN=/usr/local/bin go install github.com/google/go-licenses/v2@${GO_LICENSES_VERSION}
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY cmd ./cmd
COPY internal ./internal
# The SSH host setup script, embedded and served as is (docs/07 D16).
COPY deploy/ssh-host/embed.go deploy/ssh-host/nyyrikki-host-setup.sh ./deploy/ssh-host/
COPY LICENSE ./
COPY scripts/save-licenses.sh ./scripts/
ARG VERSION=dev
ARG TARGETOS TARGETARCH
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH GOFLAGS=-mod=readonly go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/nyyrikkid ./cmd/nyyrikkid
# The licence texts of every module compiled into nyyrikkid, for the
# target's package set (docs/09 D3, §5.3).
RUN GOOS=$TARGETOS GOARCH=$TARGETARCH GOFLAGS=-mod=readonly scripts/save-licenses.sh ./cmd/nyyrikkid /out/licenses

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /out/nyyrikkid /usr/local/bin/nyyrikkid
COPY --from=build /out/licenses /usr/share/doc/nyyrikki/licenses
USER 65532:65532
EXPOSE 8443 8081
ENTRYPOINT ["/usr/local/bin/nyyrikkid"]
CMD ["--config", "/etc/nyyrikki/config.yaml"]
