FROM golang:1.13.3-alpine as builder
COPY tcl-root-ca.crt /usr/local/share/ca-certificates
COPY ./certs/rds-combined-ca-bundle.pem /usr/local/share/ca-certificates
RUN apk add --no-cache build-base git ca-certificates && update-ca-certificates 2>/dev/null || true
COPY . /go/src/github.com/lucabrasi83/vscan
WORKDIR /go/src/github.com/lucabrasi83/vscan
ENV GO111MODULE on
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -a -ldflags="-X github.com/lucabrasi83/vscan/initializer.Commit=$(git rev-parse --short HEAD) \
    -X github.com/lucabrasi83/vscan/initializer.Version=$(git describe --tags) \
    -X github.com/lucabrasi83/vscan/initializer.BuiltAt=$(date +%FT%T%z) \
    -X github.com/lucabrasi83/vscan/initializer.BuiltOn=$(hostname)" -o vscan

FROM scratch
LABEL maintainer="sebastien.pouplin@tatacommunications.com"
USER 1000
ENV VULSCANO_MODE PROD
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY ./certs /opt/vscan/data/certs
COPY --from=builder /go/src/github.com/lucabrasi83/vscan/banner.txt /
COPY --from=builder /go/src/github.com/lucabrasi83/vscan/vscan /
CMD ["./vscan"]
