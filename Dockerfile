FROM golang:1.12.6-alpine as builder
COPY tcl-root-ca.crt /usr/local/share/ca-certificates
RUN apk add --no-cache build-base git ca-certificates && update-ca-certificates 2>/dev/null || true
COPY . /go/src/github.com/lucabrasi83/vulscano
WORKDIR /go/src/github.com/lucabrasi83/vulscano
ENV GO111MODULE on
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
go build -a -ldflags="-X github.com/lucabrasi83/vulscano/initializer.Commit=$(git rev-parse --short HEAD) \
-X github.com/lucabrasi83/vulscano/initializer.Version=$(git describe --tags) \
-X github.com/lucabrasi83/vulscano/initializer.BuiltAt=$(date +%FT%T%z) \
-X github.com/lucabrasi83/vulscano/initializer.BuiltOn=$(hostname)" -o vulscano

FROM scratch
LABEL maintainer="sebastien.pouplin@tatacommunications.com"
ENV VULSCANO_MODE PROD
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY ./certs /opt/vulscano/data/certs
COPY --from=builder /go/src/github.com/lucabrasi83/vulscano/banner.txt /
COPY --from=builder /go/src/github.com/lucabrasi83/vulscano/vulscano /
CMD ["./vulscano"]
