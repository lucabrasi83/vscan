FROM golang:1.11.1-alpine as builder
RUN apk update && apk add build-base && apk add git
COPY . /go/src/github.com/lucabrasi83/vulscano
WORKDIR /go/src/github.com/lucabrasi83/vulscano
ENV GO111MODULE on
RUN go mod tidy && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
go build -a -ldflags="-X github.com/lucabrasi83/vulscano/initializer.Commit=$(git rev-parse --short HEAD) \
-X github.com/lucabrasi83/vulscano/initializer.Version=$(git describe --tags) \
-X github.com/lucabrasi83/vulscano/initializer.BuiltAt=$(date +%FT%T%z) \
-X github.com/lucabrasi83/vulscano/initializer.BuiltOn=$(hostname)" -installsuffix cgo -o vulscano

FROM scratch
ENV VULSCANO_MODE PROD
ADD ca-certificates.crt /etc/ssl/certs/
COPY ./certs /opt/vulscano/data/certs
COPY --from=builder /go/src/github.com/lucabrasi83/vulscano/banner.txt /
COPY --from=builder /go/src/github.com/lucabrasi83/vulscano/vulscano /
CMD ["./vulscano"]