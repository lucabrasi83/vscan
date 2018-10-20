FROM golang:1.11.1-alpine as builder
WORKDIR /go/src/app
COPY . .
RUN apk update && apk add build-base && apk add git
ENV GO111MODULE on
RUN go mod tidy \
  && CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o vulscano .

FROM scratch
ADD ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /go/src/app/vulscano /
CMD ["./vulscano"]