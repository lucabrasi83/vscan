FROM scratch
ADD ca-certificates.crt /etc/ssl/certs/
ADD vulscano /
CMD ["/vulscano"]