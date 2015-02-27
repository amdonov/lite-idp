FROM google/golang-runtime
RUN cat /gopath/src/app/sample/ca.crt >> /etc/ssl/certs/ca-certificates.crt