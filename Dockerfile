FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod *.go ./
RUN go test ./... && CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /message-me-cve .

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /message-me-cve /message-me-cve
USER 1000:1000
WORKDIR /data
ENTRYPOINT ["/message-me-cve"]
