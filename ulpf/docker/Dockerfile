# syntax=docker/dockerfile:1
FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o bin/ulpf ./cmd/ulpf

FROM alpine:3.19
RUN apk add --no-cache ca-certificates tzdata
WORKDIR /app
COPY --from=builder /app/bin/ulpf /usr/local/bin/ulpf
COPY configs/ /configs/
EXPOSE 8080 9090 5514/tcp 5514/udp
ENTRYPOINT ["ulpf"]
CMD ["ingest", "--config", "/configs/ulpf.yaml"]