FROM golang:1.11-stretch AS builder
# RUN apk update && apk add --no-cache git ca-certificates tzdata alpine-sdk bash && update-ca-certificates
WORKDIR /media/storage/Project/consumerantares
# <- COPY go.mod and go.sum files to the workspace
COPY go.mod .
# COPY go.sum .

# Get dependancies - will also be cached if we won't change mod/sum
RUN go mod download
COPY . .
RUN GOOS="linux" GOARCH=amd64 CGO_ENABLED=0 go build -o main main.go

FROM alpine:latest
WORKDIR /app
ARG ENVCONSUL_VERSION=0.6.2
RUN apk --no-cache add curl ca-certificates \
 && curl https://releases.hashicorp.com/envconsul/${ENVCONSUL_VERSION}/envconsul_${ENVCONSUL_VERSION}_linux_$
RUN apk add --no-cache tzdata

COPY --from=builder /media/storage/Project/consumerantares/postgresql.key .
COPY --from=builder /media/storage/Project/consumerantares/postgresql.crt .
COPY --from=builder /media/storage/Project/consumerantares/root.crt .
RUN chmod 644 postgresql.crt
RUN chmod 644 root.crt
RUN chmod 600 postgresql.key
COPY --from=builder /media/storage/Project/consumerantares/main .
# CMD ["/app/main"]
ENTRYPOINT ["/app/main"]

