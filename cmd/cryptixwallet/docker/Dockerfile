# -- multistage docker build: stage #1: build stage
FROM golang:1.18-alpine AS build

RUN mkdir -p /go/src/github.com/cryptix-network/cryptixd

WORKDIR /go/src/github.com/cryptix-network/cryptixd

RUN apk add --no-cache curl git openssh binutils gcc musl-dev

COPY go.mod .
COPY go.sum .

RUN go mod download

COPY . .

WORKDIR /go/src/github.com/cryptix-network/cryptixd/cmd/cryptixwallet
RUN GOOS=linux go build -a -installsuffix cgo -o cryptixwallet .

# --- multistage docker build: stage #2: runtime image
FROM alpine
WORKDIR /app

RUN apk add --no-cache ca-certificates tini

COPY --from=build /go/src/github.com/cryptix-network/cryptixd/cmd/cryptixwallet/cryptixwallet /app/

USER nobody
ENTRYPOINT [ "/sbin/tini", "--" ]
