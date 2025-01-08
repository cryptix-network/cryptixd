ARG CRYPTIXD_IMAGE
ARG CRYPTIXMINER_IMAGE

FROM ${CRYPTIXD_IMAGE} as cryptixd
FROM ${CRYPTIXMINER_IMAGE} as cryptixminer

FROM golang:1.23-alpine

RUN mkdir -p /go/src/github.com/cryptix-network/cryptixd

WORKDIR /go/src/github.com/cryptix-network/cryptixd

RUN apk add bash build-base git

COPY go.mod .
COPY go.sum .

RUN go mod download

COPY . .

COPY --from=cryptixd /app/ /app/
COPY --from=cryptixminer /app/ /app/
ENV PATH="/app:${PATH}"

WORKDIR /go/src/github.com/cryptix-network/cryptixd/stability-tests

RUN go install ./...

ENTRYPOINT ["./run/run.sh"]