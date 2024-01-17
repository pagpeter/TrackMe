FROM golang:1.18-alpine3.16

RUN apk add build-base
RUN apk add libpcap-dev
WORKDIR /app

COPY go.mod go.sum config.json ./
COPY *.go ./
COPY certs ./certs/

RUN go mod download
RUN go build -o ./out/app *.go

CMD [ "./out/app" ]