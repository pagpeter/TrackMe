FROM golang:1.23-alpine

RUN apk add build-base
RUN apk add libpcap-dev
WORKDIR /app

COPY go.mod go.sum config.json ./
COPY *.go ./
COPY certs ./certs/
COPY static ./static/

RUN go mod download
RUN go build -o ./out/app *.go

CMD [ "./out/app" ]
