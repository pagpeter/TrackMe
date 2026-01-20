FROM golang:1.24-alpine

RUN apk add build-base
RUN apk add libpcap-dev
WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY cmd ./cmd/
COPY pkg ./pkg/
COPY certs ./certs/
COPY static ./static/

RUN go build -o ./out/app ./cmd/main.go

COPY config.json ./

CMD [ "./out/app" ]
