FROM golang:1.18-alpine3.16

WORKDIR /app
COPY go.mod go.sum ./
COPY *.go ./
RUN go mod download
RUN go build -o ./out/app *.go

CMD [ "./out/app" ]
