FROM golang:1.24-alpine AS builder

RUN apk add --no-cache build-base libpcap-dev clang llvm linux-headers libbpf-dev

WORKDIR /app

COPY go.mod go.sum ./
ENV GOTOOLCHAIN=auto
RUN go mod download

COPY cmd/ cmd/
COPY pkg/ pkg/
COPY ebpf/ ebpf/
COPY static/ static/

RUN cd ebpf && clang -O2 -g -target bpf -Wall -Werror \
    -I/usr/include \
    -c syn_capture.c -o syn_capture.o

RUN CGO_ENABLED=1 go build -o trackme ./cmd/

FROM alpine:latest
RUN apk add --no-cache libpcap libcap
WORKDIR /app
COPY --from=builder /app/trackme .
COPY --from=builder /app/ebpf/ ebpf/
COPY static/ static/

EXPOSE 443 80

CMD ["./trackme"]
