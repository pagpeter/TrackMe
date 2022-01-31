# TrackMe - Server side http/tls tracking demo in go

TrackMe is a custom, low-level http/1 and h2 server, that responds with the fine details about the request made.

It returns the ja3, akamai h2 fingerprint, header + header order, h2 frames, and much more.

## Running it

You first need to generate the certificate.pem and the key.pem files.

```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -sha256 -days 365 -nodes
```

You can make a binary by running `go build -o TrackMe *.go`

After that, just run the binary (`sudo ./TrackMe`)
