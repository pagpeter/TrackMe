# TrackMe - Server side http/tls tracking demo in go

TrackMe is a custom, low-level http/1 and h2 server, that responds with the fine details about the request made.

It returns the ja3, akamai h2 fingerprint, header + header order, h2 frames, and much more.

## Running it

You first need to generate the certificate.pem and the key.pem files.

```bash
$ mkdir certs 
$ openssl req -x509 -newkey rsa:4096 -keyout certs/key.pem -out certs/chain.pem -sha256 -days 365 -nodes
```

Then, you need to copy the example config (and maybe edit it)

```bash
$ cp config.example.json config.json 
$ nano config.json 
...
```

You can build a binary by running `go build -o TrackMe *.go`

After that, just run the binary (`sudo ./TrackMe`)
