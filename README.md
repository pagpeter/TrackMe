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

## TLS & HTTP2 fingerprinting resources

- [TLS 1.3, every byte explained](https://tls13.xargs.org/)
- [Ja3 explanation - Salesforce](https://engineering.salesforce.com/tls-fingerprinting-with-ja3-and-ja3s-247362855967/)
- ["A very simple article about TLS."](https://kronoz.dev/articles/tls)
- [State of TLS fingerprinting - fastly](https://www.fastly.com/blog/the-state-of-tls-fingerprinting-whats-working-what-isnt-and-whats-next)
- [TLS fingerprinting - lwthiker](https://lwthiker.com/networks/2022/06/17/tls-fingerprinting.html)
- [HTTP2 Explained - haxx.se](https://http2-explained.haxx.se/en/part1)
- [Akamai - HTTP2 fingerprinting](https://www.blackhat.com/docs/eu-17/materials/eu-17-Shuster-Passive-Fingerprinting-Of-HTTP2-Clients-wp.pdf)
- [Fingerprinting HTTP2 - privacycheck.sec.lrz.de](https://privacycheck.sec.lrz.de/passive/fp_h2/fp_http2.html)
- [HTTP2 Fingerprinting](https://lwthiker.com/networks/2022/06/17/http2-fingerprinting.html)

- [TCP fingerprinting wikipedia](https://en.wikipedia.org/wiki/TCP/IP_stack_fingerprinting) (The german version is better)
- [TCP/IP stack fingerprinting](https://en-academic.com/dic.nsf/enwiki/868408) (lots of other links)
