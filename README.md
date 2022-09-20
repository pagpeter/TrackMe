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

## Custom Fingerpints

I wanted to extend JA3, so I created my own TLS fingerprint algorithm. It's better suited for fingerprinting TLS1.3 connections, because [JA3 does not really do that](https://github.com/salesforce/ja3/issues/78), and has more datapoints. The designed is inspired by the http/2 fingerprint proposed by akamai.

It looks like this:

```
supported-tls-versions|supported-protocols|supported-groups|supported-signature-algorithms|psk-key-exchange-mode|certificate-compression-algorithms|cipher-suites|extensions
```

**supported-tls-versions**: Comma seperated list of supported TLS versions as sent in the `supported_versions` extension.

**supported-protocols**: Comma seperated list of supported HTTP versions as sent in the `application_layer_protocol_negotiation` extension. http/1.0 => 1.0, http/1.1 => 1.1, http/2 => 2

**supported-groups**: Comma seperated list of supported elliptic curve groups as sent in the `supported_groups` extension.

**supported-signature-algorithms**: Comma seperated list of supported signatue algorithms as sent in the `signature_algorithms` extension.

**psk-key-exchange-mode** The PSK key exchange mode as specified in the `psk_key_exchange_modes` extension. Usually 0 or 1.

**certificate-compression-algorithms** Comma seperated list of the certificate compression algorithms as sent in the `compress_certificate` extension.

**cipher-suites**: Comma seperated list of the supported cipher suites.

**extensions**: Comma seperated list of the supported extensions.

All TLS GREASE values must be omitted everywhere.

That means, a fingerprint could look something like this:

```
771,772|1.1,2|29,23,24|1027,2057,1025,1283,2053,1281,2054,1537|1|2|4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53|0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-41
```

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
