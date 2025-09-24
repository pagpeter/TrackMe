# TrackMe - Server side http/tls tracking demo in go

TrackMe is a custom, low-level http/1 and h2 server, that responds with the fine details about the request made.

It returns the ja3, akamai h2 fingerprint, header + header order, h2 frames, and much more.

## Generating the certificates and config

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

## Running it (Docker)

```bash
$ docker build -t "trackme:Dockerfile" .
$ docker run -p 80:80 -p 443:443 "trackme:Dockerfile"
```

## Running it (Without Docker)

You can build a binary by running `go build -o TrackMe cmd/main.go`

After that, just run the binary (`sudo ./TrackMe`)

## Different fingerprints

The site returns 3 different fingerprints: the [JA3](https://engineering.salesforce.com/tls-fingerprinting-with-ja3-and-ja3s-247362855967/), a TLS fingerprint, an HTTP/2 ["akamai-fingerprint"](https://www.blackhat.com/docs/eu-17/materials/eu-17-Shuster-Passive-Fingerprinting-Of-HTTP2-Clients-wp.pdf) (Only works on HTTP/2 connections) and my own custom "PeetPrint".

### Custom Fingerpint ("PeetPrint")

I wanted to extend JA3, so I created my own TLS fingerprint algorithm. It's better suited for fingerprinting TLS1.3 connections, because [JA3 doesn't really do that well](https://github.com/salesforce/ja3/issues/78), and has more datapoints. The designed is inspired by the http/2 fingerprint proposed by akamai.

It looks like this:

```
supported-tls-versions|supported-protocols|supported-groups|supported-signature-algorithms|psk-key-exchange-mode|certificate-compression-algorithms|cipher-suites|sorted-extensions
```

"-" is used as the seperator.

**supported-tls-versions**: Seperated list of supported TLS versions as sent in the `supported_versions` extension.

**supported-protocols**: Seperated list of supported HTTP versions as sent in the `application_layer_protocol_negotiation` extension. http/1.0 => 1.0, http/1.1 => 1.1, http/2 => 2

**supported-groups**: Seperated list of supported elliptic curve groups as sent in the `supported_groups` extension.

**supported-signature-algorithms**: Seperated list of supported signatue algorithms as sent in the `signature_algorithms` extension.

**psk-key-exchange-mode** The PSK key exchange mode as specified in the `psk_key_exchange_modes` extension. Usually 0 or 1.

**certificate-compression-algorithms** Seperated list of the certificate compression algorithms as sent in the `compress_certificate` extension.

**cipher-suites**: Seperated list of the supported cipher suites.

**sorted-extensions**: Sorted list of the supported extensions. (Sorted because of order randomization used by chrome)

All TLS GREASE values must be replaced with "GREASE".

That means, a fingerprint could look something like this:

```
GREASE-772-771|2-1.1|GREASE-29-23-24|1027-2052-1025-1283-2053-1281-2054-1537|1|2|GREASE-4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53|GREASE-0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-GREASE-21-41
```

## API endpoints

The site exposes a lot of different API endpoints.

### /api/all

Returns all of the collected data about an request

### /api/tls

Returns only the TLS data

### /api/clean

Returns only the different fingerprints (akamai-fp+ja3)

### /api/request-count

Returns the total request count the database captured. Only works when connected to a database.

### /api/search-ja3

Param: `?by=<ja3>`

Returns the most seen other identifiers (user-agent, h2, peetprint) that were seen together with this identifier. Only works when connected to a database.

### /api/search-h2

Param: `?by=<akamai-fp>`

Returns the most seen other identifiers (user-agent, JA3, peetprint) that were seen together with this identifier. Only works when connected to a database.

### /api/search-peetprint

Param: `?by=<peetprint>`

Returns the most seen other identifiers (user-agent, h2, JA3) that were seen together with this identifier. Only works when connected to a database.

## Docker

You can also run the server in a docker container using docker-compose.

```bash
# generate certs and update your config.json
docker-compose -up --build
# visit https://localhost/api/all
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
