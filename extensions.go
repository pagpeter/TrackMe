package main

import "fmt"

// https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml
// https://boringssl.googlesource.com/boringssl/+/master/ssl/test/runner/common.go
var extensions = map[uint16]string{
	0:     "server_name",
	1:     "max_fragment_length",
	2:     "client_certificate_url",
	3:     "trusted_ca_keys",
	4:     "truncated_hmac",
	5:     "status_request",
	6:     "user_mapping",
	7:     "client_authz",
	8:     "server_authz",
	9:     "cert_type",
	10:    "supported_groups",
	11:    "ec_point_formats",
	12:    "srp",
	13:    "signature_algorithms",
	14:    "use_srtp",
	15:    "heartbeat",
	16:    "application_layer_protocol_negotiation",
	17:    "status_request_v2",
	18:    "signed_certificate_timestamp",
	19:    "client_certificate_type",
	20:    "server_certificate_type",
	21:    "padding",
	22:    "encrypt_then_mac",
	23:    "extended_master_secret",
	24:    "token_binding",
	25:    "cached_info",
	26:    "tls_lts",
	27:    "compress_certificate",
	28:    "record_size_limit",
	29:    "pwd_protect",
	30:    "pwd_clear",
	31:    "password_salt",
	32:    "ticket_pinning",
	33:    "tls_cert_with_extern_psk",
	34:    "delegated_credentials",
	35:    "session_ticket",
	36:    "TLMSP",
	37:    "TLMSP_proxying",
	38:    "TLMSP_delegate",
	39:    "supported_ekt_ciphers",
	40:    "Reserved",
	41:    "pre_shared_key",
	42:    "early_data",
	43:    "supported_versions",
	44:    "cookie",
	45:    "psk_key_exchange_modes",
	46:    "Reserved",
	47:    "certificate_authorities",
	48:    "oid_filters",
	49:    "post_handshake_auth",
	50:    "signature_algorithms_cert",
	51:    "key_share",
	52:    "transparency_info",
	53:    "connection_id (deprecated)",
	54:    "connection_id",
	55:    "external_id_hash",
	56:    "external_session_id",
	57:    "quic_transport_parameters",
	58:    "ticket_request",
	59:    "dnssec_chain",
	1234:  "extensionCustom (boringssl)",
	13172: "extensionNextProtoNeg (boringssl)",
	17513: "extensionApplicationSettings (boringssl)",
	65281: "extensionRenegotiationInfo (boringssl)",
	65445: "extensionQUICTransportParamsLegacy (boringssl)",
	30032: "extensionChannelID (boringssl)",
	65535: "extensionDuplicate (boringssl)",
	65037: "extensionEncryptedClientHello (boringssl)",
	64768: "extensionECHOuterExtensions (boringssl)",
}

func GetExtensionNameByID(id uint16) string {
	if name, ok := extensions[id]; ok {
		return fmt.Sprintf("%v (%v)", name, id)
	}
	return fmt.Sprintf("Unknown extension %d", id)
}

// Curves
// https://pkg.go.dev/crypto/tls#CurveID
// https://www.iana.org/assignments/tls-parameters/tls-parameters.xml#tls-parameters-8
var curves = map[uint16]string{
	1:     "sect163k1 (1)",
	2:     "sect163k1 (2)",
	3:     "sect163r2 (3)",
	4:     "sect193r1 (4)",
	5:     "sect193r2 (5)",
	6:     "sect233k1 (6)",
	7:     "sect233r1 (7)",
	8:     "sect239k1 (8)",
	9:     "sect283k1 (9)",
	10:    "sect283r1 (10)",
	11:    "sect409k1 (11)",
	12:    "sect409r1 (12)",
	13:    "sect571k1 (13)",
	14:    "sect571r1 (14)",
	15:    "secp160k1 (15)",
	16:    "secp160r1 (16)",
	17:    "secp160r2 (17)",
	18:    "secp192k1 (18)",
	19:    "secp192r1 (19)",
	20:    "secp224k1 (20)",
	21:    "P-224 (21)",
	23:    "P-256 (23)",
	24:    "P-384 (24)",
	25:    "P-521 (25)",
	29:    "X25519 (29)",
	30:    "X448 (30)",
	31:    "P256r1tls13 (31)",
	32:    "P384r1tls13 (32)",
	33:    "P521r1tls13 (33)",
	34:    "GC256A (34)",
	35:    "GC256B (35)",
	36:    "GC256C (36)",
	37:    "GC256D (37)",
	38:    "GC512A (38)",
	39:    "GC512B (39)",
	40:    "GC512C (40)",
	41:    "SM2 (41)",
	256:   "ffdhe2048 (256)",
	257:   "ffdhe3072 (257)",
	258:   "ffdhe4096 (258)",
	259:   "ffdhe6144 (259)",
	260:   "ffdhe8192 (260)",
	16696: "CECPQ2 (16696)",
}

func GetCurveNameByID(id uint16) string {
	if name, ok := curves[id]; ok {
		return name
	}
	return fmt.Sprintf("Unknown curve %d", id)
}
