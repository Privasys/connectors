module github.com/Privasys/connectors/mail

go 1.26

// The RA-TLS client module declares a non-fetchable path, so it is consumed
// as a sibling checkout: cloned at a pin in the Dockerfile and in CI, and
// symlinked for local work. Pinned, never tracked.
replace enclave-os-mini/clients/go => ../ra-tls-clients/go

require (
	enclave-os-mini/clients/go v0.0.0-00010101000000-000000000000
	github.com/emersion/go-imap/v2 v2.0.0-beta.8
	github.com/emersion/go-message v0.18.2
)

require (
	github.com/emersion/go-sasl v0.0.0-20241020182733-b788ff22d5a6 // indirect
	golang.org/x/text v0.14.0 // indirect
)
