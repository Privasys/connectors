module github.com/Privasys/connectors/meetings

go 1.26.0

require github.com/Privasys/connectors/sdk v0.0.0

require (
	enclave-os-mini/clients/go v0.0.0-00010101000000-000000000000 // indirect
	golang.org/x/oauth2 v0.37.0 // indirect
)

// The sdk is built from this repository, beside the connector, never from a
// published version: what the shell does is part of what this image is
// measured to do.
replace github.com/Privasys/connectors/sdk => ../sdk

// The RA-TLS client the sdk's Drive leg is built on. A replace in the sdk's
// own go.mod does not reach a module that requires it, so the same pin is
// named here; the two must agree.
replace enclave-os-mini/clients/go => github.com/Privasys/ra-tls-clients/go v0.0.0-20260909145749-a5c458d7601e
