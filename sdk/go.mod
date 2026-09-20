module github.com/Privasys/connectors/sdk

go 1.26.0

require (
	enclave-os-mini/clients/go v0.0.0-00010101000000-000000000000
	github.com/ledongthuc/pdf v0.0.0-20260907135840-6c8c28e0e8a0
	golang.org/x/oauth2 v0.37.0
)

// The RA-TLS client module declares a non-fetchable path, so it is taken from
// its public repository at an exact commit rather than by name: the attested
// leg is what decides whether a holder's document leaves this service, and it
// must not change under a rebuild. Bump the pseudo-version deliberately.
replace enclave-os-mini/clients/go => github.com/Privasys/ra-tls-clients/go v0.0.0-20260909145749-a5c458d7601e
