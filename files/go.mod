module github.com/Privasys/connectors/files

go 1.26.0

require github.com/Privasys/connectors/sdk v0.0.0

require (
	github.com/ledongthuc/pdf v0.0.0-20260907135840-6c8c28e0e8a0 // indirect
	golang.org/x/oauth2 v0.37.0 // indirect
)

// The sdk is built from this repository, beside the connector, never from a
// published version: what the shell does is part of what this image is
// measured to do.
replace github.com/Privasys/connectors/sdk => ../sdk
