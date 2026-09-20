module github.com/Privasys/connectors/mail

go 1.26

require (
	github.com/Privasys/connectors/sdk v0.0.0
	github.com/emersion/go-imap/v2 v2.0.0-beta.8
	github.com/emersion/go-message v0.18.2
)

require (
	github.com/emersion/go-sasl v0.0.0-20241020182733-b788ff22d5a6 // indirect
	golang.org/x/text v0.14.0 // indirect
)

// The sdk is built from this repository, beside the connector, never from a
// published version: what the shell does is part of what this image is
// measured to do.
replace github.com/Privasys/connectors/sdk => ../sdk
