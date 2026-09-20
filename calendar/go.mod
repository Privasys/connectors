module github.com/Privasys/connectors/calendar

go 1.26.0

require (
	github.com/Privasys/connectors/sdk v0.0.0
	github.com/emersion/go-ical v0.0.0-20250609112844-439c63cef608
	github.com/emersion/go-webdav v0.7.1-0.20260628102823-c16f8a9a132c
	github.com/teambition/rrule-go v1.8.2
)

require golang.org/x/oauth2 v0.37.0 // indirect

// The sdk is built from this repository, beside the connector, never from a
// published version: what the shell does is part of what this image is
// measured to do.
replace github.com/Privasys/connectors/sdk => ../sdk
