module github.com/Privasys/connectors/files

go 1.26.0

require github.com/Privasys/connectors/sdk v0.0.0

// The sdk is built from this repository, beside the connector, never from a
// published version: what the shell does is part of what this image is
// measured to do.
replace github.com/Privasys/connectors/sdk => ../sdk
