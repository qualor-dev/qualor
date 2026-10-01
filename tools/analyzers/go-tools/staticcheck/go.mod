// Build module of staticcheck 2026.2.1 for deploy/scanner/Dockerfile's gotools stage (plan 9C, ruling G9-6).
module qualor.dev/go-tools/staticcheck

go 1.27.1

tool honnef.co/go/tools/cmd/staticcheck

require (
	github.com/BurntSushi/toml v1.4.1-0.20240526193622-a339e1f7089c // indirect
	golang.org/x/exp/typeparams v0.0.0-20231108232855-2478ac86f678 // indirect
	golang.org/x/mod v0.40.0 // indirect
	golang.org/x/sync v0.22.0 // indirect
	golang.org/x/tools v0.49.0 // indirect
	honnef.co/go/tools v0.8.1 // indirect
)
