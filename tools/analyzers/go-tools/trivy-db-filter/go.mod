// Qualor's Trivy database filter (0.16 debts D31-1, ruling B2-a): built by deploy/scanner/Dockerfile's
// gotools stage and by tools/analyzers/filter-trivy-db.sh, on bbolt v1.5.0 (Trivy 0.74.0's pin).
module qualor.dev/go-tools/trivy-db-filter

go 1.27.1

require go.etcd.io/bbolt v1.5.0

require golang.org/x/sys v0.45.0 // indirect
