default: build

build:
	go build -o terraform-provider-netgear-ap .

lint:
	go vet ./...
	test -z "$$(gofmt -l .)"

test:
	go test ./...

# Acceptance tests run against a real access point and change its settings
# (SSID slot 4 and the RTS threshold of the 2.4 GHz radio).
# Requires NETGEAR_AP_ENDPOINT and NETGEAR_AP_PASSWORD.
testacc:
	TF_ACC=1 go test ./... -v -timeout 60m

docs:
	go run github.com/hashicorp/terraform-plugin-docs/cmd/tfplugindocs@v0.25.0 generate --provider-name netgear

.PHONY: default build lint test testacc docs
