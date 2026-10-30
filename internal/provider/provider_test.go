package provider

import (
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"

	"github.com/negineri/terraform-provider-netgear-ap/internal/client"
)

// testAccProtoV6ProviderFactories instantiates the provider for acceptance tests.
var testAccProtoV6ProviderFactories = map[string]func() (tfprotov6.ProviderServer, error){
	"netgear": providerserver.NewProtocol6WithError(New("test")()),
}

// testAccPreCheck verifies the environment required by acceptance tests,
// which run against a real access point.
func testAccPreCheck(t *testing.T) {
	t.Helper()
	for _, env := range []string{"NETGEAR_AP_ENDPOINT", "NETGEAR_AP_PASSWORD"} {
		if os.Getenv(env) == "" {
			t.Fatalf("%s must be set for acceptance tests", env)
		}
	}
}

// testAccClient returns a client for the device under test.
func testAccClient(t *testing.T) *client.Client {
	t.Helper()
	c, err := client.New(client.Config{
		Endpoint: os.Getenv("NETGEAR_AP_ENDPOINT"),
		Username: os.Getenv("NETGEAR_AP_USERNAME"),
		Password: os.Getenv("NETGEAR_AP_PASSWORD"),
		Insecure: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}
