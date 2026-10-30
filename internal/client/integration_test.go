package client

import (
	"context"
	"os"
	"testing"
)

// newTestClient returns a client for the device configured with the
// NETGEAR_AP_* environment variables, or skips the test.
func newTestClient(t *testing.T) *Client {
	t.Helper()
	endpoint := os.Getenv("NETGEAR_AP_ENDPOINT")
	if endpoint == "" || os.Getenv("TF_ACC") == "" {
		t.Skip("set TF_ACC and NETGEAR_AP_ENDPOINT to run tests against a real device")
	}
	c, err := New(Config{
		Endpoint: endpoint,
		Username: os.Getenv("NETGEAR_AP_USERNAME"),
		Password: os.Getenv("NETGEAR_AP_PASSWORD"),
		Insecure: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestIntegrationRead(t *testing.T) {
	c := newTestClient(t)
	ctx := context.Background()

	d, err := c.GetDeviceInfo(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("device: %+v", *d)

	for slot := 1; slot <= MaxSSIDSlot; slot++ {
		s, err := c.GetSSID(ctx, slot)
		if err != nil {
			t.Fatal(err)
		}
		s.Passphrase = "<redacted>"
		t.Logf("ssid %d: %+v", slot, *s)
	}
	for _, b := range []string{Band2G, Band5G} {
		r, err := c.GetRadio(ctx, b)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("radio %s: %+v", b, *r)
	}
}
