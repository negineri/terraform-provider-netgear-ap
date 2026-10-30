package provider

import (
	"context"
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

// restoreSSIDAfterTest saves the configuration of an SSID slot and writes it
// back when the test finishes, as destroying netgear_ssid only disables the
// slot.
func restoreSSIDAfterTest(t *testing.T, slot int) {
	t.Helper()
	if os.Getenv(resource.EnvTfAcc) == "" {
		return // resource.Test skips the test
	}
	testAccPreCheck(t)
	c := testAccClient(t)
	ctx := context.Background()
	orig, err := c.GetSSID(ctx, slot)
	if err != nil {
		t.Fatalf("saving SSID slot %d: %v", slot, err)
	}
	t.Cleanup(func() {
		// The VLAN ID is only written while VLAN isolation is enabled, so
		// it is written first with VLAN isolation enabled.
		if !orig.VLANEnabled {
			s := *orig
			s.VLANEnabled = true
			if err := c.UpdateSSID(ctx, &s); err != nil {
				t.Errorf("restoring SSID slot %d: %v", slot, err)
				return
			}
		}
		if err := c.UpdateSSID(ctx, orig); err != nil {
			t.Errorf("restoring SSID slot %d: %v", slot, err)
		}
	})
}

// The acceptance test takes over SSID slot 4 of the device and restores it
// afterwards.
func TestAccSSIDResource(t *testing.T) {
	restoreSSIDAfterTest(t, 4)
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
resource "netgear_ssid" "test" {
  slot       = 4
  ssid       = "tf-acc-test"
  enabled_2g = false
  enabled_5g = false
  passphrase = "tf-acc-passphrase"
  hidden     = true
  vlan_id    = 40
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("netgear_ssid.test", "id", "4"),
					resource.TestCheckResourceAttr("netgear_ssid.test", "ssid", "tf-acc-test"),
					resource.TestCheckResourceAttr("netgear_ssid.test", "security", "sae-mixed"),
					resource.TestCheckResourceAttr("netgear_ssid.test", "passphrase", "tf-acc-passphrase"),
					resource.TestCheckResourceAttr("netgear_ssid.test", "hidden", "true"),
					resource.TestCheckResourceAttr("netgear_ssid.test", "vlan_id", "40"),
					resource.TestCheckResourceAttr("netgear_ssid.test", "enabled_2g", "false"),
				),
			},
			{
				ResourceName:      "netgear_ssid.test",
				ImportState:       true,
				ImportStateId:     "4",
				ImportStateVerify: true,
			},
			{
				Config: `
resource "netgear_ssid" "test" {
  slot               = 4
  ssid               = "tf-acc-test-2"
  enabled_2g         = true
  enabled_5g         = true
  security           = "psk2"
  passphrase         = "another-passphrase"
  client_isolation   = true
  band_steering      = true
  mac_filter         = "deny"
  mac_addresses      = ["aa:bb:cc:dd:ee:ff", "02:00:00:00:00:01"]
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("netgear_ssid.test", "ssid", "tf-acc-test-2"),
					resource.TestCheckResourceAttr("netgear_ssid.test", "security", "psk2"),
					resource.TestCheckResourceAttr("netgear_ssid.test", "passphrase", "another-passphrase"),
					resource.TestCheckResourceAttr("netgear_ssid.test", "enabled_2g", "true"),
					resource.TestCheckResourceAttr("netgear_ssid.test", "client_isolation", "true"),
					resource.TestCheckNoResourceAttr("netgear_ssid.test", "vlan_id"),
					resource.TestCheckResourceAttr("netgear_ssid.test", "enabled_5g", "true"),
					resource.TestCheckResourceAttr("netgear_ssid.test", "band_steering", "true"),
					resource.TestCheckResourceAttr("netgear_ssid.test", "mac_filter", "deny"),
					resource.TestCheckResourceAttr("netgear_ssid.test", "mac_addresses.#", "2"),
				),
			},
			{
				Config: `
resource "netgear_ssid" "test" {
  slot               = 4
  ssid               = "tf-acc-test-3"
  enabled_2g         = false
  enabled_5g         = false
  security           = "wpa2"
  radius_server      = "192.0.2.10"
  radius_secret      = "radius-secret"
  accounting_enabled = true
  accounting_server  = "192.0.2.11"
  accounting_secret  = "acct-secret"
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("netgear_ssid.test", "security", "wpa2"),
					resource.TestCheckResourceAttr("netgear_ssid.test", "radius_server", "192.0.2.10"),
					resource.TestCheckResourceAttr("netgear_ssid.test", "radius_secret", "radius-secret"),
					resource.TestCheckResourceAttr("netgear_ssid.test", "accounting_server", "192.0.2.11"),
					resource.TestCheckNoResourceAttr("netgear_ssid.test", "passphrase"),
				),
			},
		},
	})
}
