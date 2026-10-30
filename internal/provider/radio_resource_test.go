package provider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

// The acceptance test changes the RTS threshold of the 2.4 GHz radio and
// restores it to the factory default at the end.
func TestAccRadioResource(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
resource "netgear_radio" "test" {
  band          = "2.4GHz"
  rts_threshold = 2345
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("netgear_radio.test", "id", "2.4GHz"),
					resource.TestCheckResourceAttr("netgear_radio.test", "rts_threshold", "2345"),
					resource.TestCheckResourceAttrSet("netgear_radio.test", "channel"),
					resource.TestCheckResourceAttrSet("netgear_radio.test", "aggregation_frames"),
				),
			},
			{
				ResourceName:      "netgear_radio.test",
				ImportState:       true,
				ImportStateId:     "2.4GHz",
				ImportStateVerify: true,
			},
			{
				Config: `
resource "netgear_radio" "test" {
  band          = "2.4GHz"
  rts_threshold = 2346
}
`,
				Check: resource.TestCheckResourceAttr("netgear_radio.test", "rts_threshold", "2346"),
			},
		},
	})
}
