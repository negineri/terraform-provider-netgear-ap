package provider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccDeviceDataSource(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `data "netgear_device" "this" {}`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("data.netgear_device.this", "model", "WAX210"),
					resource.TestCheckResourceAttrSet("data.netgear_device.this", "serial_number"),
					resource.TestCheckResourceAttrSet("data.netgear_device.this", "firmware_version"),
					resource.TestCheckResourceAttrSet("data.netgear_device.this", "lan_mac_address"),
				),
			},
		},
	})
}
