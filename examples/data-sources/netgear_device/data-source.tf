data "netgear_device" "this" {}

output "firmware_version" {
  value = data.netgear_device.this.firmware_version
}
