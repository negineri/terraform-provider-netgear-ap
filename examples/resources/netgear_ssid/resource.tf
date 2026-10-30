# WPA2/WPA3-Personal SSID on both radios.
resource "netgear_ssid" "office" {
  slot          = 1
  ssid          = "office"
  passphrase    = var.office_passphrase
  band_steering = true
}

# Guest SSID on a VLAN, isolated clients, 2.4 GHz only.
resource "netgear_ssid" "guest" {
  slot             = 2
  ssid             = "guest"
  enabled_5g       = false
  security         = "psk2"
  passphrase       = var.guest_passphrase
  vlan_id          = 20
  client_isolation = true
}

# WPA3-Enterprise SSID with RADIUS authentication.
resource "netgear_ssid" "corp" {
  slot          = 3
  ssid          = "corp"
  security      = "wpa3"
  radius_server = "192.0.2.10"
  radius_secret = var.radius_secret
  hidden        = true
}
