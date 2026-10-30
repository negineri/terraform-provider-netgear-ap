resource "netgear_radio" "radio_2g" {
  band          = "2.4GHz"
  channel       = "6"
  channel_width = "HT20"
}

resource "netgear_radio" "radio_5g" {
  band          = "5GHz"
  channel       = "36"
  channel_width = "HT80"
  tx_power      = "half"
}
