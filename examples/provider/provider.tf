terraform {
  required_providers {
    netgear = {
      source = "negineri/netgear-ap"
    }
  }
}

provider "netgear" {
  endpoint = "https://192.168.0.100"
  # username = "admin"            # default
  # password = "..."              # or NETGEAR_AP_PASSWORD
  # insecure = true               # default, the device uses a self-signed certificate
}
