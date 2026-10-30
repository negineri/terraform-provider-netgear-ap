package client

import (
	"context"
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"regexp"
	"strings"
)

// DeviceInfo holds read-only information about the access point.
type DeviceInfo struct {
	Model           string
	Name            string
	SerialNumber    string
	FirmwareVersion string
	LANMACAddress   string
	WLAN2GMAC       string
	WLAN5GMAC       string
	Country         string
	IPAddress       string
	Netmask         string
	Gateway         string
	DNS             []string
	Uptime          int64
}

var (
	reModel     = regexp.MustCompile(`var model_name = '([^']*)'`)
	reFirmware  = regexp.MustCompile(`var firmwareVersion = '([^']*)'`)
	reSysName   = regexp.MustCompile(`var SystemName = repSpecHTML\("((?:[^"\\]|\\.)*)"`)
	reSerial    = regexp.MustCompile(`myid="Device_Serial_Number_text">([^<]*)<`)
	reMacLAN    = regexp.MustCompile(`id="mac_lan"[^>]*>([^<]*)<`)
	reMac24     = regexp.MustCompile(`id="mac_24g"[^>]*>([^<]*)<`)
	reMac5      = regexp.MustCompile(`id="mac_5g"[^>]*>([^<]*)<`)
	reCountry   = regexp.MustCompile(`id="ws_country"[^>]*>([^<]*)<`)
	reModelName = regexp.MustCompile(`class="model_name"[^>]*>([^<]*)<`)
)

func firstMatch(re *regexp.Regexp, s string) string {
	if m := re.FindStringSubmatch(s); m != nil {
		return strings.TrimSpace(html.UnescapeString(m[1]))
	}
	return ""
}

// GetDeviceInfo reads information shown on the status overview page.
func (c *Client) GetDeviceInfo(ctx context.Context) (*DeviceInfo, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	page, err := c.do(ctx, http.MethodGet, "admin/status/overview", nil)
	if err != nil {
		return nil, err
	}
	d := &DeviceInfo{
		Model:           firstMatch(reModel, page),
		Name:            strings.ReplaceAll(firstMatch(reSysName, page), `\"`, `"`),
		SerialNumber:    firstMatch(reSerial, page),
		FirmwareVersion: firstMatch(reFirmware, page),
		LANMACAddress:   firstMatch(reMacLAN, page),
		WLAN2GMAC:       firstMatch(reMac24, page),
		WLAN5GMAC:       firstMatch(reMac5, page),
		Country:         firstMatch(reCountry, page),
	}
	if d.Model == "" {
		d.Model = firstMatch(reModelName, page)
	}

	status, err := c.do(ctx, http.MethodGet, "admin/status/overview?status=1", nil)
	if err != nil {
		return nil, err
	}
	var st struct {
		WAN struct {
			IPAddr  string   `json:"ipaddr"`
			Netmask string   `json:"netmask"`
			GWAddr  string   `json:"gwaddr"`
			DNS     []string `json:"dns"`
			Uptime  int64    `json:"uptime"`
		} `json:"wan"`
	}
	if err := json.Unmarshal([]byte(status), &st); err != nil {
		return nil, fmt.Errorf("decoding status: %w", err)
	}
	d.IPAddress = st.WAN.IPAddr
	d.Netmask = st.WAN.Netmask
	d.Gateway = st.WAN.GWAddr
	d.DNS = st.WAN.DNS
	d.Uptime = st.WAN.Uptime
	return d, nil
}
