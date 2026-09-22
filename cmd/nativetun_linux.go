//go:build linux

package cmd

import (
	"fmt"
	"log"
	"net"

	"github.com/Diniboy1123/usque/api"
	"github.com/Diniboy1123/usque/config"
	"github.com/songgao/water"
	"github.com/vishvananda/netlink"
	wgtun "golang.zx2c4.com/wireguard/tun"
)

var longDescription = "Expose Warp as a native TUN device that accepts any IP traffic." +
	" Requires root, tun.ko, and iproute2."

func (t *tunDevice) create() (api.TunnelDevice, error) {
	var (
		dev        api.TunnelDevice
		deviceName string
	)

	if t.persist {
		// water is retained for persistent interfaces. wireguard-go's Linux
		// TUN backend is used for the normal ephemeral path because it enables
		// IFF_VNET_HDR and exposes batched GSO/GRO packet I/O.
		platformSpecificParams := water.PlatformSpecificParams{
			Name:    t.name,
			Persist: true,
		}
		waterDev, err := water.New(water.Config{DeviceType: water.TUN, PlatformSpecificParams: platformSpecificParams})
		if err != nil {
			return nil, err
		}
		deviceName = waterDev.Name()
		dev = api.NewWaterAdapter(waterDev)
	} else {
		wgDev, err := wgtun.CreateTUN(t.name, t.mtu)
		if err != nil {
			return nil, err
		}
		deviceName, err = wgDev.Name()
		if err != nil {
			_ = wgDev.Close()
			return nil, fmt.Errorf("failed to get TUN name: %v", err)
		}
		dev = api.NewBatchTunAdapter(wgDev)
	}

	t.name = deviceName

	if t.iproute2 {
		link, err := netlink.LinkByName(deviceName)
		if err != nil {
			return nil, fmt.Errorf("failed to get link: %v", err)
		}

		if err := netlink.LinkSetMTU(link, t.mtu); err != nil {
			return nil, fmt.Errorf("failed to set MTU: %v", err)
		}
		if t.ipv4 {
			if err := netlink.AddrAdd(link, &netlink.Addr{
				IPNet: &net.IPNet{
					IP:   net.ParseIP(config.AppConfig.IPv4),
					Mask: net.CIDRMask(32, 32),
				}}); err != nil {
				return nil, fmt.Errorf("failed to add IPv4 address: %v", err)
			}
		}
		if t.ipv6 {
			if err := netlink.AddrAdd(link, &netlink.Addr{
				IPNet: &net.IPNet{
					IP:   net.ParseIP(config.AppConfig.IPv6),
					Mask: net.CIDRMask(128, 128),
				}}); err != nil {
				return nil, fmt.Errorf("failed to add IPv6 address: %v", err)
			}
		}
		if err := netlink.LinkSetUp(link); err != nil {
			return nil, fmt.Errorf("failed to set link up: %v", err)
		}
	} else {
		log.Println("Skipping IP address and link setup. You should set the link up manually.")
		log.Println("Config has the following IP addresses:")
		log.Printf("IPv4: %s", config.AppConfig.IPv4)
		log.Printf("IPv6: %s", config.AppConfig.IPv6)
	}

	return dev, nil
}
