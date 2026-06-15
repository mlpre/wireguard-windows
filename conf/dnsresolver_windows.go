/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package conf

import (
	"errors"
	"log"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/services"
)

func resolveRedirect(hostUrl string) (host string, port uint16, err error) {
	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	response, err := client.Get(hostUrl)
	if err != nil {
		return "", 0, err
	}
	defer response.Body.Close()
	location := response.Header.Get("Location")
	if location == "" {
		return "", 0, errors.New("No Location Header")
	}
	locationUrl, err := url.Parse(location)
	if err != nil {
		return "", 0, err
	}
	host = locationUrl.Hostname()
	portString := locationUrl.Port()
	if host == "" || portString == "" {
		return "", 0, errors.New("Invalid Location URL")
	}
	portValue, err := strconv.Atoi(portString)
	if err != nil {
		return "", 0, err
	}
	host, err = resolveHostname(host)
	return host, uint16(portValue), err
}

func resolveHostname(name string) (resolvedIPString string, err error) {
	maxTries := 10
	if services.StartedAtBoot() {
		maxTries *= 3
	}
	for i := 0; i < maxTries; i++ {
		if i > 0 {
			time.Sleep(time.Second * 4)
		}
		resolvedIPString, err = resolveHostnameOnce(name)
		if err == nil {
			return
		}
		if err == windows.WSATRY_AGAIN {
			log.Printf("Temporary DNS error when resolving %s, so sleeping for 4 seconds", name)
			continue
		}
		if err == windows.WSAHOST_NOT_FOUND && services.StartedAtBoot() {
			log.Printf("Host not found when resolving %s at boot time, so sleeping for 4 seconds", name)
			continue
		}
		return
	}
	return
}

func resolveHostnameOnce(name string) (resolvedIPString string, err error) {
	hints := windows.AddrinfoW{
		Family:   windows.AF_UNSPEC,
		Socktype: windows.SOCK_DGRAM,
		Protocol: windows.IPPROTO_IP,
	}
	var result *windows.AddrinfoW
	name16, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return
	}
	err = windows.GetAddrInfoW(name16, nil, &hints, &result)
	if err != nil {
		return
	}
	if result == nil {
		err = windows.WSAHOST_NOT_FOUND
		return
	}
	defer windows.FreeAddrInfoW(result)
	var v6 netip.Addr
	for ; result != nil; result = result.Next {
		if result.Family != windows.AF_INET && result.Family != windows.AF_INET6 {
			continue
		}
		addr := (*winipcfg.RawSockaddrInet)(unsafe.Pointer(result.Addr)).Addr()
		if addr.Is4() {
			return addr.String(), nil
		} else if !v6.IsValid() && addr.Is6() {
			v6 = addr
		}
	}
	if v6.IsValid() {
		return v6.String(), nil
	}
	err = windows.WSAHOST_NOT_FOUND
	return
}

func (config *Config) ResolveEndpoints() error {
	for i := range config.Peers {
		if config.Peers[i].Endpoint.IsEmpty() {
			continue
		}
		host := config.Peers[i].Endpoint.Host
		var err error
		if strings.HasPrefix(host, "http://") || strings.HasPrefix(host, "https://") {
			config.Peers[i].Endpoint.Host, config.Peers[i].Endpoint.Port, err = resolveRedirect(host)
		} else {
			config.Peers[i].Endpoint.Host, err = resolveHostname(host)
		}
		if err != nil {
			return err
		}
	}
	return nil
}
