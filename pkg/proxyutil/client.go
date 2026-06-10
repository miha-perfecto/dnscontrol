package proxyutil

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"golang.org/x/net/proxy"
)

const (
	KeySocksProxy   = "socks5_proxy"
	KeyRejectDirect = "reject_direct_connection"
)

type proxyMeta struct {
	RejectDirect string `json:"reject_direct_connection"`
}

func MakeHTTPClient(providerName string, config map[string]string, metadata json.RawMessage) (*http.Client, error) {
	socksProxyAddr := config[KeySocksProxy]

	var strictMode bool
	if len(metadata) > 0 {
		var pm proxyMeta
		if err := json.Unmarshal(metadata, &pm); err == nil {
			if pm.RejectDirect == "true" || pm.RejectDirect == "1" {
				strictMode = true
			}
		}
	}

	if strictMode && socksProxyAddr == "" {
		return nil, fmt.Errorf(
			"\n⛔ SECURITY ERROR [%s]:\n"+
				"В JS-конфиге установлен флаг '%s: true'.\n"+
				"Но в creds.json не указан '%s'.\n"+
				"Прямое соединение заблокировано!",
			providerName, KeyRejectDirect, KeySocksProxy,
		)
	}

	baseTransport := &http.Transport{
		MaxIdleConns:        100,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
	}

	if socksProxyAddr != "" {
		var dialer proxy.Dialer
		var err error

		if strings.Contains(socksProxyAddr, "@") {
			parts := strings.SplitN(socksProxyAddr, "@", 2)
			if len(parts) == 2 {
				userInfo := parts[0]
				hostPort := parts[1]

				authParts := strings.SplitN(userInfo, ":", 2)
				var auth *proxy.Auth
				if len(authParts) == 2 {
					auth = &proxy.Auth{
						User:     authParts[0],
						Password: authParts[1],
					}
				} else {
					auth = nil
				}

				dialer, err = proxy.SOCKS5("tcp", hostPort, auth, proxy.Direct)
			} else {
				return nil, fmt.Errorf("неверный формат прокси: %s", socksProxyAddr)
			}
		} else {
			dialer, err = proxy.SOCKS5("tcp", socksProxyAddr, nil, proxy.Direct)
		}

		if err != nil {
			return nil, fmt.Errorf("ошибка создания SOCKS5 для %s: %v", providerName, err)
		}
		baseTransport.Dial = dialer.Dial
		fmt.Printf("🔒 [%s] Using Proxy: %s\n", providerName, socksProxyAddr)
	} else {
		fmt.Printf("⚠️ [%s] Direct connection (No Proxy)\n", providerName)
	}

	return &http.Client{
		Transport: baseTransport,
		Timeout:   time.Minute * 2,
	}, nil
}
