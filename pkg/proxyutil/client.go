package proxyutil

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"golang.org/x/net/proxy"
)

const (
	// Имя ключа в creds.json (адрес прокси)
	KeySocksProxy = "socks5_proxy"
	// Имя поля в JS (defaults.js), запрещающего прямые соединения
	KeyRejectDirect = "reject_direct_connection"
)

// Структура для парсинга метаданных из JS
type proxyMeta struct {
	RejectDirect string `json:"reject_direct_connection"`
}

// MakeHTTPClient создает клиент, объединяя настройки из creds.json (config) и dnsconfig.js (metadata)
func MakeHTTPClient(providerName string, config map[string]string, metadata json.RawMessage) (*http.Client, error) {
	// 1. Извлекаем настройки прокси из creds.json
	socksProxyAddr := config[KeySocksProxy]

	// 2. Извлекаем флаг запрета из метаданных (JS)
	var strictMode bool
	if len(metadata) > 0 {
		var pm proxyMeta
		if err := json.Unmarshal(metadata, &pm); err == nil {
			if pm.RejectDirect == "true" || pm.RejectDirect == "1" {
				strictMode = true
			}
		}
	}

	// ЛОГИКА БЕЗОПАСНОСТИ:
	// Если strictMode=true (из JS), но socks5_proxy не задан (в creds) -> ОШИБКА.
	if strictMode && socksProxyAddr == "" {
		return nil, fmt.Errorf(
			"\n⛔ SECURITY ERROR [%s]:\n"+
			"В JS-конфиге установлен флаг '%s: true'.\n"+
			"Но в creds.json не указан '%s'.\n"+
			"Прямое соединение заблокировано!",
			providerName, KeyRejectDirect, KeySocksProxy,
		)
	}

	// Настраиваем транспорт
	baseTransport := &http.Transport{
		MaxIdleConns:        100,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
	}

	if socksProxyAddr != "" {
		dialer, err := proxy.SOCKS5("tcp", socksProxyAddr, nil, proxy.Direct)
		if err != nil {
			return nil, fmt.Errorf("ошибка создания SOCKS5 для %s: %v", providerName, err)
		}
		baseTransport.Dial = dialer.Dial
		fmt.Printf("🔒 [%s] Using Proxy: %s\n", providerName, socksProxyAddr)
	} else {
		// Если прокси нет и строгий режим выключен
		fmt.Printf("⚠️ [%s] Direct connection (No Proxy)\n", providerName)
	}

	return &http.Client{
		Transport: baseTransport,
		Timeout:   time.Minute * 2,
	}, nil
}
