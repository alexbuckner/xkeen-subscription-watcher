package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// A rule assigns a deliberately chosen routing tag to exactly one source node.
// Endpoint addresses and credentials are not identities: providers rotate them.
type tagRule struct {
	Name     string  `json:"name"`
	Protocol string  `json:"protocol"`
	Network  string  `json:"network,omitempty"`
	Security string  `json:"security,omitempty"`
	Tag      string  `json:"tag"`
	Flow     *string `json:"flow,omitempty"`
	pattern  string
}

func loadTagRules(filename string) ([]tagRule, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("не удалось прочитать --tag-map: %w", err)
	}
	var document struct {
		Rules []tagRule `json:"rules"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		return nil, fmt.Errorf("неверный JSON --tag-map")
	}
	if decoder.Decode(new(any)) != io.EOF || len(document.Rules) == 0 {
		return nil, fmt.Errorf("--tag-map должен содержать непустой массив rules и один JSON-объект")
	}
	tags := make(map[string]bool)
	for i := range document.Rules {
		rule := &document.Rules[i]
		if rule.Name == "" || strings.TrimSpace(rule.Tag) == "" || strings.ContainsAny(rule.Tag, "\r\n\x00") {
			return nil, fmt.Errorf("правило --tag-map №%d: нужны name и непустой tag", i+1)
		}
		if tags[rule.Tag] {
			return nil, fmt.Errorf("--tag-map: повторный целевой тег %q", rule.Tag)
		}
		tags[rule.Tag] = true
		rule.Protocol = canonicalProtocol(rule.Protocol)
		switch rule.Protocol {
		case "vless", "vmess", "trojan", "ss", "hysteria2":
		default:
			return nil, fmt.Errorf("правило --tag-map №%d: неподдерживаемый protocol", i+1)
		}
		rule.Network = canonicalNetwork(rule.Network)
		rule.Security = strings.ToLower(rule.Security)
		if rule.Flow != nil && (rule.Protocol != "vless" || (*rule.Flow != "" && *rule.Flow != "xtls-rprx-vision" && *rule.Flow != "xtls-rprx-vision-udp443")) {
			return nil, fmt.Errorf("правило --tag-map №%d: неверный flow для VLESS", i+1)
		}
		pattern, err := normalizeGlob(rule.Name)
		if err != nil {
			return nil, fmt.Errorf("правило --tag-map №%d: неверная маска name", i+1)
		}
		rule.pattern = pattern
	}
	return document.Rules, nil
}

func canonicalProtocol(protocol string) string {
	protocol = strings.ToLower(protocol)
	if protocol == "hy2" {
		return "hysteria2"
	}
	return protocol
}

func canonicalNetwork(network string) string {
	network = strings.ToLower(network)
	if network == "raw" {
		return "tcp"
	}
	return network
}

func proxyIdentity(p proxy) (protocol, network, security string) {
	switch p := p.(type) {
	case vlessProxy:
		return "vless", canonicalNetwork(p.network), p.security
	case vmessProxy:
		return "vmess", canonicalNetwork(p.network), p.streamParams.security
	case trojanProxy:
		return "trojan", canonicalNetwork(p.network), p.security
	case shadowSocksProxy:
		return "ss", "", ""
	case hysteria2Proxy:
		return "hysteria2", "hysteria", "tls"
	}
	return "", "", ""
}

func (rule tagRule) matches(p proxy, name string) bool {
	protocol, network, security := proxyIdentity(p)
	matched, _ := path.Match(rule.pattern, normalizeName(name))
	return matched && protocol == rule.Protocol &&
		(rule.Network == "" || network == rule.Network) &&
		(rule.Security == "" || security == rule.Security)
}

func getMappedOutbounds(proxyURLs []string, cfg config) ([]any, error) {
	matches := make([][]proxy, len(cfg.tagRules))
	seen := make(map[string]bool)
	for i, raw := range proxyURLs {
		if seen[raw] || !cfg.filter.allows(rawProxyName(raw)) {
			continue
		}
		seen[raw] = true
		scheme, _, _ := strings.Cut(raw, ":")
		potential := false
		for _, rule := range cfg.tagRules {
			nameMatches, _ := path.Match(rule.pattern, normalizeName(rawProxyName(raw)))
			if canonicalProtocol(scheme) == rule.Protocol && nameMatches {
				potential = true
				break
			}
		}
		if !potential {
			continue
		}
		p, err := parseProxyURL(raw)
		if err != nil {
			// Neither parser errors nor raw URLs are logged: either can contain auth.
			return nil, fmt.Errorf("не удалось разобрать узел №%d; обновление с --tag-map отменено", i+1)
		}
		for j, rule := range cfg.tagRules {
			if rule.matches(p, rawProxyName(raw)) {
				matches[j] = append(matches[j], p)
			}
		}
	}
	result := make([]any, 0, len(cfg.tagRules))
	for i, rule := range cfg.tagRules {
		if len(matches[i]) != 1 {
			return nil, fmt.Errorf("тег %q: найдено узлов %d вместо одного; рабочая конфигурация сохранена", rule.Tag, len(matches[i]))
		}
		p := matches[i][0]
		if rule.Flow != nil {
			vless := p.(vlessProxy)
			vless.flow = *rule.Flow
			p = vless
		}
		result = append(result, generateOutbound(p, rule.Tag, cfg.realityFingerprint, ""))
	}
	return result, nil
}

// A mapped routing tag must be owned by one file. Native Xray merges duplicate
// tags rather than rejecting them, which otherwise makes API and restart differ.
func validateMappedTagOwnership(confdir, target string, rules []tagRule) error {
	selected := make(map[string]bool, len(rules))
	for _, rule := range rules {
		selected[rule.Tag] = true
	}
	entries, err := os.ReadDir(confdir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() || !isXrayConfigFile(entry.Name()) || entry.Name() == target {
			continue
		}
		output, err := runXray(xrayDumpTimeout, nil, "run", "-dump", "-config", filepath.Join(confdir, entry.Name()))
		if err != nil {
			return fmt.Errorf("не удалось проверить владельцев тегов в файле %s: %w", entry.Name(), err)
		}
		var document struct {
			Outbounds []struct {
				Tag string `json:"tag"`
			} `json:"outbounds"`
		}
		if json.Unmarshal(output, &document) != nil {
			return fmt.Errorf("не удалось разобрать результат Xray для файла %s", entry.Name())
		}
		for _, outbound := range document.Outbounds {
			if selected[outbound.Tag] {
				return fmt.Errorf("тег %q уже определён в другом файле %s; обновление отменено", outbound.Tag, entry.Name())
			}
		}
	}
	return nil
}

// Preserve every unselected outbound, its position, and unrelated document keys.
// Requiring an existing target prevents an accidental routing migration.
func mergeManagedOutbounds(original []byte, replacements []any) ([]byte, error) {
	var document map[string]json.RawMessage
	if err := json.Unmarshal(original, &document); err != nil || document == nil {
		return nil, fmt.Errorf("--update-file: неверный JSON существующего файла")
	}
	var outbounds []json.RawMessage
	if err := json.Unmarshal(document["outbounds"], &outbounds); err != nil || len(outbounds) == 0 {
		return nil, fmt.Errorf("--update-file: нужен непустой массив outbounds")
	}
	positions := make(map[string]int)
	for i, raw := range outbounds {
		var entry struct {
			Tag string `json:"tag"`
		}
		if err := json.Unmarshal(raw, &entry); err != nil || entry.Tag == "" {
			return nil, fmt.Errorf("--update-file: outbound без тега или неверного типа")
		}
		if _, exists := positions[entry.Tag]; exists {
			return nil, fmt.Errorf("--update-file: повторный тег %q", entry.Tag)
		}
		positions[entry.Tag] = i
	}
	for _, replacement := range replacements {
		outbound, ok := replacement.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("--update-file: неверный тип нового outbound")
		}
		tag := outboundTag(outbound)
		position, found := positions[tag]
		if !found {
			return nil, fmt.Errorf("--update-file: целевой тег %q отсутствует; сначала настройте его вручную", tag)
		}
		var previous map[string]any
		decoder := json.NewDecoder(bytes.NewReader(outbounds[position]))
		decoder.UseNumber()
		if decoder.Decode(&previous) != nil {
			return nil, fmt.Errorf("--update-file: не удалось прочитать прежний outbound")
		}
		preserveLocalOutboundOptions(previous, outbound)
		encoded, err := json.Marshal(outbound)
		if err != nil {
			return nil, fmt.Errorf("--update-file: не удалось сериализовать outbound")
		}
		outbounds[position] = encoded
	}
	document["outbounds"], _ = json.Marshal(outbounds)
	encoded, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("--update-file: не удалось сериализовать документ")
	}
	return append(encoded, '\n'), nil
}

// These options are local policy, not subscription connection parameters.
// Preserve them when refreshing a server of the same protocol.
func preserveLocalOutboundOptions(previous, next map[string]any) {
	if previous["protocol"] != next["protocol"] {
		return
	}
	for key, value := range previous {
		switch key {
		case "tag", "protocol", "settings", "streamSettings":
		default:
			if _, exists := next[key]; !exists {
				next[key] = value
			}
		}
	}
	oldSettings, _ := previous["settings"].(map[string]any)
	newSettings, _ := next["settings"].(map[string]any)
	if previous["protocol"] == "vless" || previous["protocol"] == "vmess" {
		if value, exists := oldSettings["packetEncoding"]; exists {
			newSettings["packetEncoding"] = value
		}
		oldServers, _ := oldSettings["vnext"].([]any)
		newServers, _ := newSettings["vnext"].([]any)
		if len(oldServers) == 1 && len(newServers) == 1 {
			oldServer, _ := oldServers[0].(map[string]any)
			newServer, _ := newServers[0].(map[string]any)
			oldUsers, _ := oldServer["users"].([]any)
			newUsers, _ := newServer["users"].([]any)
			if len(oldUsers) == 1 && len(newUsers) == 1 {
				oldUser, _ := oldUsers[0].(map[string]any)
				newUser, _ := newUsers[0].(map[string]any)
				for _, key := range []string{"level", "email"} {
					if value, exists := oldUser[key]; exists {
						newUser[key] = value
					}
				}
			}
		}
	}
	oldStream, _ := previous["streamSettings"].(map[string]any)
	newStream, _ := next["streamSettings"].(map[string]any)
	if newStream == nil {
		return
	}
	if value, exists := oldStream["sockopt"]; exists {
		newStream["sockopt"] = value
	}
	if previous["protocol"] == "hysteria" {
		oldHysteria, _ := oldStream["hysteriaSettings"].(map[string]any)
		newHysteria, _ := newStream["hysteriaSettings"].(map[string]any)
		if newHysteria != nil {
			if value, exists := oldHysteria["keepAlivePeriod"]; exists {
				newHysteria["keepAlivePeriod"] = value
			} else {
				delete(newHysteria, "keepAlivePeriod")
			}
		}
		oldTLS, _ := oldStream["tlsSettings"].(map[string]any)
		newTLS, _ := newStream["tlsSettings"].(map[string]any)
		if _, existed := oldTLS["allowInsecure"]; !existed && newTLS["allowInsecure"] == false {
			delete(newTLS, "allowInsecure") // omitted and false both verify certificates
		}
	}
}
