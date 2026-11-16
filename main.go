package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"reflect"
	"runtime/debug"
	"sort"
	"strings"

	"github.com/spf13/cobra"
)

var version = "dev"

func main() {
	log.SetFlags(log.LstdFlags)
	cmd := newRootCmd()
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	if err := cmd.Execute(); err != nil {
		log.Fatal(err)
	}
}

func run(args []string) error {
	cmd := newRootCmd()
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	cmd.SetArgs(args)
	return cmd.Execute()
}

func newRootCmd() *cobra.Command {
	var (
		outputDir          string
		noRestart          bool
		singleProxy        bool
		realityFingerprint string
		dialerProxies      []string
		noHWID             bool
		include            []string
		exclude            []string
		tagFlag            string
		urlFlag            string
		urlFile            string
		tagMapFile         string
		updateFile         string
		backupDir          string
		dryRun             bool
		validate           bool
	)

	cmd := &cobra.Command{
		Use:   "xkeen-subscription-watcher [flags] --tag <tag> --url <url> | <tag>=<url> ...",
		Short: "Обработка подписок и генерация конфигураций для Xray",
		Args:  cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if urlFile != "" {
				if urlFlag != "" {
					return fmt.Errorf("--url и --url-file нельзя использовать вместе")
				}
				data, err := os.ReadFile(urlFile)
				if err != nil {
					return fmt.Errorf("не удалось прочитать --url-file: %w", err)
				}
				urlFlag = strings.TrimSpace(string(data))
				if urlFlag == "" || len(data) > 16384 {
					return fmt.Errorf("--url-file должен содержать один непустой URL подписки")
				}
			}
			args, err := subscriptionArgs(args, tagFlag, urlFlag)
			if err != nil {
				return err
			}
			cfg, err := buildConfig(args, outputDir, !noRestart, singleProxy, realityFingerprint, dialerProxies)
			if err != nil {
				return err
			}
			cfg.sendHWID = !noHWID
			cfg.dryRun = dryRun
			cfg.validate = validate || tagMapFile != ""
			cfg.updateFile = updateFile
			cfg.backupDir = backupDir
			if tagMapFile != "" {
				cfg.tagRules, err = loadTagRules(tagMapFile)
				if err != nil {
					return err
				}
				if len(cfg.subscriptions) != 1 || singleProxy || len(dialerProxies) != 0 {
					return fmt.Errorf("--tag-map требует одну подписку без --single-proxy и --dialer-proxies")
				}
			}
			if updateFile != "" {
				if len(cfg.tagRules) == 0 || filepath.Base(updateFile) != updateFile || strings.ContainsAny(updateFile, "/\\") || !strings.HasSuffix(updateFile, ".json") {
					return fmt.Errorf("--update-file требует --tag-map и имя существующего .json файла внутри --output-dir")
				}
			}
			if tagMapFile != "" && updateFile == "" {
				return fmt.Errorf("--tag-map используется вместе с --update-file для сохранения существующих тегов")
			}
			if cfg.filter, err = newNameFilter(include, exclude); err != nil {
				return err
			}
			return execute(cfg)
		},
	}

	cmd.Flags().StringVar(&tagFlag, "tag", "",
		"Тег подписки: имя файла 04_outbounds.<tag>.json и префикс тегов узлов. Указывается вместе с --url.")
	cmd.Flags().StringVar(&urlFlag, "url", "",
		"URL подписки. Указывается вместе с --tag.")
	cmd.Flags().StringVar(&urlFile, "url-file", "",
		"Файл с URL подписки: секрет не попадает в crontab и аргументы процесса.")
	cmd.Flags().StringVar(&tagMapFile, "tag-map", "",
		"JSON с явным сопоставлением узлов постоянным тегам маршрутизации.")
	cmd.Flags().StringVar(&updateFile, "update-file", "",
		"Обновить выбранные теги в существующем файле внутри --output-dir, сохранив остальные профили.")
	cmd.Flags().StringVar(&backupDir, "backup-dir", "",
		"Каталог резервных копий (по умолчанию subscription-backups рядом с каталогом конфигов).")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false,
		"Проверить изменения, не записывая конфиги и не вызывая API Xray.")
	cmd.Flags().BoolVar(&validate, "validate", false,
		"Проверить полный кандидат через Xray -test; с --update-file включено всегда.")
	cmd.Flags().StringVar(&outputDir, "output-dir", "/opt/etc/xray/configs",
		"Каталог для сохранения сгенерированных конфигураций.")
	cmd.Flags().BoolVar(&noRestart, "no-restart", false,
		"Только записать конфигурации, не применяя их к Xray.")
	cmd.Flags().BoolVar(&singleProxy, "single-proxy", false,
		"Брать только первый прокси из подписки и не добавлять имя к тегу.")
	cmd.Flags().StringVar(&realityFingerprint, "reality-fingerprint", "",
		"Переопределить fingerprint для Reality подключений.")
	cmd.Flags().StringSliceVar(&dialerProxies, "dialer-proxies", nil,
		"Dialer proxies через запятую.")
	cmd.Flags().BoolVar(&noHWID, "no-hwid", false,
		"Не отправлять HWID роутера при запросе подписок.")
	cmd.Flags().StringArrayVar(&include, "include", nil,
		"Оставить только узлы, имя которых подходит под маску (*, ?, [...]); можно указать несколько раз.")
	cmd.Flags().StringArrayVar(&exclude, "exclude", nil,
		"Отбросить узлы, имя которых подходит под маску (*, ?, [...]); можно указать несколько раз.")

	cmd.AddCommand(newVersionCmd())

	return cmd
}

func getVersion() string {
	if version != "dev" {
		return version
	}
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
		return info.Main.Version
	}
	return version
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Показать версию",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			cmd.Println(getVersion())
		},
	}
}

// subscriptionArgs возвращает подписки в виде <tag>=<url>: из --tag и --url, если они заданы,
// иначе из позиционных аргументов.
func subscriptionArgs(positionalArgs []string, tag, url string) ([]string, error) {
	if tag == "" && url == "" {
		if len(positionalArgs) > 0 {
			log.Println("Указание подписок в виде <tag>=<url> устарело и будет удалено в одной из следующих версий. " +
				"Используйте --tag <tag> --url <url>; для нескольких подписок — по строке в crontab на каждую.")
		}
		return positionalArgs, nil
	}
	if tag == "" || url == "" {
		return nil, fmt.Errorf("--tag и --url нужно указывать вместе")
	}
	if len(positionalArgs) > 0 {
		return nil, fmt.Errorf("--tag и --url нельзя совмещать с подписками в виде <tag>=<url>")
	}
	if strings.Contains(tag, "=") {
		return nil, fmt.Errorf("--tag не может содержать «=»: %q", tag)
	}
	return []string{tag + "=" + url}, nil
}

type config struct {
	subscriptions      []subscription
	outputDir          string
	applyToXray        bool
	dialerProxies      []string
	singleProxy        bool
	realityFingerprint string
	sendHWID           bool
	device             *deviceInfo
	filter             nameFilter
	tagRules           []tagRule
	updateFile         string
	backupDir          string
	dryRun             bool
	validate           bool
}

type subscription struct {
	tag string
	url string
}

func buildConfig(
	positionalArgs []string,
	outputDir string,
	applyToXray, singleProxy bool,
	realityFingerprint string,
	dialerProxies []string,
) (config, error) {
	if len(positionalArgs) == 0 {
		return config{}, fmt.Errorf("не указана подписка. Использование: xkeen-subscription-watcher [флаги] --tag <tag> --url <url>")
	}

	var subs []subscription
	tags := make(map[string]bool)
	for _, arg := range positionalArgs {
		tag, u, found := strings.Cut(arg, "=")
		if !found {
			return config{}, fmt.Errorf("неверный формат подписки, ожидается <tag>=<url>")
		}
		if tag == "" || tag == "." || tag == ".." || strings.ContainsAny(tag, "/\\\r\n\x00") {
			return config{}, fmt.Errorf("неверный тег подписки: запрещены пустые имена и разделители пути")
		}
		if tags[tag] {
			return config{}, fmt.Errorf("тег %q указан несколько раз, используйте уникальные имена", tag)
		}
		tags[tag] = true
		if !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
			return config{}, fmt.Errorf("URL должен начинаться на http:// или https://")
		}
		subs = append(subs, subscription{tag: tag, url: u})
	}

	info, err := os.Stat(outputDir)
	if err != nil || !info.IsDir() {
		return config{}, fmt.Errorf("указанный путь для --output-dir %s не является директорией", outputDir)
	}

	return config{
		subscriptions:      subs,
		outputDir:          outputDir,
		applyToXray:        applyToXray,
		dialerProxies:      dialerProxies,
		singleProxy:        singleProxy,
		realityFingerprint: realityFingerprint,
	}, nil
}

type pendingUpdate struct {
	sub        subscription
	path       string
	oldContent []byte
	newContent []byte
}

func (u *pendingUpdate) write(content []byte) error {
	log.Printf("Записываем конфигурацию подписки %q в %s.", u.sub.tag, u.path)
	if err := writeFileAtomic(u.path, content); err != nil {
		return fmt.Errorf("ошибка записи файла %s: %w", u.path, err)
	}
	return nil
}

// writeFileAtomic пишет содержимое во временный файл рядом с path и переименовывает его в
// path. Имя временного файла оканчивается на .tmp, поэтому Xray его не читает.
func writeFileAtomic(path string, content []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)

	if _, err := tmp.Write(content); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpPath, 0600); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}

func execute(cfg config) error {
	unlock, err := lockOutputDir(cfg.outputDir)
	if err != nil {
		return err
	}
	defer unlock()
	if len(cfg.tagRules) > 0 {
		target := cfg.updateFile
		if target == "" {
			target = fmt.Sprintf("04_outbounds.%s.json", cfg.subscriptions[0].tag)
		}
		if err := validateMappedTagOwnership(cfg.outputDir, target, cfg.tagRules); err != nil {
			return err
		}
	}

	if cfg.sendHWID {
		device, err := fetchDeviceInfo()
		if err != nil {
			return fmt.Errorf("не удалось получить HWID роутера, используйте --no-hwid: %w", err)
		}
		log.Println("Отправляем HWID роутера в запросе подписки.")
		cfg.device = device
	}

	var updates []*pendingUpdate
	var preparationErrors []error
	for _, sub := range cfg.subscriptions {
		update, err := prepareUpdate(sub, cfg)
		if err != nil {
			if len(cfg.tagRules) > 0 {
				return fmt.Errorf("подписка %q: %w", sub.tag, err)
			}
			log.Printf("Ошибка при обработке подписки %q, пропускаем: %v", sub.tag, err)
			preparationErrors = append(preparationErrors, err)
			continue
		}
		if update != nil {
			updates = append(updates, update)
		}
	}

	if len(updates) == 0 {
		if len(preparationErrors) > 0 {
			return errors.Join(preparationErrors...)
		}
		log.Println("Изменений в подписках не найдено, завершаем работу.")
		return nil
	}
	if cfg.validate {
		if err := validatePendingUpdates(cfg.outputDir, updates); err != nil {
			return err
		}
	}
	if cfg.dryRun {
		log.Printf("Проверка завершена: изменится файлов %d; конфиги и работающий Xray не изменены.", len(updates))
		return nil
	}
	backupDir := cfg.backupDir
	if backupDir == "" {
		backupDir = filepath.Join(filepath.Dir(filepath.Clean(cfg.outputDir)), "subscription-backups")
	}
	// Xray loads .json files in confdir; backups must stay outside it.
	outputAbs, err := filepath.Abs(cfg.outputDir)
	if err != nil {
		return err
	}
	backupAbs, err := filepath.Abs(backupDir)
	if err != nil {
		return err
	}
	if rel, err := filepath.Rel(outputAbs, backupAbs); err != nil || rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))) {
		return fmt.Errorf("--backup-dir должен находиться вне каталога конфигов")
	}

	if !cfg.applyToXray {
		for _, update := range updates {
			if err := ensureUpdateUnchanged(update); err != nil {
				return err
			}
			if err := backupPendingUpdate(update, backupDir); err != nil {
				return err
			}
			if err := update.write(update.newContent); err != nil {
				return err
			}
		}
		return nil
	}

	addr, err := findAPIAddress(cfg.outputDir)
	if err != nil {
		return err
	}
	api := xrayAPI{addr: addr}

	var errs []error
	for _, update := range updates {
		if err := ensureUpdateUnchanged(update); err != nil {
			return err
		}
		if err := backupPendingUpdate(update, backupDir); err != nil {
			return err
		}
		apply := applyUpdate
		if cfg.updateFile != "" {
			apply = applyManagedUpdate
		}
		if err := apply(api, update); err != nil {
			errs = append(errs, fmt.Errorf("подписка %q: %w", update.sub.tag, err))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("не удалось применить изменения подписок:\n%w", errors.Join(errs...))
	}
	return nil
}

func applyUpdate(api outboundAPI, update *pendingUpdate) error {
	oldOutbounds, err := parseOutboundsFile(update.oldContent)
	if err != nil {
		return fmt.Errorf("ошибка разбора файла %s: %w", update.path, err)
	}
	newOutbounds, err := parseOutboundsFile(update.newContent)
	if err != nil {
		return fmt.Errorf("ошибка разбора новой конфигурации: %w", err)
	}
	changes := diffOutbounds(oldOutbounds, newOutbounds)
	log.Printf("Применяем изменения подписки %q к Xray: %d добавлено или изменено, %d удалено.",
		update.sub.tag, len(changes.upserts), len(changes.removals))
	failed, applyErr := applyChanges(api, changes)
	if applyErr == nil {
		return update.write(update.newContent)
	}

	appliedList := appliedOutbounds(oldOutbounds, newOutbounds, failed)
	if reflect.DeepEqual(outboundsByTag(appliedList), outboundsByTag(oldOutbounds)) {
		return applyErr
	}
	applied, err := marshalOutbounds(appliedList)
	if err != nil {
		return errors.Join(applyErr, err)
	}
	log.Printf("Изменения подписки %q применены частично, сохраняем применённую часть.", update.sub.tag)
	if err := update.write(applied); err != nil {
		return errors.Join(applyErr, err)
	}
	return applyErr
}

// prepareUpdate получает подписку и генерирует новое содержимое файла, ничего не записывая.
// Возвращает nil, если содержимое не изменилось.
func prepareUpdate(sub subscription, cfg config) (*pendingUpdate, error) {
	outputPath := filepath.Join(cfg.outputDir, fmt.Sprintf("04_outbounds.%s.json", sub.tag))
	if cfg.updateFile != "" {
		outputPath = filepath.Join(cfg.outputDir, cfg.updateFile)
	}
	existingContent, err := os.ReadFile(outputPath)
	if err != nil {
		if !os.IsNotExist(err) || cfg.updateFile != "" {
			return nil, fmt.Errorf("не удалось прочитать целевой файл: %w", err)
		}
		existingContent = nil
	}
	if existingContent != nil && !json.Valid(existingContent) {
		return nil, fmt.Errorf("неверный JSON в файле %s", filepath.Base(outputPath))
	}

	outbounds, err := getOutbounds(sub, cfg)
	if err != nil {
		return nil, err
	}

	newContent, err := marshalOutbounds(outbounds)
	if cfg.updateFile != "" {
		newContent, err = mergeManagedOutbounds(existingContent, outbounds)
	}
	if err != nil {
		return nil, err
	}

	if bytes.Equal(existingContent, newContent) || equalJSON(existingContent, newContent) {
		log.Printf("Изменения в подписке %q не найдены, пропускаем.", sub.tag)
		return nil, nil
	}

	return &pendingUpdate{
		sub:        sub,
		path:       outputPath,
		oldContent: existingContent,
		newContent: newContent,
	}, nil
}

func equalJSON(left, right []byte) bool {
	var a, b any
	if json.Unmarshal(left, &a) != nil || json.Unmarshal(right, &b) != nil {
		return false
	}
	return reflect.DeepEqual(a, b)
}

func getOutbounds(sub subscription, cfg config) ([]any, error) {
	log.Printf("Запрашиваем подписку %q.", sub.tag)

	proxyURLs, err := fetchProxyURLs(sub, cfg.device)
	if err != nil {
		return nil, err
	}
	sort.Strings(proxyURLs)
	if len(cfg.tagRules) > 0 {
		return getMappedOutbounds(proxyURLs, cfg)
	}

	tagCounters := make(map[string]int)
	var result []any

	filtered := 0
	for _, proxyURL := range proxyURLs {
		if !cfg.filter.allows(rawProxyName(proxyURL)) {
			filtered++
			continue
		}

		p, err := parseProxyURL(proxyURL)
		if err != nil {
			log.Printf("Не удалось разобрать узел из подписки %q, пропускаем (параметры подключения скрыты).", sub.tag)
			continue
		}

		tag := sub.tag
		if !cfg.singleProxy {
			if name := getProxyName(proxyURL); name != "" {
				tag = tag + "--" + name
			}
		}

		tagCounters[tag]++
		if tagCounters[tag] > 1 {
			tag = fmt.Sprintf("%s--%d", tag, tagCounters[tag])
		}

		result = append(result, generateOutbound(p, tag, cfg.realityFingerprint, ""))
		for _, dp := range cfg.dialerProxies {
			result = append(result, generateOutbound(p, tag+"--"+dp, cfg.realityFingerprint, dp))
		}

		if cfg.singleProxy {
			break
		}
	}

	if filtered > 0 {
		log.Printf("В подписке %q отфильтровано узлов по --include/--exclude: %d.", sub.tag, filtered)
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("подписка не содержит подходящих поддерживаемых узлов; рабочий файл сохранён")
	}
	return result, nil
}
