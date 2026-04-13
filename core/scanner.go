package core

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// SensitiveLevel 敏感信息风险等级
type SensitiveLevel string

const (
	LevelHigh   SensitiveLevel = "高危"
	LevelMedium SensitiveLevel = "中危"
	LevelLow    SensitiveLevel = "低危"
)

// ScanResult 单条敏感信息扫描结果
type ScanResult struct {
	WxID     string
	AppName  string
	Category string
	Level    SensitiveLevel
	KeyName  string
	Value    string
	FilePath string
	LineNo   int
}

// sensitivePattern 匹配规则
type sensitivePattern struct {
	category   string
	keyName    string
	level      SensitiveLevel
	regex      *regexp.Regexp
	valueGroup int // 0=全匹配，1+=捕获组
}

var sensitivePatterns = []sensitivePattern{
	// ══════ 微信小程序 ══════
	{
		category: "微信·AppSecret", keyName: "AppSecret", level: LevelHigh,
		regex:      regexp.MustCompile(`(?i)["']?app[_-]?secret["']?\s*[:=]\s*["']([a-zA-Z0-9]{32})["']`),
		valueGroup: 1,
	},
	{
		category: "微信·支付密钥", keyName: "MchKey/PaySignKey", level: LevelHigh,
		regex:      regexp.MustCompile(`(?i)["']?(?:pay[_-]?sign[_-]?key|mch[_-]?key|partner[_-]?key|paykey)["']?\s*[:=]\s*["']([a-zA-Z0-9]{32})["']`),
		valueGroup: 1,
	},
	{
		category: "微信·商户号", keyName: "MchID", level: LevelMedium,
		regex:      regexp.MustCompile(`(?i)["']?(?:mch[_-]?id|mchid|merchant[_-]?id)["']?\s*[:=]\s*["']?(\d{8,15})["']?`),
		valueGroup: 1,
	},

	// ══════ 腾讯云 ══════
	{
		category: "腾讯云·SecretId", keyName: "SecretId", level: LevelHigh,
		regex:      regexp.MustCompile(`(?i)["']?secret[_-]?id["']?\s*[:=]\s*["']([A-Za-z0-9]{36,40})["']`),
		valueGroup: 1,
	},
	{
		category: "腾讯云·SecretKey", keyName: "SecretKey", level: LevelHigh,
		regex:      regexp.MustCompile(`(?i)["']?secret[_-]?key["']?\s*[:=]\s*["']([A-Za-z0-9]{32,40})["']`),
		valueGroup: 1,
	},
	{
		category: "腾讯云·COS桶", keyName: "COSBucket", level: LevelLow,
		regex:      regexp.MustCompile(`([\w-]+-\d{9,13}\.cos\.[a-z0-9-]+\.myqcloud\.com)`),
		valueGroup: 1,
	},
	{
		category: "腾讯云·短信", keyName: "SMSAppKey", level: LevelHigh,
		regex:      regexp.MustCompile(`(?i)["']?sms[_-]?(?:app[_-]?)?key["']?\s*[:=]\s*["']([a-zA-Z0-9]{32,40})["']`),
		valueGroup: 1,
	},

	// ══════ 阿里云 ══════
	{
		category: "阿里云·AccessKeyId", keyName: "AccessKeyId", level: LevelHigh,
		regex:      regexp.MustCompile(`(?i)["']?access[_-]?key[_-]?id["']?\s*[:=]\s*["']([A-Za-z0-9]{20,24})["']`),
		valueGroup: 1,
	},
	{
		category: "阿里云·AccessKeySecret", keyName: "AccessKeySecret", level: LevelHigh,
		regex:      regexp.MustCompile(`(?i)["']?access[_-]?key[_-]?secret["']?\s*[:=]\s*["']([A-Za-z0-9]{28,36})["']`),
		valueGroup: 1,
	},
	{
		category: "阿里云·OSS端点", keyName: "OSSEndpoint", level: LevelLow,
		regex:      regexp.MustCompile(`([\w-]+\.oss(?:-[a-z0-9-]+)?\.aliyuncs\.com)`),
		valueGroup: 1,
	},

	// ══════ AWS ══════
	{
		category: "AWS·AccessKeyId", keyName: "AccessKeyId", level: LevelHigh,
		regex:      regexp.MustCompile(`(AKIA[0-9A-Z]{16})`),
		valueGroup: 1,
	},
	{
		category: "AWS·SecretKey", keyName: "SecretAccessKey", level: LevelHigh,
		regex:      regexp.MustCompile(`(?i)["']?aws[_-]?secret[_-]?(?:access[_-]?)?key["']?\s*[:=]\s*["']([a-zA-Z0-9+/]{40})["']`),
		valueGroup: 1,
	},

	// ══════ 七牛云 ══════
	{
		category: "七牛云·AccessKey", keyName: "AccessKey", level: LevelHigh,
		regex:      regexp.MustCompile(`(?i)["']?(?:qiniu[_-]?)?access[_-]?key["']?\s*[:=]\s*["']([a-zA-Z0-9_\-]{40,60})["']`),
		valueGroup: 1,
	},
	{
		category: "七牛云·SecretKey", keyName: "SecretKey", level: LevelHigh,
		regex:      regexp.MustCompile(`(?i)["']?(?:qiniu[_-]?)?secret[_-]?key["']?\s*[:=]\s*["']([a-zA-Z0-9_\-]{40,60})["']`),
		valueGroup: 1,
	},

	// ══════ 华为云 ══════
	{
		category: "华为云·AccessKey", keyName: "HWAccessKey", level: LevelHigh,
		regex:      regexp.MustCompile(`(?i)["']?hw[_-]?access[_-]?key["']?\s*[:=]\s*["']([A-Z0-9]{20})["']`),
		valueGroup: 1,
	},

	// ══════ 数据库 ══════
	{
		category: "数据库·MongoDB", keyName: "MongoDB URL", level: LevelHigh,
		regex:      regexp.MustCompile(`(mongodb(?:\+srv)?://[^\s"'<>\]]{10,})`),
		valueGroup: 1,
	},
	{
		category: "数据库·MySQL", keyName: "MySQL URL", level: LevelHigh,
		regex:      regexp.MustCompile(`(mysql://[^\s"'<>\]]{10,})`),
		valueGroup: 1,
	},
	{
		category: "数据库·Redis", keyName: "Redis URL", level: LevelMedium,
		regex:      regexp.MustCompile(`(redis://[^\s"'<>\]]{6,})`),
		valueGroup: 1,
	},

	// ══════ 通用 ══════
	{
		category: "通用·APIKey", keyName: "ApiKey", level: LevelMedium,
		regex:      regexp.MustCompile(`(?i)["']?api[_-]?key["']?\s*[:=]\s*["']([a-zA-Z0-9_\-]{16,64})["']`),
		valueGroup: 1,
	},
	{
		category: "通用·Token", keyName: "Token/AuthToken", level: LevelMedium,
		regex:      regexp.MustCompile(`(?i)["']?(?:auth[_-]?)?token["']?\s*[:=]\s*["']([a-zA-Z0-9_\-\.]{24,128})["']`),
		valueGroup: 1,
	},
	{
		category: "通用·密码", keyName: "Password", level: LevelMedium,
		regex:      regexp.MustCompile(`(?i)["']?(?:password|passwd|pwd)["']?\s*[:=]\s*["']([^"']{6,32})["']`),
		valueGroup: 1,
	},
	{
		category: "服务器·内网IP", keyName: "PrivateIP", level: LevelLow,
		regex:      regexp.MustCompile(`["'/]((?:192\.168|10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3})(?::\d+)?["'/]`),
		valueGroup: 1,
	},
}

// 要扫描的文件后缀
var scanExtensions = map[string]bool{
	".js": true, ".json": true, ".ts": true, ".wxs": true,
}

const maxFileSize = 2 * 1024 * 1024 // 2MB，超过跳过

// ScanDecompiledDir 扫描反编译目录，提取敏感信息
func ScanDecompiledDir(wxid, appName, decompiledDir string, logFunc func(string)) []*ScanResult {
	if appName == "" {
		appName = wxid
	}
	logFunc(fmt.Sprintf("[扫描] 开始提取敏感信息 → %s", appName))

	seen := make(map[string]bool)
	var results []*ScanResult

	_ = filepath.Walk(decompiledDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info == nil || info.IsDir() {
			return nil
		}
		if !scanExtensions[strings.ToLower(filepath.Ext(path))] {
			return nil
		}
		if info.Size() > maxFileSize {
			return nil
		}
		results = append(results, scanFile(path, wxid, appName, seen)...)
		return nil
	})

	high, mid, low := countLevels(results)
	logFunc(fmt.Sprintf("[扫描] %s 完成 → 高危%d 中危%d 低危%d，共%d条", appName, high, mid, low, len(results)))
	return results
}

func countLevels(results []*ScanResult) (high, mid, low int) {
	for _, r := range results {
		switch r.Level {
		case LevelHigh:
			high++
		case LevelMedium:
			mid++
		case LevelLow:
			low++
		}
	}
	return
}

func scanFile(path, wxid, appName string, seen map[string]bool) []*ScanResult {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var results []*ScanResult
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)

	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := sc.Text()

		for _, pat := range sensitivePatterns {
			matches := pat.regex.FindStringSubmatch(line)
			if matches == nil {
				continue
			}
			var value string
			if pat.valueGroup == 0 || pat.valueGroup >= len(matches) {
				value = matches[0]
			} else {
				value = matches[pat.valueGroup]
			}
			if value == "" {
				continue
			}

			key := pat.category + ":" + value
			if seen[key] {
				continue
			}
			seen[key] = true

			display := value
			if len(display) > 80 {
				display = display[:77] + "..."
			}

			results = append(results, &ScanResult{
				WxID:     wxid,
				AppName:  appName,
				Category: pat.category,
				Level:    pat.level,
				KeyName:  pat.keyName,
				Value:    display,
				FilePath: path,
				LineNo:   lineNo,
			})
		}
	}
	return results
}

// ResolveNameFromDecompiledDir 从反编译输出目录中读取真实小程序名称。
// 优先读取 project.config.json → "projectname"；
// 回退读取 app.json → "window" → "navigationBarTitleText"。
func ResolveNameFromDecompiledDir(decompiledDir string) string {
	// 策略1: project.config.json
	if name := readProjectConfigName(decompiledDir); name != "" {
		return name
	}
	// 策略2: app.json window.navigationBarTitleText
	if name := readAppJsonTitle(decompiledDir); name != "" {
		return name
	}
	return ""
}

func readProjectConfigName(root string) string {
	candidates := []string{
		filepath.Join(root, "project.config.json"),
	}
	// 也搜索一级子目录（反编译后有时会放在子文件夹里）
	entries, _ := os.ReadDir(root)
	for _, e := range entries {
		if e.IsDir() {
			candidates = append(candidates, filepath.Join(root, e.Name(), "project.config.json"))
		}
	}
	for _, p := range candidates {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		var obj map[string]interface{}
		if err := json.Unmarshal(data, &obj); err != nil {
			continue
		}
		if v, ok := obj["projectname"]; ok {
			if s, ok := v.(string); ok && strings.TrimSpace(s) != "" {
				return strings.TrimSpace(s)
			}
		}
	}
	return ""
}

func readAppJsonTitle(root string) string {
	candidates := []string{
		filepath.Join(root, "app.json"),
	}
	entries, _ := os.ReadDir(root)
	for _, e := range entries {
		if e.IsDir() {
			candidates = append(candidates, filepath.Join(root, e.Name(), "app.json"))
		}
	}
	for _, p := range candidates {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		var obj map[string]interface{}
		if err := json.Unmarshal(data, &obj); err != nil {
			continue
		}
		if winObj, ok := obj["window"].(map[string]interface{}); ok {
			if v, ok := winObj["navigationBarTitleText"]; ok {
				if s, ok := v.(string); ok && strings.TrimSpace(s) != "" {
					return strings.TrimSpace(s)
				}
			}
		}
	}
	return ""
}
