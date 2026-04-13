package core

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
)

// WatcherConfig 监控配置
type WatcherConfig struct {
	WatchDir           string // 监控目录
	OutputDir          string // 输出目录
	DecompileOpts      DecompileOptions
	LogFunc            func(string)        // 日志回调
	OnDecompileResult  func(*DecompileResult) // 反编译完成回调（用于触发扫描）
}

// Watcher 文件夹监控器
type Watcher struct {
	config    WatcherConfig
	fswatcher *fsnotify.Watcher
	stopCh    chan struct{}
	mu        sync.Mutex
	running   bool
	processed map[string]time.Time // 防止重复处理
}

// NewWatcher 创建新的监控器
func NewWatcher(config WatcherConfig) *Watcher {
	return &Watcher{
		config:    config,
		stopCh:    make(chan struct{}),
		processed: make(map[string]time.Time),
	}
}

var regWxDir = regexp.MustCompile(`(wx[0-9a-f]{16})`)

// GetWxDirRegex 返回小程序目录名正则（供外部包使用）
func GetWxDirRegex() *regexp.Regexp {
	return regWxDir
}

// Start 启动监控
func (w *Watcher) Start() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.running {
		return fmt.Errorf("监控器已在运行中")
	}

	if _, err := os.Stat(w.config.WatchDir); os.IsNotExist(err) {
		return fmt.Errorf("监控目录不存在: %s", w.config.WatchDir)
	}

	fswatcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("创建文件监控失败: %v", err)
	}
	w.fswatcher = fswatcher

	// 先对已有的小程序目录执行反编译
	w.config.LogFunc(fmt.Sprintf("[*] 启动监控: %s", w.config.WatchDir))
	w.scanAndDecompileExisting()

	// 监控根目录
	if err := fswatcher.Add(w.config.WatchDir); err != nil {
		fswatcher.Close()
		return fmt.Errorf("添加监控路径失败: %v", err)
	}
	w.config.LogFunc(fmt.Sprintf("[*] 正在监控目录: %s", w.config.WatchDir))

	// 监控已有的子目录
	w.addSubDirsToWatcher(w.config.WatchDir)

	w.stopCh = make(chan struct{})
	w.running = true

	go w.watchLoop()
	return nil
}

// Stop 停止监控
func (w *Watcher) Stop() {
	w.mu.Lock()
	defer w.mu.Unlock()

	if !w.running {
		return
	}
	close(w.stopCh)
	w.fswatcher.Close()
	w.running = false
	w.config.LogFunc("[*] 监控已停止")
}

// IsRunning 是否正在运行
func (w *Watcher) IsRunning() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.running
}

// watchLoop 事件处理循环
func (w *Watcher) watchLoop() {
	for {
		select {
		case <-w.stopCh:
			return

		case event, ok := <-w.fswatcher.Events:
			if !ok {
				return
			}
			w.handleEvent(event)

		case err, ok := <-w.fswatcher.Errors:
			if !ok {
				return
			}
			w.config.LogFunc(fmt.Sprintf("[!] 监控错误: %v", err))
		}
	}
}

// handleEvent 处理文件系统事件
func (w *Watcher) handleEvent(event fsnotify.Event) {
	path := event.Name

	// 新增目录：可能是新的小程序文件夹
	if event.Has(fsnotify.Create) {
		info, err := os.Stat(path)
		if err != nil {
			return
		}

		if info.IsDir() {
			// 如果是 wx 开头的16位ID目录，自动添加监控
			if regWxDir.MatchString(filepath.Base(path)) {
				w.config.LogFunc(fmt.Sprintf("[+] 检测到新小程序目录: %s", filepath.Base(path)))
				_ = w.fswatcher.Add(path)
				// 稍等让文件写入完成
				go func(dir string) {
					time.Sleep(2 * time.Second)
					w.decompileDir(dir)
				}(path)
			} else {
				// 普通子目录也加入监控
				_ = w.fswatcher.Add(path)
			}
			return
		}

		// 新增文件：检查是否是 wxapkg 文件
		if filepath.Ext(path) == ".wxapkg" {
			w.config.LogFunc(fmt.Sprintf("[+] 检测到新文件: %s", filepath.Base(path)))
			go func(p string) {
				// 等待文件写入完成
				time.Sleep(1 * time.Second)
				w.decompileFile(p)
			}(path)
		}
	}

	// 文件写入完成（部分系统用WRITE代替CREATE）
	if event.Has(fsnotify.Write) {
		if filepath.Ext(path) == ".wxapkg" {
			// 防抖：同一文件1秒内只处理一次
			w.mu.Lock()
			last, exists := w.processed[path]
			if exists && time.Since(last) < 3*time.Second {
				w.mu.Unlock()
				return
			}
			w.processed[path] = time.Now()
			w.mu.Unlock()

			go func(p string) {
				time.Sleep(1 * time.Second)
				w.decompileFile(p)
			}(path)
		}
	}
}

// decompileDir 反编译整个小程序目录
func (w *Watcher) decompileDir(dirPath string) {
	if !regWxDir.MatchString(filepath.Base(dirPath)) {
		return
	}

	// 防止重复处理
	w.mu.Lock()
	last, exists := w.processed[dirPath]
	if exists && time.Since(last) < 10*time.Second {
		w.mu.Unlock()
		return
	}
	w.processed[dirPath] = time.Now()
	w.mu.Unlock()

	result, err := DecompileDir(dirPath, w.config.OutputDir, w.config.DecompileOpts, w.config.LogFunc)
	if err != nil {
		w.config.LogFunc(fmt.Sprintf("[!] 反编译失败 '%s': %v", filepath.Base(dirPath), err))
		return
	}
	if result != nil && w.config.OnDecompileResult != nil {
		w.config.OnDecompileResult(result)
	}
}

// decompileFile 反编译单个 wxapkg 文件
func (w *Watcher) decompileFile(filePath string) {
	// 防止重复处理
	w.mu.Lock()
	last, exists := w.processed[filePath]
	if exists && time.Since(last) < 10*time.Second {
		w.mu.Unlock()
		return
	}
	w.processed[filePath] = time.Now()
	w.mu.Unlock()

	result, err := DecompileSingleFile(filePath, w.config.OutputDir, w.config.DecompileOpts, w.config.LogFunc)
	if err != nil {
		w.config.LogFunc(fmt.Sprintf("[!] 反编译失败 '%s': %v", filepath.Base(filePath), err))
		return
	}
	if result != nil && w.config.OnDecompileResult != nil {
		w.config.OnDecompileResult(result)
	}
}

// addSubDirsToWatcher 将子目录也加入 fsnotify 监控
func (w *Watcher) addSubDirsToWatcher(root string) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return
	}
	for _, entry := range entries {
		if entry.IsDir() {
			sub := filepath.Join(root, entry.Name())
			_ = w.fswatcher.Add(sub)
			w.addSubDirsToWatcher(sub)
		}
	}
}

// scanAndDecompileExisting 启动时扫描已有小程序目录并反编译
func (w *Watcher) scanAndDecompileExisting() {
	entries, err := os.ReadDir(w.config.WatchDir)
	if err != nil {
		return
	}

	var wxDirs []string
	for _, entry := range entries {
		if entry.IsDir() && regWxDir.MatchString(entry.Name()) {
			wxDirs = append(wxDirs, filepath.Join(w.config.WatchDir, entry.Name()))
		}
	}

	if len(wxDirs) == 0 {
		w.config.LogFunc("[*] 未发现已有小程序目录，等待新文件...")
		return
	}

	w.config.LogFunc(fmt.Sprintf("[*] 发现 %d 个小程序目录，开始反编译...", len(wxDirs)))
	for _, dir := range wxDirs {
		go w.decompileDir(dir)
	}
}
