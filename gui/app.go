package gui

import (
	"bufio"
	"encoding/csv"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/lxn/walk"
	. "github.com/lxn/walk/declarative"
	"github.com/wux1an/wxapkg/core"
	"github.com/wux1an/wxapkg/util"
)

const maxLogLines = 500

// AppWindow 主窗口
type AppWindow struct {
	*walk.MainWindow

	// 配置控件
	watchDirEdit  *walk.LineEdit
	outputDirEdit *walk.LineEdit
	threadCombo   *walk.ComboBox

	// 操作按钮
	startBtn    *walk.PushButton
	stopBtn     *walk.PushButton
	scanOnceBtn *walk.PushButton

	// 日志区
	logEdit *walk.TextEdit

	// 代码预览区
	previewEdit     *walk.TextEdit
	previewGroupBox *walk.GroupBox

	// 结果区
	resultsTable *walk.TableView
	statsLabel   *walk.Label
	resultModel  *ResultTableModel

	// 状态栏
	statusLabel *walk.Label

	// 业务状态
	watcher      *core.Watcher
	appNameCache map[string]string
	cacheMu      sync.RWMutex

	// 日志缓冲
	logMu    sync.Mutex
	logLines []string
}

// Run 启动应用
func Run() {
	a := &AppWindow{
		logLines:     make([]string, 0, 200),
		appNameCache: make(map[string]string),
		resultModel:  newResultTableModel(),
	}
	a.buildAndRun()
}

func (a *AppWindow) buildAndRun() {
	defaultWatch := getDefaultWatchDir()
	defaultOutput := filepath.Join(getExeDir(), "output")

	// 等待 Walk 消息循环启动后挂载右键菜单
	go func() {
		for a.MainWindow == nil || a.resultsTable == nil {
			time.Sleep(50 * time.Millisecond)
		}
		a.MainWindow.Synchronize(func() {
			a.setupContextMenu()
		})
	}()

	_, err := (MainWindow{
		AssignTo: &a.MainWindow,
		Title:    "MPScan小程序安全分析工具 v1.0",
		MinSize:  Size{Width: 1100, Height: 660},
		Size:     Size{Width: 1300, Height: 780},
		Font:     Font{Family: "Segoe UI", PointSize: 9},
		Layout:   VBox{MarginsZero: true, SpacingZero: true},
		Children: []Widget{

			// ╔══ 顶部科技风横幅（InvalidatesOnResize 保证宽度自适应）══╗
			CustomWidget{
				MinSize:             Size{Height: 52},
				MaxSize:             Size{Height: 52},
				InvalidatesOnResize: true, // 窗口拉伸时自动重绘，文字和线条随宽度变化
				PaintPixels: func(canvas *walk.Canvas, updateBounds walk.Rectangle) error {
					// 深蓝背景
					bgBrush, _ := walk.NewSolidColorBrush(walk.RGB(10, 25, 47))
					defer bgBrush.Dispose()
					_ = canvas.FillRectanglePixels(bgBrush, updateBounds)
					// 底部科技蓝细线（宽度 = updateBounds.Width，始终铺满）
					lineBrush, _ := walk.NewSolidColorBrush(walk.RGB(0, 180, 255))
					defer lineBrush.Dispose()
					lineRect := walk.Rectangle{
						X: 0, Y: updateBounds.Height - 2,
						Width: updateBounds.Width, Height: 2,
					}
					_ = canvas.FillRectanglePixels(lineBrush, lineRect)
					// 左侧主标题
					titleFont, _ := walk.NewFont("Segoe UI", 14, walk.FontBold)
					defer titleFont.Dispose()
					textRect := walk.Rectangle{
						X: 16, Y: 0,
						Width: updateBounds.Width - 32, Height: updateBounds.Height - 2,
					}
					_ = canvas.DrawTextPixels("⬡  MPScan", titleFont,
						walk.RGB(0, 200, 255), textRect,
						walk.TextLeft|walk.TextVCenter|walk.TextSingleLine)
					// 右侧版本（X=0 宽度铺满，右对齐）
					verFont, _ := walk.NewFont("Consolas", 8, 0)
					defer verFont.Dispose()
					verRect := walk.Rectangle{
						X: 0, Y: 0,
						Width: updateBounds.Width - 16, Height: updateBounds.Height - 2,
					}
					_ = canvas.DrawTextPixels("v1.0  |  自动化反编译 + 敏感信息提取", verFont,
						walk.RGB(80, 160, 200), verRect,
						walk.TextRight|walk.TextVCenter|walk.TextSingleLine)
					return nil
				},
			},

			// ╔══ 配置区 ════════════════════════════════════════╗
			Composite{
				Layout: VBox{Margins: Margins{Left: 12, Top: 8, Right: 12, Bottom: 4}, Spacing: 4},
				Children: []Widget{

					// 行1：监控目录 + 输出目录
					Composite{
						Layout: HBox{MarginsZero: true, Spacing: 6},
						Children: []Widget{
							Label{Text: "监控目录:", MinSize: Size{Width: 60}},
							LineEdit{AssignTo: &a.watchDirEdit, Text: defaultWatch},
							PushButton{
								Text: "浏览", MaxSize: Size{Width: 52},
								OnClicked: func() { a.browseFolder(a.watchDirEdit, "选择监控目录") },
							},
							Label{Text: "输出目录:", MinSize: Size{Width: 60}},
							LineEdit{AssignTo: &a.outputDirEdit, Text: defaultOutput},
							PushButton{
								Text: "浏览", MaxSize: Size{Width: 52},
								OnClicked: func() { a.browseFolder(a.outputDirEdit, "选择输出目录") },
							},
						},
					},

					// 行2：线程 + 操作按钮（已移除"代码美化"复选框）
					Composite{
						Layout: HBox{MarginsZero: true, Spacing: 6},
						Children: []Widget{
							Label{Text: "线程:"},
							ComboBox{
								AssignTo:     &a.threadCombo,
								Model:        []string{"10", "20", "30", "50"},
								CurrentIndex: 2,
								MaxSize:      Size{Width: 55},
							},
							HSpacer{},
							PushButton{
								AssignTo:  &a.startBtn,
								Text:      "▶ 开始监控",
								Font:      Font{Family: "Segoe UI", PointSize: 9, Bold: true},
								OnClicked: a.onStartMonitor,
							},
							PushButton{
								AssignTo:  &a.stopBtn,
								Text:      "■ 停止监控",
								Enabled:   false,
								OnClicked: a.onStopMonitor,
							},
							PushButton{
								AssignTo:  &a.scanOnceBtn,
								Text:      "↺ 立即扫描",
								OnClicked: a.onScanOnce,
							},
						},
					},
				},
			},

			// 分隔线
			HSeparator{},

			// ╔══ 主体三栏：日志(左) | 代码预览(中) | 结果(右) ═══╗
			// MinSize.Height 让 VBox 知道该区域需要撑开，不留空白
			HSplitter{
				MinSize: Size{Height: 480},
				Children: []Widget{

					// ── 左：运行日志 ──────────────────────────
					GroupBox{
						Title:         "运行日志",
						MinSize:       Size{Width: 200},
						Layout:        VBox{MarginsZero: true},
						StretchFactor: 22,
						Children: []Widget{
							TextEdit{
								AssignTo: &a.logEdit,
								ReadOnly: true,
								VScroll:  true,
								Font:     Font{Family: "Consolas", PointSize: 9},
							},
						},
					},

					// ── 中：代码片段预览 ──────────────────────
					GroupBox{
						AssignTo:      &a.previewGroupBox,
						Title:         "代码预览（点击条目查看上下文）",
						MinSize:       Size{Width: 320},
						Layout:        VBox{MarginsZero: true},
						StretchFactor: 38,
						Children: []Widget{
							TextEdit{
								AssignTo: &a.previewEdit,
								ReadOnly: true,
								VScroll:  true,
								HScroll:  true,
								Font:     Font{Family: "Consolas", PointSize: 9},
							},
						},
					},

					// ── 右：敏感信息结果 ──────────────────────
					GroupBox{
						Title:         "敏感信息提取结果",
						MinSize:       Size{Width: 400},
						Layout:        VBox{Margins: Margins{Left: 4, Top: 4, Right: 4, Bottom: 4}, Spacing: 4},
						StretchFactor: 40,
						Children: []Widget{

							// 统计行 + 操作按钮
							Composite{
								Layout: HBox{MarginsZero: true, Spacing: 6},
								Children: []Widget{
									Label{
										AssignTo: &a.statsLabel,
										Text:     "等待扫描...",
										Font:     Font{Family: "Consolas", PointSize: 9},
									},
									HSpacer{},
									PushButton{
										Text:      "导出 CSV",
										MaxSize:   Size{Width: 72},
										OnClicked: a.onExportCSV,
									},
									PushButton{
										Text:      "清空结果",
										MaxSize:   Size{Width: 64},
										OnClicked: a.onClearResults,
									},
								},
							},

							// 结果表格
							TableView{
								AssignTo:              &a.resultsTable,
								AlternatingRowBG:      false,
								ColumnsOrderable:      true,
								MultiSelection:        false,
								Model:                 a.resultModel,
								CellStyler:            a.resultModel,
								Font:                  Font{Family: "Consolas", PointSize: 9},
								Columns: []TableViewColumn{
									{Title: "小程序名称", Width: 118},
									{Title: "风险", Width: 46},
									{Title: "分类", Width: 118},
									{Title: "键名", Width: 104},
									{Title: "值（截断80字符）", Width: 210},
									{Title: "来源文件", Width: 120},
								},
								OnCurrentIndexChanged: a.onResultSelectionChanged,
								OnItemActivated:       a.onResultSelectionChanged,
							},
						},
					},
				},
			},

			// ╔══ 状态栏 ════════════════════════════════════════╗
			Composite{
				Layout: HBox{
					Margins: Margins{Left: 10, Top: 3, Right: 10, Bottom: 3},
					Spacing: 0,
				},
				Children: []Widget{
					Label{
						AssignTo: &a.statusLabel,
						Text:     "●  就绪 — 配置目录后点击「开始监控」或「立即扫描」",
						Font:     Font{Family: "Segoe UI", PointSize: 9},
					},
				},
			},
		},
	}.Run())

	if err != nil {
		walk.MsgBox(nil, "启动失败", err.Error(), walk.MsgBoxIconError)
	}
}

// setupContextMenu 挂载结果表格右键菜单
func (a *AppWindow) setupContextMenu() {
	menu, err := walk.NewMenu()
	if err != nil {
		return
	}

	copyAction := walk.NewAction()
	_ = copyAction.SetText("复制")
	copyAction.Triggered().Attach(func() { a.onCopyRow() })
	_ = menu.Actions().Add(copyAction)

	_ = menu.Actions().Add(walk.NewSeparatorAction())

	notepadAction := walk.NewAction()
	_ = notepadAction.SetText("用记事本打开文件")
	notepadAction.Triggered().Attach(func() { a.onOpenInNotepad() })
	_ = menu.Actions().Add(notepadAction)

	explorerAction := walk.NewAction()
	_ = explorerAction.SetText("在资源管理器中定位")
	explorerAction.Triggered().Attach(func() { a.onOpenInExplorer() })
	_ = menu.Actions().Add(explorerAction)

	a.resultsTable.SetContextMenu(menu)
}

// ══════════════════════ 按钮回调 ══════════════════════════════

func (a *AppWindow) onStartMonitor() {
	watchDir, outputDir, ok := a.validateDirs()
	if !ok {
		return
	}

	opts := core.DecompileOptions{
		Thread:          a.selectedThread(),
		DisableBeautify: false, // 始终开启代码美化
	}

	a.watcher = core.NewWatcher(core.WatcherConfig{
		WatchDir:      watchDir,
		OutputDir:     outputDir,
		DecompileOpts: opts,
		LogFunc:       a.appendLog,
		OnDecompileResult: func(result *core.DecompileResult) {
			go a.runScanner(result)
		},
	})

	if err := a.watcher.Start(); err != nil {
		walk.MsgBox(a.MainWindow, "错误", err.Error(), walk.MsgBoxIconError)
		a.watcher = nil
		return
	}

	a.setControlsEnabled(false)
	a.startBtn.SetEnabled(false)
	a.stopBtn.SetEnabled(true)
	a.setStatus(fmt.Sprintf("●  监控中 — %s", watchDir))
}

func (a *AppWindow) onStopMonitor() {
	if a.watcher != nil {
		a.watcher.Stop()
		a.watcher = nil
	}
	a.setControlsEnabled(true)
	a.startBtn.SetEnabled(true)
	a.stopBtn.SetEnabled(false)
	a.setStatus("●  已停止")
}

func (a *AppWindow) onScanOnce() {
	watchDir, outputDir, ok := a.validateDirs()
	if !ok {
		return
	}

	opts := core.DecompileOptions{
		Thread:          a.selectedThread(),
		DisableBeautify: false,
	}

	a.startBtn.SetEnabled(false)
	a.scanOnceBtn.SetEnabled(false)
	a.setStatus("●  扫描反编译中...")

	go func() {
		reg := regexp.MustCompile(`^wx[0-9a-f]{16}$`)
		entries, err := os.ReadDir(watchDir)
		if err != nil {
			a.syncUI(func() {
				a.appendLog(fmt.Sprintf("[!] 读取目录失败: %v", err))
				a.setStatus("●  扫描失败")
				a.startBtn.SetEnabled(true)
				a.scanOnceBtn.SetEnabled(true)
			})
			return
		}

		count := 0
		for _, entry := range entries {
			if !entry.IsDir() || !reg.MatchString(entry.Name()) {
				continue
			}
			result, err := core.DecompileDir(
				filepath.Join(watchDir, entry.Name()),
				outputDir, opts, a.appendLog,
			)
			if err != nil {
				a.appendLog(fmt.Sprintf("[!] 反编译失败 '%s': %v", entry.Name(), err))
				continue
			}
			count++
			a.runScanner(result)
		}

		a.syncUI(func() {
			if count == 0 {
				a.appendLog("[!] 未发现小程序目录（需要 wx 开头16位ID的文件夹）")
			} else {
				a.appendLog(fmt.Sprintf("[✓] 扫描完成，共处理 %d 个小程序", count))
			}
			a.setStatus(fmt.Sprintf("●  扫描完成 — %d 个小程序", count))
			a.startBtn.SetEnabled(true)
			a.scanOnceBtn.SetEnabled(true)
		})
	}()
}

func (a *AppWindow) onResultSelectionChanged() {
	idx := a.resultsTable.CurrentIndex()
	item := a.resultModel.getItem(idx)
	if item == nil {
		return
	}
	go func() {
		preview := readLinesAround(item.FilePath, item.LineNo, 20)
		a.syncUI(func() {
			title := fmt.Sprintf("代码预览 — %s : 第 %d 行", filepath.Base(item.FilePath), item.LineNo)
			a.previewGroupBox.SetTitle(title)
			a.previewEdit.SetText(preview)
			// 滚动到 ► 标记处
			txt := a.previewEdit.Text()
			markerIdx := strings.Index(txt, "►")
			if markerIdx >= 0 {
				a.previewEdit.SendMessage(0x00B1, uintptr(markerIdx), uintptr(markerIdx))
				a.previewEdit.SendMessage(0x00B7, 0, 0)
			}
		})
	}()
}

func (a *AppWindow) onCopyRow() {
	idx := a.resultsTable.CurrentIndex()
	item := a.resultModel.getItem(idx)
	if item == nil {
		return
	}
	text := fmt.Sprintf("[%s] %s | %s: %s", item.Level, item.AppName, item.KeyName, item.Value)
	if err := walk.Clipboard().SetText(text); err == nil {
		a.setStatus(fmt.Sprintf("●  已复制: %s", item.KeyName))
	}
}

func (a *AppWindow) onOpenInNotepad() {
	idx := a.resultsTable.CurrentIndex()
	item := a.resultModel.getItem(idx)
	if item == nil {
		return
	}
	go func() {
		_ = exec.Command("notepad.exe", item.FilePath).Start()
	}()
}

func (a *AppWindow) onOpenInExplorer() {
	idx := a.resultsTable.CurrentIndex()
	item := a.resultModel.getItem(idx)
	if item == nil {
		return
	}
	go func() {
		_ = exec.Command("explorer.exe", "/select,", item.FilePath).Start()
	}()
}

func (a *AppWindow) onClearResults() {
	a.resultModel.clear()
	a.updateStats()
	a.previewGroupBox.SetTitle("代码预览（点击条目查看上下文）")
	a.previewEdit.SetText("")
}

func (a *AppWindow) onExportCSV() {
	dlg := new(walk.FileDialog)
	dlg.Title = "导出敏感信息报告"
	dlg.Filter = "CSV 文件 (*.csv)|*.csv|所有文件 (*.*)|*.*"
	dlg.FilePath = fmt.Sprintf("wxapkg_report_%s.csv", time.Now().Format("20060102_150405"))

	ok, err := dlg.ShowSave(a.MainWindow)
	if err != nil || !ok {
		return
	}

	f, err := os.Create(dlg.FilePath)
	if err != nil {
		walk.MsgBox(a.MainWindow, "错误", "创建文件失败: "+err.Error(), walk.MsgBoxIconError)
		return
	}
	defer f.Close()

	// UTF-8 BOM，让 Excel 正确识别中文
	_, _ = f.Write([]byte{0xEF, 0xBB, 0xBF})

	w := csv.NewWriter(f)
	_ = w.Write([]string{"小程序名称", "wxid", "风险等级", "分类", "键名", "值", "来源文件", "行号"})
	for _, r := range a.resultModel.items {
		_ = w.Write([]string{
			r.AppName, r.WxID, string(r.Level), r.Category,
			r.KeyName, r.Value, r.FilePath, strconv.Itoa(r.LineNo),
		})
	}
	w.Flush()

	a.appendLog(fmt.Sprintf("[✓] 已导出 %d 条记录 → %s", len(a.resultModel.items), dlg.FilePath))
	walk.MsgBox(a.MainWindow, "导出成功",
		fmt.Sprintf("共导出 %d 条记录\n%s", len(a.resultModel.items), dlg.FilePath),
		walk.MsgBoxIconInformation)
}

// ══════════════════════ 核心逻辑 ══════════════════════════════

func (a *AppWindow) runScanner(result *core.DecompileResult) {
	appName := a.resolveAppName(result.WxID, result.OutputDir)
	items := core.ScanDecompiledDir(result.WxID, appName, result.OutputDir, a.appendLog)
	if len(items) == 0 {
		return
	}
	a.syncUI(func() {
		a.resultModel.appendItems(items)
		a.updateStats()
	})
}

// resolveAppName 优先从配置文件读取，再网络查询，最后用 wxid
func (a *AppWindow) resolveAppName(wxid, outputDir string) string {
	a.cacheMu.RLock()
	name, ok := a.appNameCache[wxid]
	a.cacheMu.RUnlock()
	if ok {
		return name
	}

	if outputDir != "" {
		if n := core.ResolveNameFromDecompiledDir(outputDir); n != "" {
			a.cacheMu.Lock()
			a.appNameCache[wxid] = n
			a.cacheMu.Unlock()
			return n
		}
	}

	info, err := util.WxidQuery.Query(wxid)
	if err != nil || info.Nickname == "" {
		name = wxid
	} else {
		name = info.Nickname
	}
	a.cacheMu.Lock()
	a.appNameCache[wxid] = name
	a.cacheMu.Unlock()
	return name
}

func (a *AppWindow) updateStats() {
	h, m, l := a.resultModel.stats()
	total := h + m + l
	a.statsLabel.SetText(fmt.Sprintf(
		"合计 %d 条   ●高危 %d   ●中危 %d   ●低危 %d",
		total, h, m, l,
	))
}

// readLinesAround 读取文件目标行前后各 context 行，目标行用 ► 标记
func readLinesAround(filePath string, targetLine, context int) string {
	f, err := os.Open(filePath)
	if err != nil {
		return fmt.Sprintf("[无法打开文件: %v]", err)
	}
	defer f.Close()

	var lines []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}

	total := len(lines)
	if total == 0 {
		return "[文件为空]"
	}

	target := targetLine - 1
	if target < 0 {
		target = 0
	}
	if target >= total {
		target = total - 1
	}
	start := target - context
	if start < 0 {
		start = 0
	}
	end := target + context
	if end >= total {
		end = total - 1
	}

	width := len(strconv.Itoa(end + 1))
	fmtStr := fmt.Sprintf("%%%dd", width)

	var sb strings.Builder
	for i := start; i <= end; i++ {
		marker := "  "
		if i == target {
			marker = "►"
		}
		sb.WriteString(fmt.Sprintf("%s "+fmtStr+" │ %s\r\n", marker, i+1, lines[i]))
	}
	return sb.String()
}

// ══════════════════════ 辅助方法 ══════════════════════════════

func (a *AppWindow) browseFolder(target *walk.LineEdit, title string) {
	dlg := new(walk.FileDialog)
	dlg.Title = title
	dlg.FilePath = target.Text()
	if ok, err := dlg.ShowBrowseFolder(a.MainWindow); err == nil && ok {
		target.SetText(dlg.FilePath)
	}
}

func (a *AppWindow) validateDirs() (watchDir, outputDir string, ok bool) {
	watchDir = strings.TrimSpace(a.watchDirEdit.Text())
	outputDir = strings.TrimSpace(a.outputDirEdit.Text())
	if watchDir == "" {
		walk.MsgBox(a.MainWindow, "提示", "请填写监控目录", walk.MsgBoxIconWarning)
		return
	}
	if outputDir == "" {
		walk.MsgBox(a.MainWindow, "提示", "请填写输出目录", walk.MsgBoxIconWarning)
		return
	}
	if err := os.MkdirAll(outputDir, os.ModePerm); err != nil {
		walk.MsgBox(a.MainWindow, "错误", "创建输出目录失败: "+err.Error(), walk.MsgBoxIconError)
		return
	}
	ok = true
	return
}

func (a *AppWindow) setControlsEnabled(enabled bool) {
	a.watchDirEdit.SetEnabled(enabled)
	a.outputDirEdit.SetEnabled(enabled)
	a.threadCombo.SetEnabled(enabled)
	a.scanOnceBtn.SetEnabled(enabled)
}

func (a *AppWindow) selectedThread() int {
	switch a.threadCombo.Text() {
	case "10":
		return 10
	case "20":
		return 20
	case "50":
		return 50
	default:
		return 30
	}
}

func (a *AppWindow) appendLog(msg string) {
	ts := time.Now().Format("15:04:05")
	line := fmt.Sprintf("[%s] %s", ts, msg)

	a.logMu.Lock()
	a.logLines = append(a.logLines, line)
	if len(a.logLines) > maxLogLines {
		a.logLines = a.logLines[len(a.logLines)-maxLogLines:]
	}
	text := strings.Join(a.logLines, "\r\n")
	a.logMu.Unlock()

	a.syncUI(func() {
		a.logEdit.SetText(text)
		a.logEdit.SendMessage(0x00B1, ^uintptr(0), ^uintptr(0)) // EM_SETSEL 选到末尾
		a.logEdit.SendMessage(0x00B7, 0, 0)                      // EM_SCROLLCARET
	})
}

func (a *AppWindow) setStatus(text string) {
	a.syncUI(func() { a.statusLabel.SetText(text) })
}

func (a *AppWindow) syncUI(fn func()) {
	if a.MainWindow == nil {
		return
	}
	a.MainWindow.Synchronize(fn)
}

func getExeDir() string {
	exe, err := os.Executable()
	if err != nil {
		dir, _ := os.Getwd()
		return dir
	}
	return filepath.Dir(exe)
}

func getDefaultWatchDir() string {
	homeDir, _ := os.UserHomeDir()
	candidates := []string{
		filepath.Join(homeDir, "Documents", "WeChat Files", "Applet"),
		filepath.Join(homeDir, "WeChat Files", "Applet"),
	}
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return getExeDir()
}
