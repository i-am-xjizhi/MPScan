package gui

import (
	"sync/atomic"
	"time"

	"github.com/lxn/walk"
	. "github.com/lxn/walk/declarative"
	"github.com/lxn/win"
)

// createTipWindow 创建无边框浮动提示窗口（红色加粗大字）
func (a *AppWindow) createTipWindow() {
	err := (MainWindow{
		AssignTo: &a.tipWin,
		Title:    "",
		MinSize:  Size{Width: 400, Height: 54},
		MaxSize:  Size{Width: 400, Height: 54},
		Layout:   VBox{MarginsZero: true, SpacingZero: true},
		Children: []Widget{
			CustomWidget{
				MinSize: Size{Width: 400, Height: 54},
				PaintPixels: func(canvas *walk.Canvas, bounds walk.Rectangle) error {
					bg, _ := walk.NewSolidColorBrush(walk.RGB(255, 252, 220))
					defer bg.Dispose()
					_ = canvas.FillRectanglePixels(bg, bounds)
					pen, _ := walk.NewCosmeticPen(walk.PenSolid, walk.RGB(200, 0, 0))
					defer pen.Dispose()
					border := walk.Rectangle{X: 0, Y: 0, Width: bounds.Width - 1, Height: bounds.Height - 1}
					_ = canvas.DrawRectanglePixels(pen, border)
					font, _ := walk.NewFont("Segoe UI", 13, walk.FontBold)
					defer font.Dispose()
					_ = canvas.DrawTextPixels("外部链接工具，请自行甄别使用！！！", font,
						walk.RGB(200, 0, 0), bounds,
						walk.TextCenter|walk.TextVCenter|walk.TextSingleLine)
					return nil
				},
			},
		},
	}).Create()
	if err != nil || a.tipWin == nil {
		return
	}

	hwnd := a.tipWin.Handle()
	// 去掉标题栏、边框，改为纯弹出层
	win.SetWindowLong(hwnd, win.GWL_STYLE, int32(win.WS_BORDER))
	win.SetWindowLong(hwnd, win.GWL_EXSTYLE,
		int32(win.WS_EX_TOPMOST|win.WS_EX_TOOLWINDOW))
}

// showTip 在鼠标上方显示提示窗口，并启动轮询 goroutine 监控鼠标位置
func (a *AppWindow) showTip() {
	if a.tipWin == nil {
		return
	}
	// CAS: 0→1，防止重复启动
	if !atomic.CompareAndSwapInt32(&a.tipShown, 0, 1) {
		return
	}

	var pt win.POINT
	win.GetCursorPos(&pt)
	const w, h int32 = 400, 54
	x := pt.X - w/2
	y := pt.Y - h - 10
	if x < 0 {
		x = 0
	}
	if y < 0 {
		y = pt.Y + 16
	}
	win.SetWindowPos(a.tipWin.Handle(), win.HWND_TOPMOST,
		x, y, w, h,
		win.SWP_NOACTIVATE|win.SWP_SHOWWINDOW)

	// 轮询 goroutine：每 20ms 检查鼠标是否还在标签区域内，离开立即隐藏
	go func() {
		for atomic.LoadInt32(&a.tipShown) == 1 {
			time.Sleep(20 * time.Millisecond)
			if !a.cursorInTag() {
				a.syncUI(func() { a.hideTip() })
				return
			}
		}
	}()
}

// hideTip 立即隐藏提示窗口
func (a *AppWindow) hideTip() {
	// CAS: 1→0，防止重复隐藏
	if !atomic.CompareAndSwapInt32(&a.tipShown, 1, 0) {
		return
	}
	if a.tipWin != nil {
		a.tipWin.Hide()
	}
}

// cursorInTag 判断鼠标当前屏幕坐标是否在右下角工具标签控件内
func (a *AppWindow) cursorInTag() bool {
	if a.toolWidget == nil {
		return false
	}
	var r win.RECT
	win.GetWindowRect(a.toolWidget.Handle(), &r)

	var pt win.POINT
	win.GetCursorPos(&pt)
	return pt.X >= r.Left && pt.X <= r.Right &&
		pt.Y >= r.Top && pt.Y <= r.Bottom
}
