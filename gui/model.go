package gui

import (
	"path/filepath"

	"github.com/lxn/walk"
	"github.com/wux1an/wxapkg/core"
)

// ResultTableModel Walk TableView 数据模型，实现 CellStyler 接口进行颜色渲染
type ResultTableModel struct {
	walk.TableModelBase
	items []*core.ScanResult
}

func newResultTableModel() *ResultTableModel {
	return &ResultTableModel{items: make([]*core.ScanResult, 0, 64)}
}

func (m *ResultTableModel) RowCount() int { return len(m.items) }

func (m *ResultTableModel) Value(row, col int) interface{} {
	if row < 0 || row >= len(m.items) {
		return nil
	}
	r := m.items[row]
	switch col {
	case 0:
		return r.AppName
	case 1:
		return string(r.Level)
	case 2:
		return r.Category
	case 3:
		return r.KeyName
	case 4:
		return r.Value
	case 5:
		return filepath.Base(r.FilePath)
	}
	return nil
}

// StyleCell 按风险等级着色（实现 walk.CellStyler 接口）
func (m *ResultTableModel) StyleCell(style *walk.CellStyle) {
	if style.Row() < 0 || style.Row() >= len(m.items) {
		return
	}
	switch m.items[style.Row()].Level {
	case core.LevelHigh:
		style.BackgroundColor = walk.RGB(255, 230, 230) // 浅红
		style.TextColor = walk.RGB(180, 0, 0)
	case core.LevelMedium:
		style.BackgroundColor = walk.RGB(255, 248, 220) // 浅橙
		style.TextColor = walk.RGB(150, 90, 0)
	case core.LevelLow:
		style.BackgroundColor = walk.RGB(230, 243, 255) // 浅蓝
		style.TextColor = walk.RGB(0, 80, 160)
	}
}

func (m *ResultTableModel) appendItems(items []*core.ScanResult) {
	if len(items) == 0 {
		return
	}
	m.items = append(m.items, items...)
	m.PublishRowsReset()
}

func (m *ResultTableModel) clear() {
	m.items = m.items[:0]
	m.PublishRowsReset()
}

func (m *ResultTableModel) getItem(row int) *core.ScanResult {
	if row < 0 || row >= len(m.items) {
		return nil
	}
	return m.items[row]
}

func (m *ResultTableModel) stats() (high, mid, low int) {
	for _, r := range m.items {
		switch r.Level {
		case core.LevelHigh:
			high++
		case core.LevelMedium:
			mid++
		case core.LevelLow:
			low++
		}
	}
	return
}
