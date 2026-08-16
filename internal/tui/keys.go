package tui

import "github.com/charmbracelet/bubbles/key"

type keyMap struct {
	NextTab     key.Binding
	PreviousTab key.Binding
	Inbound     key.Binding
	Outbound    key.Binding
	DNS         key.Binding
	Ports       key.Binding
	Persistence key.Binding
	Integrity   key.Binding
	Pause       key.Binding
	Mode        key.Binding
	Filter      key.Binding
	ClearFilter key.Binding
	Detail      key.Binding
	Back        key.Binding
	Refresh     key.Binding
	Help        key.Binding
	Quit        key.Binding
}

func defaultKeyMap() keyMap {
	return keyMap{
		NextTab:     key.NewBinding(key.WithKeys("tab", "right", "l"), key.WithHelp("tab", "next tab")),
		PreviousTab: key.NewBinding(key.WithKeys("shift+tab", "left", "h"), key.WithHelp("shift+tab", "previous tab")),
		Inbound:     key.NewBinding(key.WithKeys("1"), key.WithHelp("1", "inbound")),
		Outbound:    key.NewBinding(key.WithKeys("2"), key.WithHelp("2", "outbound")),
		DNS:         key.NewBinding(key.WithKeys("3"), key.WithHelp("3", "dns")),
		Ports:       key.NewBinding(key.WithKeys("4"), key.WithHelp("4", "ports")),
		Persistence: key.NewBinding(key.WithKeys("5"), key.WithHelp("5", "persistence")),
		Integrity:   key.NewBinding(key.WithKeys("6"), key.WithHelp("6", "integrity")),
		Pause:       key.NewBinding(key.WithKeys("p"), key.WithHelp("p", "pause view")),
		Mode:        key.NewBinding(key.WithKeys("m"), key.WithHelp("m", "live/session")),
		Filter:      key.NewBinding(key.WithKeys("/"), key.WithHelp("/", "filter")),
		ClearFilter: key.NewBinding(key.WithKeys("c"), key.WithHelp("c", "clear filter")),
		Detail:      key.NewBinding(key.WithKeys("enter"), key.WithHelp("enter", "inspect")),
		Back:        key.NewBinding(key.WithKeys("esc"), key.WithHelp("esc", "back")),
		Refresh:     key.NewBinding(key.WithKeys("r"), key.WithHelp("r", "rescan")),
		Help:        key.NewBinding(key.WithKeys("?"), key.WithHelp("?", "more")),
		Quit:        key.NewBinding(key.WithKeys("q", "ctrl+c"), key.WithHelp("q", "quit")),
	}
}
