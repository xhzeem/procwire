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
	Processes   key.Binding
	Loader      key.Binding
	Pause       key.Binding
	Mode        key.Binding
	Trust       key.Binding
	Sort        key.Binding
	Collapse    key.Binding
	Legend      key.Binding
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
		NextTab:     key.NewBinding(key.WithKeys("tab", "right"), key.WithHelp("tab", "next tab")),
		PreviousTab: key.NewBinding(key.WithKeys("shift+tab", "left", "h"), key.WithHelp("shift+tab", "previous tab")),
		Inbound:     key.NewBinding(key.WithKeys("1"), key.WithHelp("1", "inbound")),
		Outbound:    key.NewBinding(key.WithKeys("2"), key.WithHelp("2", "outbound")),
		DNS:         key.NewBinding(key.WithKeys("3"), key.WithHelp("3", "dns")),
		Ports:       key.NewBinding(key.WithKeys("4"), key.WithHelp("4", "ports")),
		Persistence: key.NewBinding(key.WithKeys("5"), key.WithHelp("5", "persistence")),
		Processes:   key.NewBinding(key.WithKeys("6"), key.WithHelp("6", "processes")),
		Loader:      key.NewBinding(key.WithKeys("7"), key.WithHelp("7", "loader")),
		Pause:       key.NewBinding(key.WithKeys("p"), key.WithHelp("p", "pause view")),
		Mode:        key.NewBinding(key.WithKeys("m"), key.WithHelp("m", "switch view")),
		Trust:       key.NewBinding(key.WithKeys("t"), key.WithHelp("t", "trust filter")),
		Sort:        key.NewBinding(key.WithKeys("s"), key.WithHelp("s", "sort")),
		Collapse:    key.NewBinding(key.WithKeys(" "), key.WithHelp("space", "collapse branch")),
		Legend:      key.NewBinding(key.WithKeys("l"), key.WithHelp("l", "label legend")),
		Filter:      key.NewBinding(key.WithKeys("/"), key.WithHelp("/", "filter")),
		ClearFilter: key.NewBinding(key.WithKeys("c"), key.WithHelp("c", "clear filter")),
		Detail:      key.NewBinding(key.WithKeys("enter"), key.WithHelp("enter", "inspect")),
		Back:        key.NewBinding(key.WithKeys("esc"), key.WithHelp("esc", "back")),
		Refresh:     key.NewBinding(key.WithKeys("r"), key.WithHelp("r", "rescan")),
		Help:        key.NewBinding(key.WithKeys("?"), key.WithHelp("?", "more")),
		Quit:        key.NewBinding(key.WithKeys("q", "ctrl+c"), key.WithHelp("q", "quit")),
	}
}
