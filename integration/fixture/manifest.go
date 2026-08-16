package fixture

import "time"

type Manifest struct {
	GeneratedAt         time.Time `json:"generated_at"`
	ProcessName         string    `json:"process_name"`
	TCPPorts            []uint16  `json:"tcp_ports"`
	UDPPorts            []uint16  `json:"udp_ports"`
	DNSNames            []string  `json:"dns_names"`
	ServiceUnits        []string  `json:"service_units"`
	TimerUnits          []string  `json:"timer_units"`
	CronPaths           []string  `json:"cron_paths"`
	ModifiedPackageFile string    `json:"modified_package_file"`
}
