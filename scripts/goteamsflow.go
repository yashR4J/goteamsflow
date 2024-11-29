package main

import (
	"bytes"
	"encoding/binary"
	"encoding/csv"
	"flag"
	"fmt"
	"image/color"
	"io"
	"math"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"runtime/pprof"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/pion/rtp"
	"github.com/pion/stun"
	"github.com/sirupsen/logrus"
	"gonum.org/v1/plot"
	"gonum.org/v1/plot/plotter"
	"gonum.org/v1/plot/vg"
	"gonum.org/v1/plot/vg/draw"
)

var log = logrus.New()
var DEBUG = true
var tracker = NewIPTracker()

// ====== Constants and Variables ======

/*
Teams server IP ranges and ports.

Technical Details:
- Purpose: This list of IP ranges is used to identify Microsoft Teams traffic by matching the source or destination IPs against known Teams server IP ranges. It helps in differentiating Teams-related traffic from other network activities.
- Use Case: Essential for network monitoring and traffic analysis, this list enables tools to recognize and classify traffic directed to or from Microsoft Teams servers. This can be used for quality of service (QoS) adjustments, security monitoring, or detailed traffic analysis for optimizing Teams performance in a network environment.

- Reference: The IP ranges and ports for Microsoft Teams are based on Microsoft's official documentation for network connectivity, available at:
  https://learn.microsoft.com/en-us/microsoft-365/enterprise/urls-and-ip-address-ranges?view=o365-worldwide [Last Modified: 30/09/2024]
  This page provides updated information on IP ranges and ports that Teams uses, helping administrators configure firewalls and network rules for optimal Teams connectivity.
*/

var IP_RANGES = []struct {
	first net.IP
	last  net.IP
}{
	{net.ParseIP("52.112.0.0"), net.ParseIP("52.115.255.255")},                           // 52.112.0.0/14
	{net.ParseIP("52.122.0.0"), net.ParseIP("52.123.255.255")},                           // 52.122.0.0/15
	{net.ParseIP("52.238.119.141"), net.ParseIP("52.238.119.141")},                       // 52.238.119.141/32
	{net.ParseIP("52.244.160.207"), net.ParseIP("52.244.160.207")},                       // 52.244.160.207/32
	{net.ParseIP("2603:1027::"), net.ParseIP("2603:1027:ffff:ffff:ffff:ffff:ffff:ffff")}, // 2603:1027::/48
	{net.ParseIP("2603:1037::"), net.ParseIP("2603:1037:ffff:ffff:ffff:ffff:ffff:ffff")}, // 2603:1037::/48
	{net.ParseIP("2603:1047::"), net.ParseIP("2603:1047:ffff:ffff:ffff:ffff:ffff:ffff")}, // 2603:1047::/48
	{net.ParseIP("2603:1057::"), net.ParseIP("2603:1057:ffff:ffff:ffff:ffff:ffff:ffff")}, // 2603:1057::/48
	{net.ParseIP("2603:1063::"), net.ParseIP("2603:1063:ffff:ffff:ffff:ffff:ffff:ffff")}, // 2603:1063::/38
	{net.ParseIP("2620:1ec6::"), net.ParseIP("2620:1ec6:ffff:ffff:ffff:ffff:ffff:ffff")}, // 2620:1ec6::/48
	{net.ParseIP("2620:1ec:40::"), net.ParseIP("2620:1ec:40:ffff:ffff:ffff:ffff:ffff")},  // 2620:1ec:40::/42
	{net.ParseIP("2620:1ec:6::"), net.ParseIP("2620:1ec:6:ffff:ffff:ffff:ffff:ffff")},    // 2620:1ec:6::/48
}

// Media and SFU Ports for Teams traffic
var MEDIA_PORTS = map[uint16]bool{}
var RTP_PAYLOAD_TYPES = map[uint16]bool{}

/*
Maps of RTP payload types to media categories for classification of RTP streams.

Technical Details:
- Protocol: RTP (Real-time Transport Protocol) uses payload type identifiers (PT) to indicate the format of the media data carried in the packet.
- Payload Type (PT): An 8-bit field in the RTP header that indicates the type of encoded media data (e.g., audio codec, video codec).

- Media Type Maps:
  - `AUDIO_RTP_PAYLOAD_TYPES`: Maps RTP payload type values to a boolean `true` for audio codecs.
    - Microsoft Teams Expectations:
      - Microsoft Teams uses a mix of modern codecs like Opus and proprietary codecs such as Satin for audio communication,
	    adapting dynamically based on network conditions.
      - Example Payload Types:
        - 9: G.722, used for compatibility or fallback scenarios.
        - 111: Commonly used for Opus in WebRTC and Teams, offering high-quality audio even at varying bitrates.
        - 112: Can be associated with Satin, a proprietary codec used by Microsoft for optimized audio performance.
        - 103, 104: Often dynamically assigned and may represent various audio codecs used in real-time communication.

  - `VIDEO_RTP_PAYLOAD_TYPES`: Maps RTP payload type values to a boolean `true` for video codecs.
    - Microsoft Teams Expectations:
      - H.264/AVC is the primary video codec used by Microsoft Teams due to its widespread support and efficient compression.
	    Teams may also use dynamic payload types in the `96-127` range based on codec negotiation.
      - Example Payload Types:
        - 96, 97, 98: Represent dynamic payloads for H.264/AVC, often negotiated during session setup.
        - 122, 123, 127: Can correspond to VP8/VP9 or other dynamic video codecs, although H.264 remains the default choice in most scenarios.
        - 107: Potentially used for custom video streams or other codec implementations in specific use cases.

  - `SCREENSHARE_RTP_PAYLOAD_TYPES`: Maps RTP payload type values to a boolean `true` for screen-sharing data.
    - Microsoft Teams Expectations:
      - Microsoft Teams uses Video-based Screen Sharing (VBSS), which relies on H.264 for efficient screen-sharing. The dynamic
	    payload types often fall in the range `96` to `127`.
      - Example Payload Types:
        - 96: H.264, commonly used for screen-sharing due to its compatibility and efficiency.
        - 102: Associated with VBSS, optimized for low-latency screen-sharing in Teams.
        - 119, 123, 127: Used for specialized screen-sharing codecs, especially in scenarios requiring high fidelity or minimal latency
		  during desktop sharing.

- Purpose: These maps are used to classify RTP traffic based on the payload type field, enabling accurate identification of media
  streams for audio, video, and screen-sharing in applications like Microsoft Teams.
- Use Case: Critical for media analysis and quality of service monitoring in real-time communication environments, such as
  Microsoft Teams. It allows a program to differentiate between audio, video, and screen-sharing streams for performance optimization and
  debugging. The classification helps network administrators identify bandwidth usage per media type, troubleshoot connectivity
  issues, and improve user experience by optimizing network resources.
*/

var AUDIO_RTP_PAYLOAD_TYPES = map[uint8]bool{103: true, 108: true, 111: true, 112: true, 120: true}
var VIDEO_RTP_PAYLOAD_TYPES = map[uint8]bool{96: true, 97: true, 98: true, 122: true, 123: true, 127: true, 107: true}
var SCREENSHARE_RTP_PAYLOAD_TYPES = map[uint8]bool{96: true, 102: true, 119: true, 123: true, 127: true}

// Mapping of active flows
var flows = make(map[string]*TeamsFlow)

// Map to track session setup times for each host
var sessionSetupMap = make(map[string]*SessionSetup)
var sessionSetupTimesByOS = map[string][]time.Duration{
	"Windows":   {},
	"Linux":     {},
	"macOS/iOS": {},
	"Unknown":   {},
}

// CLI flags
var method int
var viewLogs []string
var viewPlots []string

// Dynamic Cache to store IPs that communicate with Teams Conferencing Servers

type IPTracker struct {
	mu        sync.Mutex
	clientIPs map[string]time.Time // Stores unique client IPs with a last seen timestamp
	serverIPs map[string]time.Time // Stores unique server IPs with a last seen timestamp
}

// Constructor for IPTracker
func NewIPTracker() *IPTracker {
	return &IPTracker{
		clientIPs: make(map[string]time.Time),
		serverIPs: make(map[string]time.Time),
	}
}

// ====== Struct Definitions ======

type Frame struct {
	StartTimestamp time.Time
	EndTimestamp   time.Time
	FrameJitter    float64
	FrameSize      int
	PacketCount    int
}

type TeamsFlow struct {
	SourceIP, DestIP     string
	SourcePort, DestPort uint16
	Timestamp            time.Time

	// RTP
	Marker           bool
	SSRC             uint32
	RTPTimestamp     uint32
	RTPPayloadType   []uint8
	InterArrivalTime time.Duration
	Jitter           float32
	CurrentFrame     *Frame
	MediaTypes       map[string]bool

	// TCP
	Flags               uint8
	SequenceNumber      uint32
	AckNumber           uint32
	WindowSize          uint16
	PayloadLength       int
	RetransmissionCount int
	PacketCount         int
	RetransmissionRate  float32
	LatencyOneWay       time.Duration
	PacketLossCount     int
}

type RTCPHeader struct {
	Version    uint8
	Padding    uint8
	Count      uint8
	PacketType uint8
	Length     uint16
}

type SessionState int

const (
	StateIdle SessionState = iota
	StatePreInitiated
	StateInitiated
	StateConnecting
	StateEstablished
)

type SessionSetup struct {
	Hostname        string
	OperatingSystem string
	DNSQueries      map[string]time.Time
	FlightproxyTime time.Time
	InitiationTime  time.Time
	SFUStartTime    time.Time
	RTPStartTime    time.Time
	CurrentState    SessionState
}

var logEntries []*logrus.Entry

// Custom hook to collect log entries
type LogCollectorHook struct{}

// ====== Initialization ======

func init() {
	// Add custom hooks for logger to convert to csv
	log.AddHook(&LogCollectorHook{})
	log.SetFormatter(&logrus.TextFormatter{
		FullTimestamp: true,
	})

	// Initialize the port ranges for Teams media
	for port := uint16(50000); port <= 50059; port++ {
		MEDIA_PORTS[port] = true
	}

	// Initialize the rtp payload type ranges for Teams media
	for payload_type := uint16(96); payload_type <= 127; payload_type++ {
		RTP_PAYLOAD_TYPES[payload_type] = true
	}

	// Configure logrus for structured logging
	log.SetFormatter(&logrus.TextFormatter{
		FullTimestamp: true,
	})
}

// ====== Helper Functions ======

// Logging

func (h *LogCollectorHook) Levels() []logrus.Level {
	return logrus.AllLevels
}

func (h *LogCollectorHook) Fire(entry *logrus.Entry) error {
	logEntries = append(logEntries, entry)
	return nil
}

// Check if an IP address is in the Teams server IP ranges
func isTeamsIP(ip net.IP) bool {
	for _, ipRange := range IP_RANGES {
		if bytes.Compare(ip, ipRange.first) >= 0 && bytes.Compare(ip, ipRange.last) <= 0 {
			return true
		}
	}
	return false
}

// Structured logging

func logDNSQuery(srcIP string, dstIP string, queryName string, timestamp time.Time) {
	if contains(viewLogs, "all") || contains(viewLogs, "dns") {
		log.WithFields(logrus.Fields{
			"Type":           "DNS",
			"Source IP":      srcIP,
			"Destination IP": dstIP,
			"Query":          queryName,
			"Timestamp":      timestamp,
		}).Info("| MS Teams DNS Traffic")
	}
}

func logSessionSetup(host string, timestamp time.Time, state string, sessionSetupTime *time.Duration) {
	if contains(viewLogs, "all") || contains(viewLogs, "session_setup") {
		session, exists := sessionSetupMap[host]
		if !exists {
			return
		}
		logFields := logrus.Fields{
			"Type":      "Session Setup",
			"Source IP": host,
			"Timestamp": timestamp,
			"State":     state,
			"OS":        session.OperatingSystem,
		}

		if sessionSetupTime != nil {
			logFields["Session Setup Time"] = *sessionSetupTime
		}

		log.WithFields(logFields).Info("| MS Teams Session Setup")
	}
}

func logTCPFlow(flow *TeamsFlow, upstream bool) {
	if contains(viewLogs, "all") || contains(viewLogs, "tcp") {
		trafficDirection := "Downstream"
		if upstream {
			trafficDirection = "Upstream"
		}
		log.WithFields(logrus.Fields{
			"Type":             fmt.Sprintf("%s TCP", trafficDirection),
			"Source IP":        flow.SourceIP,
			"Source Port":      flow.SourcePort,
			"Destination IP":   flow.DestIP,
			"Destination Port": flow.DestPort,
			"Sequence Number":  flow.SequenceNumber,
			"Ack Number":       flow.AckNumber,
			"Flags":            fmt.Sprintf("0x%X", flow.Flags),
			"Window Size":      flow.WindowSize,
			"Payload Length":   flow.PayloadLength,
			"Timestamp":        flow.Timestamp,
			// "Retransmission Count": flow.RetransmissionCount,
			// "Packet Count":         flow.PacketCount,
			// "Retransmission Rate":  flow.RetransmissionRate,
			// "Packet Loss Count":    flow.PacketLossCount,
			// "Latency (One Way)":    flow.LatencyOneWay,
		}).Infof("| MS Teams %s TCP Traffic", trafficDirection)
	}
}

func logUDPFlow(srcIP string, srcPort uint16, dstIP string, dstPort uint16, timestamp time.Time, payloadLength int, upstream bool) {
	if contains(viewLogs, "all") || contains(viewLogs, "udp") {
		trafficDirection := "Downstream"
		if upstream {
			trafficDirection = "Upstream"
		}

		log.WithFields(logrus.Fields{
			"Type":             fmt.Sprintf("%s UDP", trafficDirection),
			"Source IP":        srcIP,
			"Source Port":      srcPort,
			"Destination IP":   dstIP,
			"Destination Port": dstPort,
			"Payload Length":   payloadLength,
			"Timestamp":        timestamp,
		}).Infof("| MS Teams %s UDP Traffic", trafficDirection)
	}
}

func logSTUNFlow(srcIP string, srcPort uint16, dstIP string, dstPort uint16, timestamp time.Time, payloadLength int, stunType string) {
	if strings.Contains(stunType, "response") {
		// stunType = strings.Replace(stunType, "response", "", -1)
		// stunType = strings.TrimSpace(stunType)
	} else if strings.Contains(stunType, "error") && !DEBUG {
		return
	}

	if contains(viewLogs, "all") || contains(viewLogs, "stun") {
		log.WithFields(logrus.Fields{
			"Type":             "STUN",
			"Source IP":        srcIP,
			"Source Port":      srcPort,
			"Destination IP":   dstIP,
			"Destination Port": dstPort,
			"Payload Length":   payloadLength,
			"Message Type":     stunType,
			"Timestamp":        timestamp,
		}).Info("| MS Teams STUN Traffic")
	}
}

func logRTPFlow(flow *TeamsFlow) {
	if contains(viewLogs, "all") || contains(viewLogs, "rtp") {
		var mediaList []string
		for media, detected := range flow.MediaTypes {
			if detected {
				mediaList = append(mediaList, media)
			}
		}

		// Handle case where mediaList is empty
		mediaTypeString := "Unknown"
		if len(mediaList) > 0 {
			mediaTypeString = mediaList[0] // If multiple, take the first one for this log entry
		}

		log.WithFields(logrus.Fields{
			"Type":                    "RTP " + mediaTypeString,
			"Source IP":               flow.SourceIP,
			"Source Port":             flow.SourcePort,
			"Destination IP":          flow.DestIP,
			"Destination Port":        flow.DestPort,
			"Marker":                  flow.Marker,
			"SSRC":                    flow.SSRC,
			"Payload Type":            strings.Join(convertPayloadTypesToStrings(flow.RTPPayloadType), ", "),
			"Media Type":              strings.Join(mediaList, ", "),
			"Sequence Number":         flow.SequenceNumber,
			"Inter-Arrival Time (ms)": flow.InterArrivalTime.Milliseconds(),
			"Payload Length":          flow.PayloadLength,
			"Timestamp":               flow.Timestamp,
			"RTP Timestamp":           flow.RTPTimestamp,
			"Frame Size":              flow.CurrentFrame.FrameSize,
			"Jitter (ms)":             time.Duration(flow.Jitter * float32(time.Second)).Milliseconds(),
			"Frame Jitter (ms)":       time.Duration(flow.CurrentFrame.FrameJitter * float64(time.Second)).Milliseconds(),
		}).Infof("| RTP Traffic %s", func() string {
			if len(flow.RTPPayloadType) > 1 {
				return "(Modified)"
			}
			return ""
		}())
	}
}

func logRTCPFlow(srcIP string, srcPort uint16, dstIP string, dstPort uint16, payloadLength int, timestamp time.Time) {
	if contains(viewLogs, "all") || contains(viewLogs, "rtcp") {
		log.WithFields(logrus.Fields{
			"Type":             "RTCP",
			"Source IP":        srcIP,
			"Source Port":      srcPort,
			"Destination IP":   dstIP,
			"Destination Port": dstPort,
			"Payload Length":   payloadLength,
			"Timestamp":        timestamp,
		}).Info("| MS Teams RTCP Traffic")
	}
}

// Create unique flow IDs

func createDNSFlowID(srcIP string, queryName string) string {
	return fmt.Sprintf("DNS:%s:%s", queryName, srcIP)
}

func createTCPFlowID(srcIP string, dstIP string, seq uint32) string {
	return fmt.Sprintf("TCP:%s->%s-Seq:%d", srcIP, dstIP, seq)
}

func createUDPFlowID(srcIP string, dstIP string, srcPort uint16, dstPort uint16) string {
	return fmt.Sprintf("UDP:%s:%d->%s:%d", srcIP, srcPort, dstIP, dstPort)
}

func createRTPFlowID(srcIP string, dstIP string, ssrc uint32) string {
	return fmt.Sprintf("RTP:%s->%s-SSRC:%d", srcIP, dstIP, ssrc)
}

// ========================================
// ====== Packet Detection Functions ======
// ========================================

// ====== DNS Classification ======

/*
The following regular expressions capture DNS names associated with Microsoft Teams services:

1. `microsoftDNSRegex`:
   - Matches any DNS name ending with:
     - `microsoft.com`: This captures domains directly under Microsoft’s main domain, including various Teams-related subdomains.
     - `trafficmanager.net`: This is used by Microsoft for traffic routing and load balancing, commonly appearing in DNS queries for Teams traffic.
     - `cloudapp.azure.com`: This is used for Azure-hosted services, potentially including Teams instances or services deployed on Azure.
     - `office.net`: This domain is used for services related to Microsoft Office 365, which integrates with Teams for user authentication and data services.
   - The regex captures these domains to identify traffic associated with Microsoft service infrastructure, covering a broad range of Microsoft-related DNS queries for accurate traffic identification.

2. `teamsCallInitDNSRegex`:
   - Matches DNS names indicating call initiation, media relays, and specific infrastructure:
     - Subdomains like `worldaz`, `uswe`, `euno`, `apse`, `weu`, followed by `.tr.teams.microsoft.com` or `.tr.teams.office.net`:
       - These represent specific geographic regions (e.g., `worldaz` for World Azure, `uswe` for US West Europe, etc.).
       - The `tr` subdomain signifies Teams traffic regions, essential for directing media traffic to the nearest geographic data center.
     - `*.relay.teams.microsoft.com`, `*.relay.teams.trafficmanager.net`, `*.relay.teams.cloudapp.azure.com`:
       - These capture DNS queries for media relays used during Teams calls, essential for establishing connections between call participants.
     - `*.flightproxy.teams.microsoft.com`, `*.flightproxy.teams.trafficmanager.net`, `*.flightproxy.teams.cloudapp.azure.com`:
       - These DNS queries indicate interactions with flight proxies, which are used for service monitoring and testing the network path before establishing a call.
     - `*.ic3-calling-enterpriseproxy.*.cosmic.office.net`, `*.enterpriseproxy.*.cosmic.office.net`:
       - These patterns match DNS names associated with enterprise proxy services, essential for directing enterprise call traffic.
       - Captures additional subdomain patterns specific to `ic3-calling-enterpriseproxy` and other enterprise services.
   - The regex captures these DNS queries to track call setup, initiation stages, and enterprise-related infrastructure interactions. This is critical for analyzing call quality, setup times, and understanding the flow of Teams call-related traffic through Microsoft's infrastructure.

3. `teamsFlightProxyDNSRegex`:
   - Specifically matches DNS names related to flight proxies used in Microsoft Teams:
     - Includes patterns like `api`, `r[0-3]-api`, `ep[-\w]*-prod-aks`, `epx[-\w]*`, `flightproxy[-\w]*`, `b[-\w]*`, `a[-\w]*` before `.flightproxy.teams.microsoft.com`, `.flightproxy.teams.trafficmanager.net`, or `.flightproxy.teams.cloudapp.net`.
     - The regex captures these subdomains to focus on DNS interactions with flight proxy services.
     - This allows for the precise identification of DNS queries related to the initiation of a call, aiding in understanding the role of flight proxies in establishing media paths for Microsoft Teams.

+++++++++++++++++++++++++++++++++++++++++++++++++
Strategy for Identifying Session Setup Initiation
+++++++++++++++++++++++++++++++++++++++++++++++++

- The logic for identifying session setup and tracking initiation is based on DNS queries observed in the packet traffic:
	- The primary strategy involves capturing DNS queries related to Teams services and identifying when a session setup starts.
	- If a DNS query matches `teamsFlightProxyDNSRegex`, it indicates an interaction with a flight proxy, a crucial step before call initiation. This is logged with a timestamp, and the `FlightproxyTime` is updated for that source IP.
	- If a DNS query matches `teamsCallInitDNSRegex` but not `teamsFlightProxyDNSRegex`, it indicates the initiation of a call or connection setup (e.g., media relay setup). This step involves the following:
		- The session is initialized in the `sessionSetupMap` if it does not already exist, with the DNS query time recorded.
		- The session's `CurrentState` is set to `StatePreInitiated` initially.
		- If a `FlightproxyTime` exists and the time difference between `FlightproxyTime` and the call initiation DNS query is within a 5-second window, the `InitiationTime` is adjusted to `FlightproxyTime` to accurately reflect the beginning of the session setup.
	- The `sessionSetupMap` tracks ongoing sessions using the source IP as the key, storing details such as DNS queries, the time of the last query, `OperatingSystem`, and `CurrentState`.
	- Each time a DNS query relevant to call setup is observed, the session's state is updated accordingly, and the `InitiationTime` helps determine when the session setup process began.
	- This strategy ensures that all necessary DNS interactions leading to a session setup are captured, allowing for detailed analysis of call initiation times and the flow of traffic through various stages of Teams communication.

*/

// Detect Teams DNS queries
func detectTeamsDNSQuery(packet gopacket.Packet) {
	microsoftDNSRegex := regexp.MustCompile(`(?i)(^|\.)((microsoft\.com$|trafficmanager\.net$|cloudapp\.azure\.com$|office\.net$))`)
	teamsCallInitDNSRegex := regexp.MustCompile(`(?i)(^|\.)((worldaz|uswe|euno|apse|weu|.*)\.tr\.teams\.(microsoft\.com|office\.net)$|.*\.relay\.teams\.(microsoft\.com|trafficmanager\.net|cloudapp\.azure\.com)$|.*\.flightproxy\.teams\.(microsoft\.com|trafficmanager\.net|cloudapp\.azure\.com)$|.*\.(trouter|calling|media|enterpriseproxy)\.teams\.(microsoft\.com|office\.net)$|.*\.(ic3-calling-enterpriseproxy\..*|enterpriseproxy\..*)\.cosmic\.(office\.net)$)`)
	teamsFlightProxyDNSRegex := regexp.MustCompile(`(?i)(^|\.)((api|r[0-3]-api|ep[-\w]*-prod-aks|epx[-\w]*|flightproxy[-\w]*|b[-\w]*|a[-\w]*)\.flightproxy\.teams\.(microsoft\.com|trafficmanager\.net|cloudapp\.net)$)`)

	if dnsLayer := packet.Layer(layers.LayerTypeDNS); dnsLayer != nil {
		dns, _ := dnsLayer.(*layers.DNS)
		transportLayer := packet.TransportLayer()

		for _, query := range dns.Questions {
			queryName := strings.ToLower(string(query.Name))
			if microsoftDNSRegex.MatchString(queryName) {
				srcIP := packet.NetworkLayer().NetworkFlow().Src().String()
				dstIP := packet.NetworkLayer().NetworkFlow().Dst().String()
				srcPort := transportLayer.TransportFlow().Src().String()
				flowID := createDNSFlowID(queryName, srcIP)

				if _, exists := flows[flowID]; !exists {
					flows[flowID] = &TeamsFlow{
						SourceIP:  srcIP,
						DestIP:    dstIP,
						Timestamp: packet.Metadata().Timestamp,
					}
					logDNSQuery(srcIP, dstIP, queryName, packet.Metadata().Timestamp)
				} else {
					flows[flowID].Timestamp = packet.Metadata().Timestamp
					if DEBUG {
						logDNSQuery(srcIP, dstIP, queryName, packet.Metadata().Timestamp)
					}
				}

				if srcPort == "53" || srcPort == "853" {
					return
				}

				if method != 1 {
					return
				}

				if teamsFlightProxyDNSRegex.MatchString(queryName) {
					// create a session setup record with the outgoing flight proxy DNS time
					if _, sessionExists := sessionSetupMap[srcIP]; !sessionExists {
						sessionSetupMap[srcIP] = &SessionSetup{
							Hostname:        srcIP,
							DNSQueries:      make(map[string]time.Time),
							FlightproxyTime: packet.Metadata().Timestamp,
							OperatingSystem: identifyOperatingSystem(packet),
							CurrentState:    StatePreInitiated,
						}
						sessionSetupMap[srcIP].DNSQueries[queryName] = packet.Metadata().Timestamp
						sessionSetupMap[srcIP].FlightproxyTime = packet.Metadata().Timestamp
					} else { // update outgoing unresolved flight proxy DNS time
						sessionSetupMap[srcIP].DNSQueries[queryName] = packet.Metadata().Timestamp
						sessionSetupMap[srcIP].FlightproxyTime = packet.Metadata().Timestamp
					}
				}

				// if a consecutive pattern of call initiation DNS queries is detected, initiate session setup
				if teamsCallInitDNSRegex.MatchString(queryName) && !teamsFlightProxyDNSRegex.MatchString(queryName) {
					session, exists := sessionSetupMap[srcIP]
					// create a session setup record
					if !exists {
						session = &SessionSetup{
							Hostname:        srcIP,
							DNSQueries:      make(map[string]time.Time),
							OperatingSystem: identifyOperatingSystem(packet),
							CurrentState:    StatePreInitiated,
						}
						sessionSetupMap[srcIP] = session
						session.InitiationTime = packet.Metadata().Timestamp

						// if a session setup record was already created (because of flight proxy), use the flight proxy DNS within the last 5 seconds, use that time as the session initiation time
					} else if session.CurrentState == StatePreInitiated && packet.Metadata().Timestamp.Sub(session.FlightproxyTime) <= 5*time.Second {
						session.InitiationTime = session.FlightproxyTime
						// if a session setup record was already created and is in pre initiated state, let's update the initiation time
					} else if session.CurrentState == StatePreInitiated {
						session.InitiationTime = packet.Metadata().Timestamp
					}

					session.DNSQueries[queryName] = packet.Metadata().Timestamp

					if session.CurrentState == StatePreInitiated {
						updateSessionState(srcIP, StateInitiated, session.InitiationTime)
					}
				}

				cleanUpOldSessions(packet.Metadata().Timestamp)
			}
		}
	}
}

// ====== TCP Classification ======

// TCP flag constants
const (
	FlagSYN = 1 << 0
	FlagACK = 1 << 1
	FlagFIN = 1 << 2
	FlagRST = 1 << 3
)

// Detect TCP traffic to Teams servers
func detectTCPToTeams(packet gopacket.Packet) {
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		srcIP := packet.NetworkLayer().NetworkFlow().Src().String()
		dstIP := packet.NetworkLayer().NetworkFlow().Dst().String()

		flags := extractTCPFlags(tcp)
		flowID := createTCPFlowID(srcIP, dstIP, tcp.Seq)

		if isTeamsIP(net.ParseIP(dstIP)) { // upstream
			handleTCPFlow(srcIP, dstIP, tcp, flowID, flags, packet)
			logTCPFlow(flows[flowID], true)
		} else if isTeamsIP(net.ParseIP(srcIP)) { // downstream
			handleTCPFlow(srcIP, dstIP, tcp, flowID, flags, packet)
			logTCPFlow(flows[flowID], false)
		}
		tracker.Update(srcIP, dstIP)
	}
}

// Extracts TCP flags from the packet
func extractTCPFlags(tcp *layers.TCP) uint8 {
	var flags uint8
	if tcp.SYN {
		flags |= FlagSYN
	}
	if tcp.ACK {
		flags |= FlagACK
	}
	if tcp.FIN {
		flags |= FlagFIN
	}
	if tcp.RST {
		flags |= FlagRST
	}
	return flags
}

// Handle TCP flow and calculate LatencyOneWay if SYN-ACK matches SYN packet
func handleTCPFlow(srcIP string, dstIP string, tcp *layers.TCP, flowID string, flags uint8, packet gopacket.Packet) {
	if _, exists := flows[flowID]; !exists {
		flows[flowID] = createTeamsTCPFlow(srcIP, dstIP, tcp, flags, packet)
		if tcp.SYN && tcp.ACK {
			synFlowID := createTCPFlowID(dstIP, srcIP, tcp.Ack-1)
			if synFlow, exists := flows[synFlowID]; exists && synFlow.LatencyOneWay == 0 {
				flows[flowID].LatencyOneWay = packet.Metadata().Timestamp.Sub(flows[synFlowID].Timestamp)
			}
		}
	} else {
		updateTCPFlowDetails(flowID, tcp, flags, packet)
	}
}

// Update flow details and handle retransmission and packet loss detection
func updateTCPFlowDetails(flowID string, tcp *layers.TCP, flags uint8, packet gopacket.Packet) {
	if flow, exists := flows[flowID]; exists { // this is always true, we just need the flow
		expectedSeq := flow.SequenceNumber + uint32(flow.PayloadLength)

		if tcp.Seq > expectedSeq {
			// Calculate the number of missing bytes, assuming standard TCP MSS of 1460 bytes
			missingPackets := (tcp.Seq - expectedSeq) / 1460
			flow.PacketLossCount += int(missingPackets)
		}

		if tcp.Seq == flow.SequenceNumber && tcp.Ack == flow.AckNumber {
			flow.RetransmissionCount++
		}

		flow.SequenceNumber = tcp.Seq
		flow.AckNumber = tcp.Ack
		flow.Flags = flags
		flow.WindowSize = tcp.Window
		flow.PayloadLength = len(tcp.Payload)

		flow.Timestamp = packet.Metadata().Timestamp

		flow.PacketCount++
		flow.RetransmissionRate = float32(flow.RetransmissionCount) / float32(flow.PacketCount)
	}
}

// Create a new TeamsFlow with provided TCP and packet details
func createTeamsTCPFlow(srcIP, dstIP string, tcp *layers.TCP, flags uint8, packet gopacket.Packet) *TeamsFlow {
	return &TeamsFlow{
		SourceIP:            srcIP,
		DestIP:              dstIP,
		SourcePort:          uint16(tcp.SrcPort),
		DestPort:            uint16(tcp.DstPort),
		Timestamp:           packet.Metadata().Timestamp,
		SequenceNumber:      tcp.Seq,
		AckNumber:           tcp.Ack,
		Flags:               flags,
		WindowSize:          tcp.Window,
		PayloadLength:       len(tcp.Payload),
		LatencyOneWay:       0,
		PacketLossCount:     0,
		RetransmissionCount: 0,
	}
}

// ====== SFU Traffic Classification (UDP, STUN, RTP, RTCP) ======

/*

The `detectSFUPacket` function identifies and categorizes traffic related to Selective Forwarding Units (SFUs) in Microsoft Teams.
SFUs are critical in WebRTC-based applications like Teams as they manage the distribution of media streams to different participants.
This method processes incoming UDP packets to identify RTP, RTCP, and STUN traffic, updating flow information and session states accordingly.
The detection logic follows several steps:
1. Extract UDP Layer Information:
   - The function first checks if the packet contains a UDP layer and extracts details like source and destination IPs and ports.
2. Identify Non-Teams IPs with Media Ports:
   - The method targets packets where either the source or destination IP is not a known Microsoft Teams server IP, but one of the ports is a known media port (e.g., RTP).
   - This helps isolate SFU traffic from external participants or servers not part of the core Teams infrastructure.
3. Parse RTP Traffic:
   - Attempts to parse the UDP payload as an RTP header.
   - If successful and the payload type matches known RTP types, the flow is identified as RTP, and a unique flow ID is generated based on the IPs, ports, and RTP SSRC.
   - If the flow does not exist, it is added to the `flows` map with its details, including RTP payload types.
   - Media type classification is performed to categorize the flow as audio, video, or screen sharing.
   - This helps track RTP streams for ongoing media sessions, logging their initiation and updates.
4. Parse RTCP Traffic:
   - If the RTP parsing fails, the function tries to parse the payload as an RTCP packet.
   - RTCP is used for reporting statistics and control messages between endpoints.
   - The flow is recorded if it doesn't already exist, and the RTCP packet details are logged.
   - This helps monitor the quality of ongoing media sessions.
5. Parse STUN Traffic:
   - If neither RTP nor RTCP parsing succeeds, the function checks if the payload is a STUN packet.
   - STUN is used for NAT traversal, which is essential for setting up direct media connections in WebRTC-based applications like Teams.
   - Logs STUN packet flows, which are useful for understanding connection setups and network negotiations.
6. Handle Specific Cases of UDP Traffic:
   - Upstream UDP Traffic: When the destination IP is a known Teams IP and the destination port is 3478 (used for STUN/TURN traffic).
     - Logs the flow as upstream traffic, indicating a client communicating with Teams' STUN servers.
   - Downstream UDP Traffic: When the source IP is a known Teams IP, typically indicating media or control traffic from Teams servers to a client.
     - Logs the flow as downstream traffic for debugging purposes.
7. Update Session States:
   - After identifying the type of packet (RTP, RTCP, or STUN), the function checks if the packet belongs to a session in a "Connecting" state.
   - If so, it updates the session state to "Established" when RTP or RTCP traffic is observed, indicating a successful connection.
   - This state transition is critical for understanding the progress of call setups and identifying potential issues in call initiation phases.

*/

// Detect SFU traffic
func detectSFUPacket(packet gopacket.Packet) {
	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		srcIP := packet.NetworkLayer().NetworkFlow().Src().String()
		dstIP := packet.NetworkLayer().NetworkFlow().Dst().String()
		srcPort := uint16(udp.SrcPort)
		dstPort := uint16(udp.DstPort)
		payloadLength := len(udp.Payload)

		tracker.mu.Lock()

		_, srcInClient := tracker.clientIPs[srcIP]
		_, dstInClient := tracker.clientIPs[dstIP]
		_, srcInServer := tracker.serverIPs[srcIP]
		_, dstInServer := tracker.serverIPs[dstIP]

		tracker.mu.Unlock()

		if !(srcInClient || srcInServer || dstInClient || dstInServer) {
			return
		}

		if (!isTeamsIP(net.ParseIP(srcIP)) && MEDIA_PORTS[srcPort]) || (!isTeamsIP(net.ParseIP(dstIP)) && MEDIA_PORTS[dstPort]) {
			if handleRTPPacket(udp, packet, srcIP, dstIP, srcPort, dstPort, payloadLength) {
				return
			} else if handleRTCPPacket(udp, packet, srcIP, dstIP, srcPort, dstPort, payloadLength) {
				return
			} else if handleSTUNPacket(udp, packet, srcIP, dstIP, srcPort, dstPort, payloadLength) {
				return
			}
		} else if isTeamsIP(net.ParseIP(dstIP)) && uint16(udp.DstPort) == 3478 {
			handleUpstreamUDPPacket(packet, srcIP, dstIP, srcPort, dstPort, payloadLength)
		} else if isTeamsIP(net.ParseIP(srcIP)) && uint16(udp.SrcPort) == 3478 {
			handleDownstreamUDPPacket(packet, srcIP, dstIP, srcPort, dstPort, payloadLength)
		}

		tracker.Update(srcIP, dstIP)
	}
}

// Handle RTP packet
func handleRTPPacket(udp *layers.UDP, packet gopacket.Packet, srcIP, dstIP string, srcPort, dstPort uint16, payloadLength int) bool {
	rtpHeader, err := parseRTPHeader(udp.Payload)
	if err != nil || !RTP_PAYLOAD_TYPES[uint16(rtpHeader.PayloadType)] {
		return false
	}

	flowID := createRTPFlowID(srcIP, dstIP, rtpHeader.SSRC)
	processRTPFlow(packet, flowID, rtpHeader, srcIP, dstIP, srcPort, dstPort, payloadLength)
	return true
}

// Handle RTCP packet
func handleRTCPPacket(udp *layers.UDP, packet gopacket.Packet, srcIP, dstIP string, srcPort, dstPort uint16, payloadLength int) bool {
	if _, err := parseRTCPHeader(udp.Payload); err != nil {
		return false
	}

	flowID := createUDPFlowID(srcIP, dstIP, srcPort, dstPort)
	processRTCPFlow(flowID, srcIP, dstIP, srcPort, dstPort, payloadLength, packet.Metadata().Timestamp)
	return true
}

// Handle STUN packet
func handleSTUNPacket(udp *layers.UDP, packet gopacket.Packet, srcIP, dstIP string, srcPort, dstPort uint16, payloadLength int) bool {
	stunType, err := parseSTUNpacket(udp.Payload)
	if err != nil {
		return false
	}

	flowID := createUDPFlowID(srcIP, dstIP, srcPort, dstPort)
	processSTUNFlow(packet, flowID, srcIP, dstIP, srcPort, dstPort, payloadLength, packet.Metadata().Timestamp, stunType)
	return true
}

// Handle upstream UDP traffic
func handleUpstreamUDPPacket(packet gopacket.Packet, srcIP, dstIP string, srcPort, dstPort uint16, payloadLength int) {
	flowID := createUDPFlowID(srcIP, dstIP, srcPort, dstPort)
	processUDPFlow(flowID, srcIP, dstIP, srcPort, dstPort, payloadLength, packet.Metadata().Timestamp, true)
	if session, exists := sessionSetupMap[srcIP]; exists && session.CurrentState == StateInitiated {
		updateSessionState(srcIP, StateConnecting, packet.Metadata().Timestamp)
	}
}

// Handle downstream UDP traffic
func handleDownstreamUDPPacket(packet gopacket.Packet, srcIP, dstIP string, srcPort, dstPort uint16, payloadLength int) {
	flowID := createUDPFlowID(srcIP, dstIP, srcPort, dstPort)
	processUDPFlow(flowID, srcIP, dstIP, srcPort, dstPort, payloadLength, packet.Metadata().Timestamp, false)
	if session, exists := sessionSetupMap[srcIP]; exists && session.CurrentState == StateInitiated {
		updateSessionState(srcIP, StateConnecting, packet.Metadata().Timestamp)
	}
}

// Process RTP flow
func processRTPFlow(packet gopacket.Packet, flowID string, rtpHeader rtp.Header, srcIP, dstIP string, srcPort, dstPort uint16, payloadLength int) {
	if _, exists := flows[flowID]; !exists {
		flows[flowID] = &TeamsFlow{
			SourceIP:         srcIP,
			DestIP:           dstIP,
			SourcePort:       srcPort,
			DestPort:         dstPort,
			RTPTimestamp:     rtpHeader.Timestamp,
			Timestamp:        packet.Metadata().Timestamp,
			MediaTypes:       make(map[string]bool),
			RTPPayloadType:   []uint8{rtpHeader.PayloadType},
			SSRC:             rtpHeader.SSRC,
			Marker:           rtpHeader.Marker,
			SequenceNumber:   uint32(rtpHeader.SequenceNumber),
			InterArrivalTime: 0,
			PayloadLength:    payloadLength,
			Jitter:           0,
			CurrentFrame:     &Frame{StartTimestamp: packet.Metadata().Timestamp},
		}
		updateMediaTypes(flows[flowID], rtpHeader)
	} else {
		// Existing flow, update timestamps and calculate jitter
		updateRTPFlow(packet, flowID, rtpHeader, payloadLength)
	}
	logRTPFlow(flows[flowID])

	// If marker bit is set, consider it as the end of the frame
	if rtpHeader.Marker {
		flows[flowID].CurrentFrame = &Frame{StartTimestamp: flows[flowID].Timestamp}
	}

	if _, exists := sessionSetupMap[srcIP]; exists {
		updateSessionState(srcIP, StateEstablished, packet.Metadata().Timestamp)
	} else if _, exists := sessionSetupMap[dstIP]; exists {
		updateSessionState(dstIP, StateEstablished, packet.Metadata().Timestamp)
	}
}

// Process RTCP flow
func processRTCPFlow(flowID string, srcIP, dstIP string, srcPort, dstPort uint16, payloadLength int, timestamp time.Time) {
	if _, exists := flows[flowID]; !exists {
		flows[flowID] = &TeamsFlow{
			SourceIP:      srcIP,
			DestIP:        dstIP,
			SourcePort:    srcPort,
			DestPort:      dstPort,
			Timestamp:     timestamp,
			PayloadLength: payloadLength,
		}
	}
	logRTCPFlow(srcIP, srcPort, dstIP, dstPort, payloadLength, timestamp)

	if session, exists := sessionSetupMap[dstIP]; exists && session.CurrentState == StateConnecting { // incoming rtcp packets in case participant is passive
		updateSessionState(dstIP, StateEstablished, timestamp)
	}
}

// Process STUN flow
func processSTUNFlow(packet gopacket.Packet, flowID string, srcIP, dstIP string, srcPort, dstPort uint16, payloadLength int, timestamp time.Time, stunType string) {
	if _, exists := flows[flowID]; !exists {
		flows[flowID] = &TeamsFlow{
			SourceIP:      srcIP,
			DestIP:        dstIP,
			SourcePort:    srcPort,
			DestPort:      dstPort,
			Timestamp:     timestamp,
			PayloadLength: payloadLength,
		}
	}
	logSTUNFlow(srcIP, srcPort, dstIP, dstPort, timestamp, payloadLength, stunType)

	if session, exists := sessionSetupMap[srcIP]; exists {
		if session.CurrentState == StateInitiated {
			updateSessionState(srcIP, StateConnecting, timestamp)
		}
	} else if !isTeamsIP(net.ParseIP(srcIP)) && strings.Contains(stunType, "Allocate request") { // outgoing STUN
		if method != 2 {
			return
		}
		sessionSetupMap[srcIP] = &SessionSetup{
			Hostname:        srcIP,
			OperatingSystem: identifyOperatingSystem(packet),
			CurrentState:    StatePreInitiated,
		}
		sessionSetupMap[srcIP].InitiationTime = packet.Metadata().Timestamp
		updateSessionState(srcIP, StateInitiated, sessionSetupMap[srcIP].InitiationTime)
	}
}

// Process generic UDP flow
func processUDPFlow(flowID string, srcIP, dstIP string, srcPort, dstPort uint16, payloadLength int, timestamp time.Time, isUpstream bool) {
	if _, exists := flows[flowID]; !exists {
		flows[flowID] = &TeamsFlow{
			SourceIP:      srcIP,
			DestIP:        dstIP,
			SourcePort:    srcPort,
			DestPort:      dstPort,
			Timestamp:     timestamp,
			PayloadLength: payloadLength,
		}
	}
	logUDPFlow(srcIP, srcPort, dstIP, dstPort, timestamp, payloadLength, isUpstream)
}

// Update RTP Flow for existing flows to calculate jitter and update timestamps
func updateRTPFlow(packet gopacket.Packet, flowID string, rtpHeader rtp.Header, payloadLength int) {
	previousRTPTimestamp := flows[flowID].RTPTimestamp
	currentRTPTimestamp := rtpHeader.Timestamp
	previousTimestamp := flows[flowID].Timestamp
	currentTimestamp := packet.Metadata().Timestamp

	var sampleRate float64
	if flows[flowID].MediaTypes["Audio"] {
		sampleRate = 16000 // Assume 16 kHz for audio
	} else if flows[flowID].MediaTypes["Video"] || flows[flowID].MediaTypes["ScreenShare"] {
		sampleRate = 90000 // Assume 90 kHz for video/screen sharing
	} else {
		sampleRate = 16000 // Default to audio sample rate if unknown
	}

	rtpTimestampDifference := float64(currentRTPTimestamp-previousRTPTimestamp) / sampleRate
	interArrivalTime := currentTimestamp.Sub(previousTimestamp)
	rtpInterArrivalTime := time.Duration(rtpTimestampDifference * float64(time.Second))

	difference := interArrivalTime - rtpInterArrivalTime
	if difference < 0 {
		difference = -difference
	}

	flows[flowID].Jitter += (float32(difference.Seconds()) - flows[flowID].Jitter) / 16

	currentFrame := flows[flowID].CurrentFrame
	currentFrame.PacketCount++
	currentFrame.FrameSize += flows[flowID].PayloadLength
	currentFrame.EndTimestamp = currentTimestamp
	currentFrame.FrameJitter += (float64(difference.Seconds()) - currentFrame.FrameJitter) / 16

	flows[flowID].RTPTimestamp = currentRTPTimestamp
	flows[flowID].Timestamp = currentTimestamp
	flows[flowID].SequenceNumber = uint32(rtpHeader.SequenceNumber)
	flows[flowID].InterArrivalTime = interArrivalTime
	flows[flowID].PayloadLength = payloadLength
	flows[flowID].Marker = rtpHeader.Marker

	if !containsPayloadType(flows[flowID].RTPPayloadType, rtpHeader.PayloadType) {
		flows[flowID].RTPPayloadType = append(flows[flowID].RTPPayloadType, rtpHeader.PayloadType)
	}
	updateMediaTypes(flows[flowID], rtpHeader)
}

/*

The media classification strategy aims to accurately determine the type of media (audio, video, or screen share)
being transmitted in RTP traffic within Microsoft Teams flows. The classification process is critical for analyzing
media quality and performance in real-time communication. It consists of two steps:
1. Destination Port-Based Classification:
   - This step attempts to classify media types using well-known destination ports:
     - Port 3479: Indicates audio streams, as this port is commonly used for audio media in Microsoft Teams.
     - Port 3480: Indicates video streams, corresponding to video media communication.
     - Port 3481: Indicates screen sharing streams, used when sharing screens between participants.
   - The rationale for this step is that Teams often uses specific ports to streamline the identification of media types,
     allowing faster categorization without requiring deeper packet inspection.
2. Fallback to RTP Payload Type-Based Classification:
   - If a media type cannot be determined solely by the destination port, the method uses the RTP payload type along with
     the source or destination port range:
     - The method checks if the payload type matches known audio, video, or screen share payload types and if the port
       falls within specific ranges (50000-50019 for audio, 50020-50039 for video, 50040-50059 for screen share).
     - The port ranges are used to differentiate between media streams during dynamic port allocation for RTP traffic.
   - This step ensures flexibility in identifying media types when ports do not directly match predefined values, covering
     cases where the Teams application may use dynamic ports for RTP traffic based on network conditions.
This two-tiered strategy balances efficiency and accuracy, using direct port-based identification where possible and
falling back to more granular checks to handle variability in RTP stream setup.

*/

func updateMediaTypes(flow *TeamsFlow, rtpHeader rtp.Header) {
	// Attempt to classify based on destination port -- outgoing traffic to Teams
	switch flow.DestPort {
	case 3479:
		flow.MediaTypes["Audio"] = true
	case 3480:
		flow.MediaTypes["Video"] = true
	case 3481:
		flow.MediaTypes["ScreenShare"] = true
	}

	// If no media type has been defined, classify based on RTP payload type and source/destination port range -- incoming traffic from Teams
	var mediaPort uint16
	if MEDIA_PORTS[flow.SourcePort] {
		mediaPort = flow.SourcePort
	} else {
		mediaPort = flow.DestPort
	}

	if !flow.MediaTypes["Audio"] && mediaPort >= 50000 && mediaPort <= 50019 {
		flow.MediaTypes["Audio"] = true
	}

	if !flow.MediaTypes["Video"] && mediaPort >= 50020 && mediaPort <= 50039 {
		flow.MediaTypes["Video"] = true
	}

	if !flow.MediaTypes["ScreenShare"] && mediaPort >= 50040 && mediaPort <= 50059 {
		flow.MediaTypes["ScreenShare"] = true
	}

	// fallback to heuristic based on RTP payload types
	if !flow.MediaTypes["Audio"] && !flow.MediaTypes["Video"] && !flow.MediaTypes["ScreenShare"] {
		if AUDIO_RTP_PAYLOAD_TYPES[rtpHeader.PayloadType] {
			flow.MediaTypes["Audio"] = true
		}

		if VIDEO_RTP_PAYLOAD_TYPES[rtpHeader.PayloadType] {
			flow.MediaTypes["Video"] = true
		}

		if SCREENSHARE_RTP_PAYLOAD_TYPES[rtpHeader.PayloadType] {
			flow.MediaTypes["ScreenShare"] = true
		}
	}
}

// Updates the state of a session based on the source IP address, new state, and timestamp.
//
// Technical Details:
// - Session State Management: Tracks the lifecycle of a communication session through various states such as Pre-Initiated, Initiated, Connecting, and Established.
// - States:
//   - `StatePreInitiated`: Initial state before any session activity has been detected.
//   - `StateInitiated`: Indicates that a session initiation attempt has been detected (e.g., DNS resolution or initial STUN request).
//   - `StateConnecting`: Represents the phase where the session is transitioning from initiation to establishing a media connection (e.g., ICE checks).
//   - `StateEstablished`: Indicates that the session has successfully set up a media path (e.g., RTP streams).
// - Session Tracking:
//   - `sessionSetupMap`: A map that maintains active sessions, keyed by source IP address (`srcIP`).
//   - `SessionState`: Represents the current state of a session.
//   - `sessionSetupTimesByOS`: Records the time taken to establish sessions, categorized by the detected operating system of the source device.
// - Time-Based Transitions:
//   - The function enforces time-based conditions for state transitions:
//     - `StateInitiated` to `StateConnecting` or `StateEstablished` is allowed only if the time difference between `timestamp` and `session.InitiationTime` is within 30 seconds.
//     - This time limit ensures that sessions are not considered valid if they take too long to progress through the setup phases, which can indicate network issues or dropped connections.
// - Cleanup: When a session reaches the `StateEstablished`, the session information is removed from `sessionSetupMap` to free up resources.
// - Expected Input:
//   - `srcIP`: The source IP address of the session.
//   - `newState`: The target state to which the session should transition.
//   - `timestamp`: The time at which the state transition is detected.
// - Use Case: Useful in scenarios involving real-time communication applications, such as Microsoft Teams, for tracking the progress of session setup and identifying delays in session establishment based on timestamps. It provides insights into session performance and potential issues with connectivity.

func updateSessionState(srcIP string, newState SessionState, timestamp time.Time) {
	session, exists := sessionSetupMap[srcIP]
	if !exists {
		return
	}

	switch newState {
	case StateInitiated:
		if session.CurrentState == StatePreInitiated || session.CurrentState == StateIdle {
			session.CurrentState = StateInitiated
			logSessionSetup(srcIP, timestamp, "Initiation", nil)
		}
	case StateConnecting:
		if session.CurrentState == StateInitiated && timestamp.Sub(session.InitiationTime) <= 30*time.Second {
			session.CurrentState = StateConnecting
			session.SFUStartTime = timestamp
			logSessionSetup(srcIP, timestamp, "Connecting", nil)
		}
	case StateEstablished:
		if (session.CurrentState == StateConnecting || session.CurrentState == StateInitiated) && timestamp.Sub(session.InitiationTime) <= 10*time.Second {
			session.CurrentState = StateEstablished
			session.RTPStartTime = timestamp
			sessionSetupTime := session.RTPStartTime.Sub(session.InitiationTime)
			sessionSetupTimesByOS[session.OperatingSystem] = append(sessionSetupTimesByOS[session.OperatingSystem], sessionSetupTime)
			logSessionSetup(srcIP, timestamp, "Established", &sessionSetupTime)
			delete(sessionSetupMap, srcIP)
		}
	}
}

// Clean up old sessions
func cleanUpOldSessions(now time.Time) {
	for srcIP, session := range sessionSetupMap {
		if now.Sub(session.InitiationTime) > 30*time.Second {
			delete(sessionSetupMap, srcIP)
		}
	}
}

// Check if a payload type exists in the slice
func containsPayloadType(payloadTypes []uint8, payloadType uint8) bool {
	for _, pt := range payloadTypes {
		if pt == payloadType {
			return true
		}
	}
	return false
}

// Convert a slice of uint8 to a slice of strings
func convertPayloadTypesToStrings(payloadTypes []uint8) []string {
	strPayloadTypes := make([]string, len(payloadTypes))
	for i, pt := range payloadTypes {
		strPayloadTypes[i] = fmt.Sprintf("%d", pt)
	}
	return strPayloadTypes
}

/*
Parses an RTP header from raw packet data.

Technical Details:
 - Protocol: RTP (Real-time Transport Protocol), used for delivering audio and video over IP networks.
 - Expected Input: Raw binary data of an RTP packet, with a minimum length of 12 bytes for a valid RTP header.
 - RTP Header Structure: Includes fields such as Version, Payload Type, Sequence Number, Timestamp, SSRC, Marker and more.
 - Version Check: The function verifies that the RTP version is 2, which is the standard version used in most RTP applications.
 - Error Handling: Attempts to strip potential TURN (Traversal Using Relays around NAT) Channel Data prefix if the initial unmarshaling fails, as RTP data may be encapsulated within TURN channels.
 - Output: Returns a parsed `rtp.Header` containing details like the payload type, sequence number, and timestamp, or an error if parsing fails.
 - Use Case: Useful for analyzing RTP packets in real-time communication applications, including those that use TURN servers for NAT traversal (e.g., VoIP, video conferencing).
*/

func parseRTPHeader(data []byte) (rtp.Header, error) {
	if len(data) < 12 {
		return rtp.Header{}, fmt.Errorf("invalid RTP packet, too short")
	}

	header := rtp.Header{}
	if _, err := header.Unmarshal(data); err != nil {
		strippedData := stripTURNChannelData(data)
		if _, err := header.Unmarshal(strippedData); err != nil {
			return rtp.Header{}, fmt.Errorf("failed to unmarshal RTP header: %v", err)
		}
	}

	if header.Version != 2 {
		return rtp.Header{}, fmt.Errorf("invalid RTP version: %d", header.Version)
	}

	return header, nil
}

// Parses an RTCP header from raw packet data.
//
// Technical Details:
// - Protocol: RTCP (RTP Control Protocol), used alongside RTP for providing control and monitoring of multimedia streams.
// - Expected Input: Raw binary data of an RTCP packet, with a minimum length of 4 bytes for a valid RTCP header.
// - RTCP Header Structure:
//   - Version: Extracted from the first 2 bits of the first byte, indicating the protocol version. Standard version is 2.
//   - Padding: A single bit indicating if the packet contains additional padding bytes at the end.
//   - Count: Extracted from the last 5 bits of the first byte, representing either the number of reception report blocks or a format-specific value.
//   - PacketType: Identifies the type of RTCP packet (e.g., Sender Report, Receiver Report).
//   - Length: The length of the RTCP packet, expressed in 32-bit words minus one.
// - Version Check: Validates that the RTCP version is 2, which is required for compliance with standard RTCP specifications.
// - Output: Returns a parsed `RTCPHeader` structure containing details of the RTCP packet, or an error if parsing fails.
// - Use Case: Useful for analyzing RTCP packets in multimedia applications, including feedback mechanisms for RTP streams (e.g., packet loss, jitter, round-trip time) in real-time communications.

func parseRTCPHeader(data []byte) (RTCPHeader, error) {
	if len(data) < 4 {
		return RTCPHeader{}, fmt.Errorf("invalid RTCP packet, too short")
	}

	// Create an RTCP header from the raw data
	header := RTCPHeader{
		Version:    (data[0] >> 6) & 0x03,
		Padding:    (data[0] >> 5) & 0x01,
		Count:      data[0] & 0x1F,
		PacketType: data[1],
		Length:     binary.BigEndian.Uint16(data[2:4]),
	}

	// Validate RTCP version
	if header.Version != 2 {
		return RTCPHeader{}, fmt.Errorf("invalid RTCP version: %d", header.Version)
	}

	return header, nil
}

// parseSTUNpacket parses a STUN packet to identify Microsoft-specific attributes related to protocol versions.
//
// Technical Details:
// - Protocol: STUN (Session Traversal Utilities for NAT), used in NAT traversal and media negotiation.
// - Attributes of Interest:
//   - MS-Version (0x8008): Conveys the TURN protocol version, typically included in Allocate requests
//     from a client and responses from a TURN server.
//   - MS-IMPLEMENTATION-VERSION (0x8070): Indicates the ICE protocol implementation version, included
//     in connectivity check messages as part of ICE negotiation.
// - Expected Input: Raw binary data of a STUN packet, with a minimum length of 20 bytes.
// - Output: Returns the type of STUN message if the relevant attributes are present, or an error if
//   they are missing.
// - Use Case: Useful for identifying STUN messages associated with Microsoft communication protocols,
//   such as those used in Microsoft Teams, by detecting the presence of specific protocol version attributes.

func parseSTUNpacket(data []byte) (string, error) {
	if len(data) < 20 {
		return "", fmt.Errorf("invalid STUN packet, too short")
	}
	msg := &stun.Message{}
	err := msg.UnmarshalBinary(data)
	if err != nil {
		return "", fmt.Errorf("failed to unmarshal STUN packet: %v", err)
	}

	var msVersion, implementationVersion string

	for _, attr := range msg.Attributes {
		switch attr.Type {
		case 0x8008: // MS-VERSION attribute type
			msVersion = string(attr.Value)
		case 0x8070: // MS-IMPLEMENTATION-VERSION attribute type
			implementationVersion = string(attr.Value)
		}
	}

	if msVersion == "" && implementationVersion == "" {
		return "", fmt.Errorf("missing required STUN attributes: MS-Version or IMPLEMENTATION-VERSION not found")
	}

	return msg.Type.String(), nil
}

// Removes TURN ChannelData prefix from the payload, if present.
//
// Technical Details:
// - Protocol: TURN (Traversal Using Relays around NAT), commonly used in real-time communication applications like Microsoft Teams
//   to facilitate media relay when direct peer-to-peer connections are not possible due to NAT restrictions or firewalls.
// - Purpose: In TURN, media data such as RTP can be encapsulated with a ChannelData prefix to optimize transmission between the client
//   and the TURN server. This function removes the ChannelData prefix, allowing the underlying payload (e.g., RTP data) to be processed directly.
// - ChannelData Structure:
//   - Channel Number (2 bytes): Ranges from 0x4000 to 0x7FFF, uniquely identifying the channel in the TURN protocol.
//   - Length (2 bytes): Specifies the length of the encapsulated data in bytes.
// - Microsoft Teams Relevance:
//   - Microsoft Teams uses TURN servers to ensure media connectivity in restricted network environments. If media packets are being relayed through
//     a TURN server in a Teams call, they may contain ChannelData headers that need to be removed to analyze the underlying media flow (such as RTP).
//   - This function can be useful for processing media packets captured in Teams sessions where TURN relaying is active.
// - Conditions for Removal:
//   - The payload must be at least 4 bytes to contain a valid ChannelData header.
//   - The Channel Number must be in the range of 0x4000 to 0x7FFF, which is the standard range for TURN channels.
//   - The total length of the payload must be sufficient to include the ChannelData header and the encapsulated data.
// - Output: Returns the payload with the ChannelData header removed if the conditions are met; otherwise, it returns the original payload.
// - Use Case: This function is useful in scenarios where TURN is used for relaying RTP or other real-time media, particularly in analyzing
//   traffic from applications like Microsoft Teams, where the ChannelData needs to be stripped to access and analyze the underlying media data.

func stripTURNChannelData(payload []byte) []byte {
	if len(payload) >= 4 {
		channelNumber := binary.BigEndian.Uint16(payload[0:2])
		length := binary.BigEndian.Uint16(payload[2:4])
		if channelNumber >= 0x4000 && channelNumber <= 0x7FFF && len(payload) >= int(4+length) {
			return payload[4+length:]
		}
	}
	return payload
}

// Identifies the operating system type based on the TTL (Time to Live) value in an IPv4 packet.
//
// Technical Details:
// - Protocol: IPv4 (Internet Protocol version 4)
// - Analysis Basis: The function uses the Time to Live (TTL) value from the IPv4 header to infer the operating system of the source device.
//   - TTL is a field in the IPv4 header that indicates the maximum number of hops a packet can take before being discarded.
//   - Different operating systems use default initial TTL values when generating packets, which can be used as a heuristic for OS detection.
// - TTL Heuristics:
//   - Windows: Typically uses an initial TTL of 128 or higher.
//   - Linux: Often uses an initial TTL of 64.
//   - macOS/iOS: Commonly uses an initial TTL of 30 or higher.
// - Limitations:
//   - This method provides a heuristic-based estimation and may not be entirely accurate, especially if network conditions or intermediary devices (e.g., routers) decrement the TTL significantly.
//   - TTL values can be customized on a device, leading to potential inaccuracies.
// - Expected Input: A `gopacket.Packet` containing an IPv4 layer.
// - Output: Returns a string indicating the inferred operating system ("Windows", "Linux", "macOS/iOS", or "Unknown").

func identifyOperatingSystem(packet gopacket.Packet) string {
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)

		switch {
		case ip.TTL >= 128:
			return "Windows"
		case ip.TTL >= 64:
			return "Linux"
		case ip.TTL >= 30:
			return "macOS/iOS"
		}
	}
	return "Unknown"
}

// ====== Session Setup Time Visualisations ======

// Plot session setup time
func plotSessionSetupTimes() error {
	for _, osType := range viewPlots {
		switch osType {
		case "all":
			for osKey, osSessionTimes := range sessionSetupTimesByOS {
				if len(osSessionTimes) > 0 {
					if err := plotSessionSetupTimesHelper(osSessionTimes, osKey); err != nil {
						return err
					}
				}
			}
		case "windows":
			if len(sessionSetupTimesByOS["Windows"]) > 0 {
				if err := plotSessionSetupTimesHelper(sessionSetupTimesByOS["Windows"], "Windows"); err != nil {
					return err
				}
			}
		case "linux":
			if len(sessionSetupTimesByOS["Linux"]) > 0 {
				if err := plotSessionSetupTimesHelper(sessionSetupTimesByOS["Linux"], "Linux"); err != nil {
					return err
				}
			}
		case "ios":
			if len(sessionSetupTimesByOS["macOS/iOS"]) > 0 {
				if err := plotSessionSetupTimesHelper(sessionSetupTimesByOS["macOS/iOS"], "macOS/iOS"); err != nil {
					return err
				}
			}
		default:
			log.Warnf("Unsupported plot option: %s", osType)
		}
	}
	return nil
}

func plotSessionSetupTimesHelper(sessionTimes []time.Duration, osType string) error {
	if len(sessionTimes) == 0 {
		return fmt.Errorf("no session setup times to plot")
	}

	var maxSetupTime float64
	for _, setupTime := range sessionTimes {
		if setupTime.Seconds() > maxSetupTime {
			maxSetupTime = setupTime.Seconds()
		}
	}

	maxSetupTimeCeil := math.Ceil(maxSetupTime)

	p := plot.New()

	p.Title.Text = fmt.Sprintf("Session Setup Times for %s Devices", osType)
	p.X.Label.Text = "Session Number"
	p.Y.Label.Text = "Setup Time (s)"

	pts := make(plotter.XYs, len(sessionTimes))
	for i, setupTime := range sessionTimes {
		pts[i].X = float64(i + 1)
		pts[i].Y = setupTime.Seconds()
	}

	scatter, err := plotter.NewScatter(pts)
	if err != nil {
		return err
	}

	scatter.GlyphStyle.Shape = draw.CircleGlyph{}
	scatter.GlyphStyle.Color = color.Black

	p.Add(scatter)

	p.Y.Min = 0
	p.Y.Max = maxSetupTimeCeil

	p.Y.Tick.Marker = plot.TickerFunc(
		func(min, max float64) []plot.Tick {
			var ticks []plot.Tick
			for i := 0.0; i <= maxSetupTimeCeil; i++ {
				ticks = append(ticks, plot.Tick{Value: i, Label: fmt.Sprintf("%ds", int(i))})
			}
			for i := 0.0; i <= maxSetupTimeCeil; i += 0.2 {
				if i != float64(int(i)) {
					ticks = append(ticks, plot.Tick{Value: i, Label: ""})
				}
			}
			return ticks
		})

	filename := fmt.Sprintf("session_setup_times_%s.png", strings.ToLower(osType))
	if err := p.Save(6*vg.Inch, 4*vg.Inch, filename); err != nil {
		return err
	}

	return nil
}

// ====== Process PCAP File ======

func processPcap(fileName string, batchSize int) error {
	handle, err := pcap.OpenOffline(fileName)
	if err != nil {
		return fmt.Errorf("could not open pcap file: %v", err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	var batch []gopacket.Packet
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case packet, ok := <-packetSource.Packets():
			if !ok {
				if len(batch) > 0 {
					err = processBatch(batch)
					if err != nil {
						return fmt.Errorf("could not process batch: %v", err)
					}
					return nil
				}
			}

			batch = append(batch, packet)

			if len(batch) >= batchSize {
				err = processBatch(batch)
				if err != nil {
					return fmt.Errorf("could not process batch: %v", err)
				}
				batch = nil
			}

		case <-ticker.C:
			cleanUpOldSessions(time.Now())
		}
	}
}

func processBatch(batch []gopacket.Packet) error {
	for _, packet := range batch {
		detectTeamsDNSQuery(packet)
		detectTCPToTeams(packet)
		detectSFUPacket(packet)
	}
	return nil
}

func writeLogsToCSV(filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("could not create CSV file: %v", err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	fieldSet := map[string]struct{}{}
	for _, entry := range logEntries {
		for key := range entry.Data {
			fieldSet[key] = struct{}{}
		}
	}

	var headers []string
	for field := range fieldSet {
		headers = append(headers, field)
	}
	sort.Strings(headers)

	if err := writer.Write(headers); err != nil {
		return fmt.Errorf("could not write headers to CSV: %v", err)
	}

	for _, entry := range logEntries {
		record := make([]string, len(headers))

		for i, header := range headers {
			if value, ok := entry.Data[header]; ok {
				record[i] = fmt.Sprintf("%v", value)
			} else {
				record[i] = ""
			}
		}

		if err := writer.Write(record); err != nil {
			return fmt.Errorf("could not write record to CSV: %v", err)
		}
	}

	return nil
}

// ====== Utility Functions ======

// Check if a slice contains a value
func contains(slice []string, value string) bool {
	for _, item := range slice {
		if strings.ToLower(item) == value {
			return true
		}
	}
	return false
}

// validateInputs checks for required inputs and valid method options.
func validateInputs(pcapFiles string, methodOption int) error {
	if pcapFiles == "" {
		return fmt.Errorf("please provide at least one PCAP file using --pcap or -p")
	}
	if methodOption != 1 && methodOption != 2 {
		return fmt.Errorf("invalid method selected. Use '1' for DNS-based analysis or '2' for STUN/ICE timing analysis")
	}
	return nil
}

// expandPcapPatterns processes the glob patterns and returns a list of matching files.
func expandPcapPatterns(pcapFiles string) []string {
	var fileList []string
	for _, pattern := range strings.Split(pcapFiles, ",") {
		absPattern, err := filepath.Abs(strings.TrimSpace(pattern))
		if err != nil {
			fmt.Printf("Error processing pattern '%s': %v\n", pattern, err)
			continue
		}

		matches, err := filepath.Glob(absPattern)
		if err != nil {
			fmt.Printf("Error finding files for pattern '%s': %v\n", absPattern, err)
			continue
		}

		for _, match := range matches {
			if info, err := os.Stat(match); err == nil && !info.IsDir() &&
				(strings.HasSuffix(match, ".pcap") || strings.HasSuffix(match, ".pcapng")) {
				fileList = append(fileList, match)
			}
		}
	}
	return fileList
}

func formatDuration(d time.Duration) string {
	hours := d / time.Hour
	d -= hours * time.Hour
	minutes := d / time.Minute
	d -= minutes * time.Minute
	seconds := d / time.Second

	if hours > 0 {
		return fmt.Sprintf("%dh%dm%ds", hours, minutes, seconds)
	} else if minutes > 0 {
		return fmt.Sprintf("%dm%ds", minutes, seconds)
	}
	return fmt.Sprintf("%ds", seconds)
}

func (tracker *IPTracker) Update(srcIP string, dstIP string) {
	tracker.mu.Lock()
	defer tracker.mu.Unlock()

	if isTeamsIP(net.ParseIP(srcIP)) {
		tracker.serverIPs[srcIP] = time.Now()
		tracker.clientIPs[dstIP] = time.Now()
	} else if isTeamsIP(net.ParseIP(dstIP)) {
		tracker.serverIPs[dstIP] = time.Now()
		tracker.clientIPs[srcIP] = time.Now()
	}
}

func (tracker *IPTracker) Cleanup(expiration time.Duration) {
	tracker.mu.Lock()
	defer tracker.mu.Unlock()

	for ip, lastSeen := range tracker.clientIPs {
		if time.Since(lastSeen) > expiration {
			delete(tracker.clientIPs, ip)
		}
	}

	for ip, lastSeen := range tracker.serverIPs {
		if time.Since(lastSeen) > expiration {
			delete(tracker.serverIPs, ip)
		}
	}
}

// ====== Main Function ======

func main() {
	pcapFiles := flag.String("pcap", "", "Glob pattern or comma-separated list of PCAP files to parse - ensure arguments are marked with double quotes")
	flag.StringVar(pcapFiles, "p", "", "Glob pattern or comma-separated list of PCAP files to parse (shorthand)")

	logOptions := flag.String("logs", "all", "Log options: all, dns, udp, tcp, stun, rtp, session_setup")
	flag.StringVar(logOptions, "l", "all", "Log options: all, dns, udp, tcp, stun, rtp, session_setup (shorthand)")

	plotOptions := flag.String("plot", "", "Plot options: all, windows, linux, ios")
	flag.StringVar(plotOptions, "pl", "", "Plot options: all, windows, linux, ios (shorthand)")

	methodOption := flag.Int("method", 2, "Select the method for calculating session setup time. Use '1' for DNS based analysis or '2' for STUN/ICE timing analysis.")
	flag.IntVar(methodOption, "m", 2, "Method for calculating session setup time (shorthand)")

	batchProcess := flag.Int("batch", 5000, "Specify the number of packets to process in each batch.")
	flag.IntVar(batchProcess, "b", 5000, "Specify the number of packets to process in each batch (shorthand)")

	outputFile := flag.String("output", "", "Output CSV file to write logs")
	flag.StringVar(outputFile, "o", "", "Output CSV file to write logs (shorthand)")

	quietMode := flag.Bool("quiet", false, "Suppress log output if set to true")
	flag.BoolVar(quietMode, "q", false, "Suppress log output if set to true (shorthand)")

	flag.Parse()

	if err := validateInputs(*pcapFiles, *methodOption); err != nil {
		fmt.Println(err)
		flag.Usage()
		os.Exit(1)
	}

	if DEBUG {
		f, _ := os.Create("cpu.prof")
		pprof.StartCPUProfile(f)
		defer pprof.StopCPUProfile()
	}

	if *quietMode {
		log.SetOutput(io.Discard)
	}

	pcapFileList := expandPcapPatterns(*pcapFiles)
	if len(pcapFileList) == 0 {
		fmt.Println("No matching PCAP files found for the provided pattern(s).")
		os.Exit(1)
	}

	method = *methodOption
	viewLogs = strings.Split(strings.ToLower(*logOptions), ",")
	viewPlots = strings.Split(strings.ToLower(*plotOptions), ",")

	if *outputFile != "" || *quietMode {
		log.SetOutput(io.Discard)
	}

	go func() {
		for {
			time.Sleep(10 * time.Second)
			tracker.Cleanup(1800 * time.Second)
		}
	}()

	fmt.Printf("==============================\n")
	fmt.Printf("Selected method: '%d' - %s\n", *methodOption,
		map[int]string{1: "DNS-based analysis", 2: "STUN/ICE timing analysis"}[*methodOption])
	fmt.Printf("Processing %d PCAP %s...\n", len(pcapFileList), map[bool]string{true: "file", false: "files"}[len(pcapFileList) == 1])
	fmt.Printf("==============================\n")

	numLogEntries := 0
	for _, fileName := range pcapFileList {
		fmt.Printf("Processing PCAP '%s'...\n", fileName)
		startTime := time.Now()
		if err := processPcap(fileName, *batchProcess); err != nil {
			log.Fatalf("Error processing PCAP file '%s': %v", fileName, err)
			continue
		}
		elapsedTime := time.Since(startTime)

		fmt.Printf("Finished processing '%s' in %v. Total log entries in file: %d\n", fileName, formatDuration(elapsedTime), len(logEntries)-numLogEntries)
		fmt.Printf("==============================\n")

		// reset flows after each file is processed
		flows = make(map[string]*TeamsFlow)
		sessionSetupMap = make(map[string]*SessionSetup)

		numLogEntries = len(logEntries)
	}

	fmt.Printf("Processing complete. Total log entries: %d\n", len(logEntries))
	fmt.Printf("==============================\n")

	if *outputFile != "" {
		if err := writeLogsToCSV(*outputFile); err != nil {
			fmt.Printf("Error writing logs to CSV: %v\n", err)
		} else {
			fmt.Printf("Logs written to CSV file: %s\n", *outputFile)
		}
		fmt.Printf("==============================\n\n")
	}

	if *plotOptions != "" {
		fmt.Printf("Creating plot for session setup times...\n")
		err := plotSessionSetupTimes()
		if err != nil {
			fmt.Printf("Error generating plot: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Generated plot for session setup times\n")
		fmt.Printf("==============================\n")
	}
}
