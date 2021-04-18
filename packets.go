package main

import (
    "fmt"
    "log"
    "github.com/google/gopacket/pcap"
    "github.com/google/gopacket/layers"
	"github.com/google/gopacket"
	//"time"
	"flag"
	"os"
)

/**
Used for testing filter layers
UDP, TCP, IPV4, ETHERNET

*/
func filterPacketInfo(packet gopacket.Packet){

	// Ethernet packet
	ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
    if ethernetLayer != nil {
        fmt.Println("Ethernet layer detected.")
        ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)
        fmt.Println("Source MAC: ", ethernetPacket.SrcMAC)
        fmt.Println("Destination MAC: ", ethernetPacket.DstMAC)

        // Ethernet type is typically IPv4 but could be ARP or other
        fmt.Println("Ethernet type: ", ethernetPacket.EthernetType)
    }


	//Filter IPV4
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
    if ipLayer != nil {
        fmt.Println("IPv4 layer detected.")
        ip, _ := ipLayer.(*layers.IPv4)

        fmt.Printf("From %s to %s\n", ip.SrcIP, ip.DstIP)
        fmt.Println("Protocol: ", ip.Protocol)
        fmt.Println()
    }

	//filter UDP
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer != nil {
		fmt.Println("Udp layer ")
		udpPacket, _ := udpLayer.(*layers.UDP)
		fmt.Printf("From %s to %s\n", udpPacket.SrcPort, udpPacket.DstPort)
	}

}


func getDevices(){

    // Find all devices
    devices, err := pcap.FindAllDevs()
    if err != nil {
        log.Fatal(err)
    }

    // Print device information
    fmt.Println("Devices found:")
    for _, device := range devices {
        fmt.Println("\nName: ", device.Name)
        fmt.Println("Description: ", device.Description)
        fmt.Println("Devices addresses: ", device.Description)
        for _, address := range device.Addresses {
            fmt.Println("- IP address: ", address.IP)
            fmt.Println("- Subnet mask: ", address.Netmask)
        }
    }
}



/**
var (
    device       string = "wlp3s0"
    snapshot_len int32  = 1024
    promiscuous  bool   = false
    err          error
    timeout      time.Duration = 30 * time.Second
    handle       *pcap.Handle
)

*/

func main() {
    // Open device
	deviceInterface := flag.String("i", "all", "View device interfaces")	
	//setDeviceInterface := flag.String("d", "wlp3d0", "Listen on interface")
	flag.Parse()

	if *deviceInterface == ""{
		flag.PrintDefaults()
		os.Exit(1)
	}

	switch os.Args[2] {
		case "all":
			getDevices()

		default:
			flag.PrintDefaults()
	}





	/**
    handle, err = pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
    if err != nil {log.Fatal(err) }
    defer handle.Close()

    // Use the handle as a packet source to process all packets
    packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

    for packet := range packetSource.Packets() {
        // Process packet here
		filterPacketInfo(packet)

    }
	*/
}
