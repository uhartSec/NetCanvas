package main

import (
    "fmt"
    "log"
    "github.com/google/gopacket/pcap"
    "github.com/google/gopacket/layers"
	"github.com/google/gopacket"
	"time"
)


type DeviceInterface struct {
	DeviceAddress string
	Description string
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






var (
    device       string = "wlp3s0"
    snapshot_len int32  = 1024
    promiscuous  bool   = false
    err          error
    timeout      time.Duration = 30 * time.Second
    handle       *pcap.Handle
)

func main() {
    // Open device
    handle, err = pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
    if err != nil {log.Fatal(err) }
    defer handle.Close()

    // Use the handle as a packet source to process all packets
    packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

    for packet := range packetSource.Packets() {
        // Process packet here
		filterPacketInfo(packet)

    }
}
