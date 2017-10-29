package com.sniffer.com;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;

import org.jnetpcap.packet.PcapPacket;

//to format data and get headers
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.packet.Payload;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;
import org.jnetpcap.protocol.network.Arp;
//chapter 2.7
import org.jnetpcap.packet.PcapPacketHandler;

//chapter 3.1.2
import org.jnetpcap.protocol.network.Ip4;
//For getting host IP address & MAC
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.net.NetworkInterface;

public class Sniffer2 {

	public static Ip4 ip = new Ip4();
	public static Ethernet eth = new Ethernet();
	public static Tcp tcp = new Tcp();
	public static Udp udp = new Udp();
	/*
	 * public static Rip rip = new Rip() { void printheader() {
	 * System.out.println(rip.getHeader()); } };
	 */

	public static Arp arp = new Arp();
	public static Payload payload = new Payload();
	public static byte[] payloadContent;
	public static boolean readdata = false;
	public static byte[] myinet = new byte[3];
	public static byte[] mymac = new byte[5];

	public static InetAddress inet;
	@SuppressWarnings("rawtypes")
	public static Enumeration e;
	public static NetworkInterface n;
	@SuppressWarnings("rawtypes")
	public static Enumeration ee;

	@SuppressWarnings("deprecation")
	public static void main(String args[]) throws Exception {
		
		List<PcapIf> alldevs = new ArrayList<PcapIf>(); // Will be filled with NICs  
        StringBuilder errbuf = new StringBuilder(); // For any error msgs  
  
        /*************************************************************************** 
         * First get a list of devices on this system 
         **************************************************************************/  
        int r = Pcap.findAllDevs(alldevs, errbuf);  
        if (r == Pcap.NOT_OK || alldevs.isEmpty()) {  
            System.err.printf("Can't read list of devices, error is %s", errbuf  
                .toString());  
            return;  
        }  
  
        System.out.println("Network devices found:");  
  
        int i = 0;  
        for (PcapIf device : alldevs) {  
            String description =  
                (device.getDescription() != null) ? device.getDescription()  
                    : "No description available";  
            System.out.printf("#%d: %s [%s] %s\n", i++, device.getName(), description, device.getAddresses());  
        }  
  
        PcapIf device = alldevs.get(5); // We know we have atleast 1 device  
        System.out  
            .printf("\nChoosing '%s' on your behalf:\n",  
                (device.getDescription() != null) ? device.getDescription()  
                    : device.getName());  		
		
		
		// chapter 2.2-4
		// initiate packet capture device
		final int snaplen = 64 * 1024;
		final int flags = Pcap.MODE_PROMISCUOUS;
		final int timeout = 1000 * 1000; 
		//final StringBuilder errbuf = new StringBuilder();
		Pcap pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);
		if (pcap == null) {
			System.out.println("Error while opening device for capture: "
					+ errbuf.toString());
			return;
		}

		// Get local address
		e = NetworkInterface.getNetworkInterfaces();
		while (e.hasMoreElements()) {
			n = (NetworkInterface) e.nextElement();
			if (device.getName().equals(n.getDisplayName())) {
				ee = n.getInetAddresses();
				mymac = n.getHardwareAddress();
				while (ee.hasMoreElements()) {
					inet = (InetAddress) ee.nextElement();
					System.out.println(n.getDisplayName() + " " + inet);
				}
			}
		}
		// Get IPv4 manually instead of looping through all IP's
		// myinet = inet.getAddress();

		// packet handler for packet capture
		pcap.loop(Integer.parseInt(device.getName()), pcappackethandler, "pressure");
		pcap.close();
	}

	public static PcapPacketHandler<String> pcappackethandler = new PcapPacketHandler<String>() {
		public void nextPacket(PcapPacket pcappacket, String user) {
			if (pcappacket.hasHeader(ip)) {
				if (FormatUtils.ip(ip.source()) != FormatUtils.ip(myinet)
						&& FormatUtils.ip(ip.destination()) != FormatUtils
								.ip(myinet)) {
					System.out.println();
					System.out.println("IP type:\t" + ip.typeEnum());
					System.out.println("IP src:\t-\t"
							+ FormatUtils.ip(ip.source()));
					System.out.println("IP dst:\t-\t"
							+ FormatUtils.ip(ip.destination()));
					readdata = true;
				}
			}
			if (pcappacket.hasHeader(eth) && readdata == true) {
				System.out.println("Ethernet type:\t" + eth.typeEnum());
				System.out.println("Ethernet src:\t"
						+ FormatUtils.mac(eth.source()));
				System.out.println("Ethernet dst:\t"
						+ FormatUtils.mac(eth.destination()));
			}
			if (pcappacket.hasHeader(tcp) && readdata == true) {
				System.out.println("TCP src port:\t" + tcp.source());
				System.out.println("TCP dst port:\t" + tcp.destination());
			} else if (pcappacket.hasHeader(udp) && readdata == true) {
				System.out.println("UDP src port:\t" + udp.source());
				System.out.println("UDP dst port:\t" + udp.destination());
			}
			/*
			 * if (pcappacket.hasHeader(rip) && readdata == true) {
			 * System.out.println("RIP count:\t" + rip.count());
			 * System.out.println("RIP header:\t" + rip.getHeader()); }
			 */
			if (pcappacket.hasHeader(arp) && readdata == true) {

				// System.out.println("ARP decode header:\t" +
				// arp.decodeHeader());
				// System.out.println("ARP hardware type:\t" + arp.
				// hardwareType());
				// System.out.println("ARP hw type descr:\t" +
				// arp.hardwareTypeDescription());
				// System.out.println("ARP hw type enum:\t" +
				// arp.hardwareTypeEnum());
				// System.out.println("ARP hlen:\t-\t" + arp.hlen());
				// System.out.println("ARP operation:\t-\t" + arp.operation());
				// System.out.println("ARP plen:\t-\t" + arp.plen());
				// System.out.println("ARP protocol type:\t" +
				// arp.protocolType());
				// System.out.println("ARP prtcl type descr:\t" +
				// arp.protocolTypeDescription());
				// System.out.println("ARP prtcl type enum:\t" +
				// arp.protocolTypeEnum());
				// System.out.println("ARP sha:\t-\t" +
				// FormatUtils.mac(arp.sha()));
				// System.out.println("ARP sha length:\t-\t" + arp.shaLength());
				// System.out.println("ARP spa:\t-\t" +
				// FormatUtils.ip(arp.spa()));
				// System.out.println("ARP spa length:\t-\t" + arp.spaLength());
				// System.out.println("ARP spa offset:\t-\t" + arp.spaOffset());
				// System.out.println("ARP tha:\t-\t" +
				// FormatUtils.mac(arp.tha()));
				// System.out.println("ARP tha length:\t-\t" + arp.thaLength());
				// System.out.println("ARP tha offset:\t-\t" + arp.thaOffset());
				// System.out.println("ARP tpa:\t-\t" +
				// FormatUtils.ip(arp.tpa()));
				// System.out.println("ARP tpa length:\t-\t" + arp.tpaLength());
				// System.out.println("ARP tpa offset:\t-\t" + arp.tpaOffset());
				System.out.println("ARP Packet!");
				readdata = true;
			}
			if (pcappacket.hasHeader(payload) && readdata == true) {
				payloadContent = payload.getPayload();
				System.out.println("Payload:\n");
				for (int x = 0; x < payloadContent.length; x++) {
					System.out.print(payload.toHexdump());
				}
			}
			if (readdata == true)
				System.out.println("-\t-\t-\t-\t-");
			readdata = false;
		}
	};
	// public static void writeDump(
}