package com.sniffer.com;

import java.text.SimpleDateFormat;

import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Arp;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;

public class PacketRunner extends Object implements Runnable {

	String timestamp;
	PcapPacket packet;
	Ip4 ip2 = new Ip4();
	Tcp tcp = new Tcp();
	Udp udp = new Udp();
	Arp arp = new Arp();

	public PacketRunner(PcapPacket packet) {
		try {
			this.packet = packet;
			packet.hasHeader(ip2);
			packet.hasHeader(tcp);
			packet.hasHeader(udp);
			packet.hasHeader(arp);
			timestamp = new SimpleDateFormat("yyyy-MM-DD HH:mm:ss.SSS")
					.format(System.currentTimeMillis());

		} catch (Exception E) {
			E.printStackTrace();
		}
	}

	@Override
	public void run() {
		try {

			// get ip address so we know its the TV
		
			String src = FormatUtils.ip(ip2.source()).toString();
			String dst = FormatUtils.ip(ip2.destination()).toString();

			if (src.equals("192.168.0.181") || dst.equals("192.168.0.181")) {
				System.out.printf(timestamp + ":: TV! header TTL=" + ip2.ttl()
						+ " [src IP]=" + src + " [dst IP]=" + dst + " Size="
						+ packet.getCaptureHeader().wirelen() + "\n");

			}

			if (packet.hasHeader(udp)) {
				System.out.printf("\n UDP Packet ");
				System.out.println(udp.source() + " " + udp.destination() + " "
						+ udp.getPayloadLength());
				Ethernet eth = new Ethernet();
				packet.hasHeader(eth);
				dst = FormatUtils.mac(eth.destination());
				src = FormatUtils.mac(eth.source());
				String type = Integer.toHexString(eth.type());

				System.out.println(src + " -> " + dst + ":" + type
						+ " Eth tot pkts=[" + packet.size() + "]");

			}
			System.out.printf(timestamp + ":: TV! header TTL=" + ip2.ttl()
					+ " [src IP]=" + src + " [dst IP]=" + dst + " Size="
					+ packet.getCaptureHeader().wirelen() + "\n");

		} catch (Exception E) {
			E.printStackTrace();
		}

	}

}
