package com.sniffer.com;

import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Udp;

/*
 * @TV Information
 * IP	192.168.0.181
 * MAC	14:C9:13:77:62:C1
 * 
 * Router
 * MAC	10:BE:F5:1C:6B:70
 * IP	192.168.0.1  
 */

public class PacketRunner extends Object implements Runnable {

	private volatile boolean isRunning = true;
	private boolean load = false;

	String timestamp;
	PcapPacket packet;
	Ip4 ip2 = new Ip4();
	// Tcp tcp = new Tcp();
	Udp udp = new Udp();

	// Arp arp = new Arp();

	public PacketRunner(PcapPacket packet, String ts) {
		try {
			this.packet = packet;
			timestamp = ts;

		} catch (Exception E) {
			E.printStackTrace();
		}
	}

	@Override
	public void run() {
		try {

			while (isRunning) {
				/*
				 * IP level information
				 */
				Packet p = new Packet();
				//p.setTs(timestamp);

				if (packet.hasHeader(ip2)) {
					if (FormatUtils.ip(ip2.source()).toString()
							.equals("192.168.0.181")
							|| FormatUtils.ip(ip2.destination()).toString()
									.equals("192.168.0.181")) {
						load = true;
						p.setIp_source(FormatUtils.ip(ip2.source()).toString());
						p.setIp_destination(FormatUtils.ip(ip2.destination())
								.toString());
						p.setIp_size(ip2.size());
						p.setIp_payload(ip2.getPayloadLength());

					} else
						kill();
				}

				// if (packet.hasHeader(tcp)) {
				// // TODO
				//
				// }

				if (packet.hasHeader(udp)) {

					Ethernet eth = new Ethernet();
					packet.hasHeader(eth);
					if (FormatUtils.mac(eth.destination()).equals(
							"14:C9:13:77:62:C1")
							|| FormatUtils.mac(eth.source()).equals(
									"14:C9:13:77:62:C1")) {
						load = true;
						p.setEth_destination(FormatUtils.mac(eth.destination()));
						p.setEth_source(FormatUtils.mac(eth.source()));
						p.setEth_size(udp.size());
						p.setEth_payload(eth.getPayloadLength());
						p.setEth_type(eth.type());
					} else
						kill();
				}
				if(load) Sniffer.writePacket(p);
				kill();
			}

		} catch (Exception E) {
			E.printStackTrace();
		}

	}

	public void kill() {
		isRunning = false;
		//System.out.println("Thread Killed! ");
	}

}
