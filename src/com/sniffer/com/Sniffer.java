package com.sniffer.com;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.List;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;

import java.sql.Connection;
import java.sql.DriverManager;

/**
 * 
 * Network devices found: #0: \Device\NPF_{54C9D3F2-A2C3-41DF-A4D5-710DAB096FD6}
 * [Intel(R) Ethernet Connection (3) I218-LM]
 * [[addr=[INET6:FE80:0000:0000:0000:906E:A3B9:5A58:208F], mask=[0],
 * broadcast=[0], dstaddr=null],
 * [addr=[INET6:FE80:0000:0000:0000:906E:A3B9:5A58:208F], mask=[0],
 * broadcast=[0], dstaddr=null]] #1:
 * \Device\NPF_{EF49FC64-96AF-4830-BBB8-79436F7D7422} [Microsoft]
 * [[addr=[INET6:FE80:0000:0000:0000:3DC5:A054:B26B:B45C], mask=[0],
 * broadcast=[0], dstaddr=null],
 * [addr=[INET6:FE80:0000:0000:0000:3DC5:A054:B26B:B45C], mask=[0],
 * broadcast=[0], dstaddr=null]] #2:
 * \Device\NPF_{DB3E59D4-F0D7-4262-8E12-15E5DEED5F86} [Microsoft]
 * [[addr=[INET4:192.168.0.122], mask=[INET4:255.255.255.0],
 * broadcast=[INET4:255.255.255.255], dstaddr=null],
 * [addr=[INET6:FE80:0000:0000:0000:7981:688B:4057:0627], mask=[0],
 * broadcast=[0], dstaddr=null]]
 * 
 */
public class Sniffer {

	/**
	 * Main startup method
	 * 
	 * @param args
	 *            ignored
	 */
	static SimpleDateFormat sdf = new SimpleDateFormat(
			"yyyy-MM-DD HH:mm:ss.SSS");
	static Connection conn;

	@SuppressWarnings("deprecation")
	public static void main(String[] args) {

		MakeConnection();

		List<PcapIf> alldevs = new ArrayList<PcapIf>(); // Will be filled with
														// NICs
		StringBuilder errbuf = new StringBuilder(); // For any error msgs

		/***************************************************************************
		 * First get a list of devices on this system
		 **************************************************************************/
		int r = Pcap.findAllDevs(alldevs, errbuf);
		if (r == Pcap.NOT_OK || alldevs.isEmpty()) {
			System.err.printf("Can't read list of devices, error is %s",
					errbuf.toString());
			return;
		}

		System.out.println("Network devices found:");

		int i = 0;
		for (PcapIf device : alldevs) {
			String description = (device.getDescription() != null) ? device
					.getDescription() : "No description available";
			System.out.printf("#%d: %s [%s] %s\n", i++, device.getName(),
					description, device.getAddresses());
		}

		PcapIf device = alldevs.get(2); // We know we have atleast 1 device
		System.out.printf("\nChoosing '%s' on your behalf:\n",
				(device.getDescription() != null) ? device.getDescription()
						: device.getName());

		/***************************************************************************
		 * Second we open up the selected device
		 **************************************************************************/
		int snaplen = 64 * 1024; // Capture all packets, no trucation
		int flags = Pcap.MODE_PROMISCUOUS; // capture all packets
		int timeout = 1000 * 1000; // 10 seconds in millis
		Pcap pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout,
				errbuf);

		if (pcap == null) {
			System.err.printf("Error while opening device for capture: "
					+ errbuf.toString());
			return;
		}

		/***************************************************************************
		 * Third we create a packet handler which will receive packets from the
		 * libpcap loop.
		 **************************************************************************/
		PcapPacketHandler<String> jpacketHandler = new PcapPacketHandler<String>() {

			public void nextPacket(PcapPacket packet, String ts) {

				PacketRunner runner = new PacketRunner(packet, ts);
				runner.run();

			};
		};

		/***************************************************************************
		 * Fourth we enter the loop and tell it to capture 10 packets. The loop
		 * method does a mapping of pcap.datalink() DLT value to JProtocol ID,
		 * which is needed by JScanner. The scanner scans the packet buffer and
		 * decodes the headers. The mapping is done automatically, although a
		 * variation on the loop method exists that allows the programmer to
		 * sepecify exactly which protocol ID to use as the data link type for
		 * this pcap interface.
		 **************************************************************************/
		pcap.loop(Pcap.LOOP_INFINITE, jpacketHandler,
				sdf.format(System.currentTimeMillis()));

		/***************************************************************************
		 * Last thing to do is close the pcap handle
		 **************************************************************************/
		pcap.close();

	}

	private static void MakeConnection() {
		try {

			// create a connection to the database
			conn = DriverManager
					.getConnection("jdbc:sqlite:C:/Users/Bot/Documents/JavaLibs/sqlight/chinook.db");
			// DriverManager.getConnection("jdbc:sqlite:C:/Users/Bot/Documents/JavaLibs/sqlight/chinook.db").createStatement().execute("CREATE TABLE IF NOT EXISTS warehouses (\n"
			// + "	id integer PRIMARY KEY,\n"
			// + "	name text NOT NULL,\n"
			// + "	capacity real\n"
			// + ");");

			System.out.println("Connection to SQLite has been established.");
		} catch (Exception E) {
			E.printStackTrace();
		}
	}

	public static int writePacket(Packet p) {
		try {		
			
			return conn.createStatement()
					.executeUpdate(
							"INSERT INTO  packet_traffic(ts, ip_source, ip_destination, ip_payload, ip_size, eth_source, eth_destination, eth_payload, eth_size, eth_type) VALUES(\""
									+ p.getTs()
									+ "\",  \""
									+ p.getIp_source()
									+ "\", \""
									+ p.getIp_destination()
									+ "\", "
									+ p.getIp_payload()
									+ ", "
									+ p.getIp_size()
									+ ", \""
									+ p.getEth_source()
									+ "\", \""
									+ p.getEth_destination()
									+ "\", "
									+ p.getEth_payload()
									+ ",  "
									+ p.getEth_size()
									+ ",  "
									+ p.getEth_type() + ")");

		} catch (Exception E) {
			E.printStackTrace();
			return -1;
		}
	}
}
