package com.sniffer.com;

public class Packet {

	/**
	 * @param args
	 */
	String ts;
	String ip_source;
	String ip_destination;
	int ip_payload;
	int ip_size;
	String eth_source;
	String eth_destination;
	int eth_payload;
	int eth_size;
	int eth_type;
	
	
	public Packet(){
		ts = Sniffer.sdf.format(System.currentTimeMillis());
		ip_source = "";
		ip_destination = "";
		ip_payload = 0;
		ip_size = 0;
		
		eth_destination = "";
		eth_source = "";
		eth_payload = 0;
		eth_size = 0;
		eth_type = 0;
	}


	public String getTs() {
		return ts;
	}


	public void setTs(String ts) {
		this.ts = ts;
	}


	public String getIp_source() {
		return ip_source;
	}


	public void setIp_source(String ip_source) {
		this.ip_source = ip_source;
	}


	public String getIp_destination() {
		return ip_destination;
	}


	public void setIp_destination(String ip_destination) {
		this.ip_destination = ip_destination;
	}


	public int getIp_payload() {
		return ip_payload;
	}


	public void setIp_payload(int ip_payload) {
		this.ip_payload = ip_payload;
	}


	public int getIp_size() {
		return ip_size;
	}


	public void setIp_size(int ip_size) {
		this.ip_size = ip_size;
	}


	public String getEth_source() {
		return eth_source;
	}


	public void setEth_source(String eth_source) {
		this.eth_source = eth_source;
	}


	public String getEth_destination() {
		return eth_destination;
	}


	public void setEth_destination(String eth_destination) {
		this.eth_destination = eth_destination;
	}


	public int getEth_payload() {
		return eth_payload;
	}


	public void setEth_payload(int eth_payload) {
		this.eth_payload = eth_payload;
	}


	public int getEth_size() {
		return eth_size;
	}


	public void setEth_size(int eth_size) {
		this.eth_size = eth_size;
	}


	public int getEth_type() {
		return eth_type;
	}


	public void setEth_type(int eth_type) {
		this.eth_type = eth_type;
	}
	


}
