package structure;

import java.util.ArrayList;

public class IEEE80211ManagementFrame {
	private long timestamp;
	private String sr_mac;
	private String dst_mac;
	private int seq_num; //probe reqquest帧序列号
	private ArrayList<Integer> IE; //probe request帧的信息元素的编码
	
	public int getSeq_num() {
		return seq_num;
	}
	public void setSeq_num(int seq_num) {
		this.seq_num = seq_num;
	}
	public IEEE80211ManagementFrame(long timestamp, String sr_mac, String dst_mac, int seq_num, ArrayList<Integer> IE) {
		super();
		this.timestamp = timestamp;
		this.sr_mac = sr_mac;
		this.dst_mac = dst_mac;
		this.seq_num = seq_num;
		this.IE = IE;
	}
	public long getTimestamp() {
		return timestamp;
	}
	public void setTimestamp(long timestamp) {
		this.timestamp = timestamp;
	}
	public String getSr_mac() {
		return sr_mac;
	}
	public void setSr_mac(String sr_mac) {
		this.sr_mac = sr_mac;
	}
	public String getDst_mac() {
		return dst_mac;
	}
	public void setDst_mac(String dst_mac) {
		this.dst_mac = dst_mac;
	}
	
	
	
}
