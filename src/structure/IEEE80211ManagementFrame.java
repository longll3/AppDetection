package structure;

import java.util.ArrayList;
import java.util.Map;

public class IEEE80211ManagementFrame {
	private long timestamp;
	private String sr_mac;
	private String dst_mac;
	
	private int seq_num; //probe reqquest帧序列号
	private ArrayList<Integer> IE; //probe request帧的信息元素的编码
	private Map<Integer, byte[]> IEs; //probe request帧的信息元素的编码及byte[]值
	
	public int getSeq_num() {
		return seq_num;
	}
	public void setSeq_num(int seq_num) {
		this.seq_num = seq_num;
	}
	
	
	
	public Map<Integer, byte[]> getIEs() {
		return IEs;
	}
	public void setIEs(Map<Integer, byte[]> iEs) {
		IEs = iEs;
	}
	public IEEE80211ManagementFrame(long timestamp, String sr_mac, String dst_mac, int seq_num, Map<Integer, byte[]> IEs, ArrayList<Integer> IE) {
		super();
		this.timestamp = timestamp;
		this.sr_mac = sr_mac;
		this.dst_mac = dst_mac;
		this.seq_num = seq_num;
		this.IEs = IEs;
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
	public ArrayList<Integer> getIE() {
		return IE;
	}
	public void setIE(ArrayList<Integer> iE) {
		IE = iE;
	}
	
}
