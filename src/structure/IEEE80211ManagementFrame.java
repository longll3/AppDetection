package structure;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.Map;

public class IEEE80211ManagementFrame {
	private long macTimestamp; //radiotap header中的时间戳
	private int timestamp; //pcap头中的时间戳
	private String sr_mac;
	private String dst_mac;
	private int frame_len;
	
	private int seq_num; //probe reqquest帧序列号
	private ArrayList<Integer> IE; //probe request帧的信息元素的编码
	private Map<Integer, byte[]> IEs; //probe request帧的信息元素的编码及byte[]值

	private LinkedHashMap<Integer, byte[]> sequenceIEs; //使用linkedhashmap保存IE的出现顺序
	
	public int getSeq_num() {
		return seq_num;
	}
	public void setSeq_num(int seq_num) {
		this.seq_num = seq_num;
	}
	
	public LinkedHashMap<Integer, byte[]> getSequenceIEs() { return sequenceIEs; }
	
	public Map<Integer, byte[]> getIEs() {
		return IEs;
	}
	public void setIEs(Map<Integer, byte[]> iEs) {
		IEs = iEs;
	}

	public IEEE80211ManagementFrame(long macTimestamp, String sr_mac, String dst_mac, int seq_num, Map<Integer, byte[]> IEs, ArrayList<Integer> IE, LinkedHashMap<Integer, byte[]> sequenceIEs, int length, int timestamp) {
		super();
		this.macTimestamp = macTimestamp;
		this.sr_mac = sr_mac;
		this.dst_mac = dst_mac;
		this.seq_num = seq_num;
		this.IEs = IEs;
		this.IE = IE;
		this.sequenceIEs = sequenceIEs;
		this.timestamp = timestamp;

		byte ssid[] = IEs.get(0);
		if (ssid.length == 0) {
			this.frame_len = length;
		} else {
			this.frame_len = length - ssid.length;
		}
	}

	public int getTimestamp() {
		return timestamp;
	}

	public void setTimestamp(int timestamp) {
		this.timestamp = timestamp;
	}

	public long getMacTimestamp() {
		return macTimestamp;
	}
	public void setMacTimestamp(long macTimestamp) {
		this.macTimestamp = macTimestamp;
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

	public int getFrame_len() {
		return frame_len;
	}

	public void setFrame_len(int frame_len) {
		this.frame_len = frame_len;
	}
}
