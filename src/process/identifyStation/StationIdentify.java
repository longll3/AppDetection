package process.identifyStation;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import DeviceMap.DeviceMap;
import signature.SignatureForIFAT;
import parser.IEEE80211Parser;
import structure.IEEE80211ManagementFrame;
import util.DTWDistance;

/**
 * 终端随机mac地址追踪
 * @author longlong
 *
 */
public class StationIdentify {
	private IEEE80211Parser parser; //解析文件工具
	
	//存放当前捕捉到的终端集合，key为终端的编号，value为终端的mac地址集合
	private Map<Integer, StationInfo> stationMap;
	private Map<Integer, StationInfoOfIFAT> stationMapOfIFAT;
	
	private final static int MaxSeqNum = 4095;
	private final static int SeqNumMaxDiff = 600;
	private final static int HTCapabilitiesID = 45;
	
	
	//用于区分终端所需要用到的信息,通过序列号和IE等信息
	private class StationInfo {
		private ArrayList<IEEE80211ManagementFrame> frameList;
		private int lastSeq;
		private String lastMAC;
		
		private ArrayList<Integer> IEType;
		private Map<Integer, byte[]> IEs;
		
		public StationInfo() {
			frameList = new ArrayList<>();
			lastSeq = -1;
			lastMAC = "";
			IEs = new HashMap<>();
		}
		
		public void setLastSeq(int seq) { this.lastSeq = seq; }
		public int getLastSeq() { return this.lastSeq; }
		
		public void setLastMAC(String mac) { this.lastMAC = mac; }
		public String getLastMAC() { return this.lastMAC; }
		
		public void updateIEType(ArrayList<Integer> IEList) {
			this.IEType = IEList;
		}
		
//		public Set<ArrayList<Integer>> getIEs() { return this.IEs; }
			
		public Map<Integer, byte[]> getIEs() { return this.IEs; }
		
		public void setIEs(Map<Integer, byte[]> IEs) { this.IEs = IEs; }
		
		public void addFrame(IEEE80211ManagementFrame frame) {
			this.frameList.add(frame);
			this.setLastMAC(frame.getSr_mac());
			this.setLastSeq(frame.getSeq_num());
			this.updateIEType(frame.getIE());
			this.setIEs(frame.getIEs());
		}
		
		@Override
		public String toString() {
			String re = "frame number:"+this.frameList.size()+", IE type:[";
			for (Integer type : this.IEType) {
				re += type.toString()+", ";
			}
			re += "]";
			return re;
		}
		
	}
	
	
	
	//用于区分终端所需要用到的信息,加入了IFAT签名
	//序列号，MAC地址集合，IFAT签名
	private class StationInfoOfIFAT {

		private ArrayList<IEEE80211ManagementFrame> frameList;
		private int lastSeq;
		//区分后的MAC地址集 
		private Set<String> MACs;
		private SignatureForIFAT sig;
		
		public StationInfoOfIFAT(ArrayList<IEEE80211ManagementFrame> burst) {
			ArrayList<Long> frameArr = new ArrayList<>();
			for (int i = 1; i < burst.size(); i++) {
				frameArr.add(burst.get(i).getTimestamp()-burst.get(i-1).getTimestamp());
			}
			//将burst中的最后一帧的序列号set为lastSeq，为了跟下一个设备可以用帧号进行协助判断
			setLastSeq(burst.get(burst.size()).getSeq_num());
			sig = new SignatureForIFAT(frameArr);
			frameList = new ArrayList<>();
			frameList.addAll(burst);
			MACs.add(burst.get(0).getSr_mac());
			
		}
		
		public void setLastSeq(int seq) { this.lastSeq = seq; }
		public int getLastSeq() { return this.lastSeq; }
		
		public void addBurst(ArrayList<IEEE80211ManagementFrame> burst) {
			this.frameList.addAll(burst);
		}
		
		public void updateSignature(ArrayList<Long> ifat_burst) {
			this.sig.updateSig(ifat_burst);
		}
		
		
		@Override
		public String toString() {
			String re = "本终端共发出 " + this.frameList.size() + " 个probe request帧";
			re = "本终端所使用到的mac地址有";
			for (String mac : this.MACs) {
				re += mac;
			}
			return re;
		}
		
	}
	
	public StationIdentify() {
		this.parser = new IEEE80211Parser();
		stationMap = new HashMap<>();
	}
	
	public void process(String filename) throws IOException {
		this.parser.setFile(new File(filename));
		this.parser.parse();
		this.parser.openInfoElementsFlag();
		
		this.parser.printIE();
		
		for (IEEE80211ManagementFrame frame: this.parser.getTimeArray()) {
			judgeBySeqAndIEType(frame);
//			judgeBySeqAndHTCapInfo(frame);
		}
		
	}
	
	
	/**
	 * 通过序列号，MAC地址和IFAT签名来判断终端是否是同一个
	 */
	public void judgeBySeqAndMACAndIFATSig(IEEE80211ManagementFrame frame) {
		
	}
	
	
	private boolean matchSeqNum(int lastSeq, int seq) {
		//首先seq一定是比上一帧要大,且在一定范围内
		//另一种情况就是seq的值达到最大需要从头开始计数时
		if ((seq > lastSeq && seq - lastSeq < SeqNumMaxDiff) || (seq + MaxSeqNum - lastSeq < SeqNumMaxDiff)) {
			return true;
		}
		
		return false;
	}
	
	public void judgeByIFATAndSeq(ArrayList<IEEE80211ManagementFrame> burst) {
		DTWDistance dtw = new DTWDistance();
		Long[] burst_arr = new Long[burst.size()];
		
		Long lastFrame_timestamp = burst.get(0).getTimestamp();
		for (int i = 0; i < burst.size(); i++) burst_arr[i] = burst.get(i+1).getTimestamp() - lastFrame_timestamp;
		
		//找到距离最小的。
		int index = 0; //标记归类的是那个终端
		double minDistance = Double.MAX_VALUE;
		for (int i = 1; i < this.stationMap.size(); i++) {
			StationInfoOfIFAT stationInfo = this.stationMapOfIFAT.get(i);
			SignatureForIFAT sig = stationInfo.sig;
			
			double distance = dtw.getDTWDistance(sig.getSig().get(burst.size()), burst_arr);
//			double factor = (1-sig.getBurstSizeDistribution().get(burst.size());
//			double realDistance = distance*factor; 
			
			if (minDistance > distance) {
				minDistance = distance;
				index = i;
			}
		}
		
		if (index == 0) {
			// station map is empty
			StationInfoOfIFAT stationInfo = new StationInfoOfIFAT(burst);
			
			this.stationMapOfIFAT.put(1, stationInfo);
		} else if (minDistance > 40000) {
			//当最小距离都很大时，则认为时一个新的终端
			StationInfoOfIFAT stationInfo = new StationInfoOfIFAT(burst);
			
//			this.stationMapOfIFAT.put(1, stationInfo);
		} else {
			ArrayList<Long> tt = new ArrayList<>();
			for (Long ifat: burst_arr) tt.add(ifat);
			stationMapOfIFAT.get(index).sig.updateSig(tt);
			stationMapOfIFAT.get(index).lastSeq = burst.get(burst.size()-1).getSeq_num();
			stationMapOfIFAT.get(index).MACs.add(burst.get(0).getSr_mac());

		}
		
		
	}
	
	
	/**
	 * 通过seq和mac 和 IE的种类进行判断
	 * @param frame
	 */
	public void judgeBySeqAndIEType(IEEE80211ManagementFrame frame) {
		int seq = frame.getSeq_num();
		String srcMAC = frame.getSr_mac();
		ArrayList<Integer> IE = frame.getIE();
		
		int stationSize = this.stationMap.size();
		if (stationSize == 0) {
			//是收到的第一个帧
			StationInfo station = new StationInfo();
			station.addFrame(frame);
			this.stationMap.put(1, station);
		} else {
			//注意：应该先把所有的mac地址都进行一次判断，要不然如果在前面MAC地址不一样，但匹配到了IE种类一样的，而序列号又不符合要求，则直接会添加一个新的StationInfo，而完全匹配的MAC地址却在后面。
			boolean match = matchMAC(frame);
			if (match) return;	
			else {
				//再遍历已经收集到的终端，寻找IE总类一样的且序列号匹配的
				for (int i = 1; i <= stationSize; i++) {
					if (match) break;
					
//					Set<Integer> stationMapIEs = stationMap.get(i).IEs.keySet();
//					ArrayList<Integer> ie = new ArrayList<>(stationMapIEs);
						
					if (IE.equals(stationMap.get(i).IEType)) {
						if (seq > stationMap.get(i).getLastSeq() && seq - stationMap.get(i).getLastSeq() < 500) {
//						if (matchSeqNum(stationMap.get(i).getLastSeq(), seq)) {
							//MAC地址不一样时，首先比较sequence number的大小，若小于上一个的大小，则为另一个终端，或者相差超过40的，则也为另一个终端
							//但是有一个问题，就是有些设备的序列号不会递增到4096才重置，如honor10（是另一个设备，具体是哪一个，还得去看一下），其序列号的范围则只在30以内（大概），这个问题应该怎么解决呢？
							this.stationMap.get(i).addFrame(frame);
							match = true;
						} else if ((stationMap.get(i).getLastSeq() - 4096) < 100 && seq < 100) {
							//序列号为[0-4095]，这是序列号重新开始的情况
							this.stationMap.get(i).addFrame(frame);
							match = true;
							
						} 
					}	
					
				}
				if (!match) {
					//IE种类不一样，MAC不一样，再次就认为是另一种设备
					StationInfo station = new StationInfo();
					station.addFrame(frame);
					this.stationMap.put(stationSize+1, station);
				}
			}
			
			
		}
		
		
	}
		
	public Set<ArrayList<IEEE80211ManagementFrame>> generateBurstSet(ArrayList<IEEE80211ManagementFrame> frameArr) {
		Map<String, ArrayList<IEEE80211ManagementFrame>> macMap;
		return null;
		
	}
	
	/**
	 * 以MAC地址为划分依据，将同一个MAC地址的所有帧映射到一起
	 * @param frameArr
	 * @return
	 */
	public Map<String, ArrayList<IEEE80211ManagementFrame>> partitionByMac(ArrayList<IEEE80211ManagementFrame> frameArr) {
		Map<String, ArrayList<IEEE80211ManagementFrame>> re = new HashMap<>();
		for (IEEE80211ManagementFrame frame : frameArr) {
			 if (re.containsKey(frame.getSr_mac())) {
				 re.get(frame.getSr_mac()).add(frame);
			 } else {
				 ArrayList<IEEE80211ManagementFrame> frameList = new ArrayList<>();
				 frameList.add(frame);
				 re.put(frame.getSr_mac(), frameList);
			 }
		}
		return re;
		
	}
	
	public void judgeBySeqAndHTCapInfo(IEEE80211ManagementFrame frame) {
		int seq = frame.getSeq_num();
		String srcMAC = frame.getSr_mac();
		Map<Integer, byte[]> IEs = frame.getIEs();
		
		int stationSize = this.stationMap.size();
		if (stationSize == 0) {
			//是收到的第一个帧
			StationInfo station = new StationInfo();
			station.addFrame(frame);
			this.stationMap.put(1, station);
		} else {
			//注意：应该先把所有的mac地址都进行一次判断，要不然如果在前面MAC地址不一样，但匹配到了IE种类一样的，而序列号又不符合要求，则直接会添加一个新的StationInfo，而完全匹配的MAC地址却在后面。
			boolean match = matchMAC(frame);
			if (match) return;	
			else {
				
				if ( IEs.containsKey(HTCapabilitiesID)) {
					//再遍历已经收集到的终端，寻找IE中的HT Capability Info的值一样的终端
					for (int i = 1; i <= stationSize; i++) {
						if (match) break;
						StationInfo stationInfo = stationMap.get(i);
						if (matchHTInfo(stationInfo.getIEs(), IEs)) {
							if (matchSeqNum(stationInfo.getLastSeq(), seq)) {
								this.stationMap.get(i).addFrame(frame);
								match = true;
							}
						}
					}
					if (!match) {
						//ht cap info value不一样，MAC不一样，再次就认为是另一种设备
						StationInfo station = new StationInfo();
						station.addFrame(frame);
						this.stationMap.put(stationSize+1, station);
					}
					
				} else {
					//该帧中没有HT cap info元素
					System.out.println("该帧中没有HT cap info元素");
					if (!matchIEsTypes(frame)) {
						StationInfo station = new StationInfo();
						station.addFrame(frame);
						this.stationMap.put(stationSize+1, station);
					}
					
				}
				
			}
			
		}
		
	}
	
	public boolean matchIEsTypes(IEEE80211ManagementFrame frame) {
		int stationSize = this.stationMap.size();
		for (int i = 1; i <= stationSize; i++) {
			if (stationMap.get(i).getIEs().keySet().equals(frame.getIEs().keySet())) {
				if (matchSeqNum(stationMap.get(i).getLastSeq(), frame.getSeq_num())) {
					this.stationMap.get(i).addFrame(frame);
					return true;
				} else {
					StationInfo station = new StationInfo();
					station.addFrame(frame);
					this.stationMap.put(stationSize+1, station);
					return true;
				}
			}
		}
		return false;
	}
	
	/**
	 * 与信息元素中的HT capabilities info比较，
	 * @param frame
	 * @return
	 */
	public boolean matchHTInfo(Map<Integer, byte[]> mapIEs, Map<Integer, byte[]> frameIEs) {
		
		byte[] f = frameIEs.get(HTCapabilitiesID); 
		if (mapIEs.containsKey(HTCapabilitiesID)) {
			byte[] a = mapIEs.get(HTCapabilitiesID);
			
//			System.out.println(DataUtils.byte2HexStr(a, 0, a.length));
//			System.out.println(DataUtils.byte2HexStr(f, 0, a.length));
			
			if (a[0] == f[0] && a[1] == f[1] ) {
				//HT Cap info为HT Cap元素的值部分的前两个字节。
				return true;
			}
		}
	
		return false;
	}
	
	public boolean matchMAC(IEEE80211ManagementFrame frame) {
		int stationSize = this.stationMap.size();
		boolean match = false;
		for (int i = 1; i <= stationSize; i++) {
			if (frame.getSr_mac().equals(stationMap.get(i).getLastMAC())) {
				//首先，mac地址相同的，则一定是来自同一个设备的。
				this.stationMap.get(i).addFrame(frame);
				match = true;
				break;
			}
		}
		return match;
	}
	
	public void print() {
		int stationSize = this.stationMap.size();
		System.out.println("总共检测到的设备有"+stationSize);
		for (int i = 1; i <= stationSize; i++) {
			System.out.println(stationMap.get(i).toString());
			ArrayList<IEEE80211ManagementFrame> frames = stationMap.get(i).frameList;
			Set<String> macSet = new HashSet<>();
			for (IEEE80211ManagementFrame frame : frames) {
				macSet.add(frame.getSr_mac());
			}
			System.out.print("设备MAC地址集为：");
			for (String mac: macSet) System.out.print(mac+", ");
			System.out.println("");
			System.out.println();
		}
		
	}
	
	public static void main(String[] args) throws IOException {
		StationIdentify identify = new StationIdentify();
//		identify.process("/Users/longlong/Documents/周报/研一下学期/ifat实验/packets/"+"proreq-iphone7-others.pcap");
//		identify.process("/Users/longlong/Documents/周报/研一下学期/ifat实验/packets/"+"iphone7-1.pcap");
//		identify.process("/Users/longlong/master_work/学校内的研究工作/AppDetection&IFATexperience/test_data/"+"packet1.pcap");
//		identify.process("/Users/longlong/Documents/研究生工作/ifat实验/packets/"+"honor10-2.pcap");
//		identify.process("/Users/longlong/Documents/研究生工作/ifat实验/packets/"+"honor10_all.pcap");
		identify.process("/Users/longlong/Documents/研究生工作/ifat实验/packets/"+"honor2.pcap");
//		identify.process("/Users/longlong/Documents/研究生工作/ifat实验/packets/"+"honor10.pcap");

		identify.print();
		System.out.println("finish");
//		

		
	}
	
	/**
	 * 利用已有的数据为已知设备简历信息元素以及序列号签名
	 * 
	 * 没用！！！！
	 */
	public void generateDataBase() throws IOException {
		
		String path = "/Users/longlong/Documents/周报/研一下学期/ifat实验/packets/";
		String file = "mate72_1.pcap";
		
		this.parser = new IEEE80211Parser(new File(path+file));
		parser.openInfoElementsFlag();
		DeviceMap.MATE7_2.setInfoElem(parser.getInfoElem());
 		System.out.println(DeviceMap.MATE7_2);
		
		
		parser.setFile(new File(path+"mate71-all.pcap"));
		parser.printIE();
		
		parser.setFile(new File(path+"mate9-all.pcap"));
		parser.printIE();
		
		parser.setFile(new File(path+"mi6-1.pcap"));
		parser.printIE();
		
		parser.setFile(new File(path+"honor10-2.pcap"));
		parser.printIE();
		
		parser.setFile(new File(path+"iphon6s_1.pcap"));
		parser.printIE();
		
		parser.setFile(new File(path+"iphone7-1.pcap"));
		parser.printIE();
		
	}
	
	
}
