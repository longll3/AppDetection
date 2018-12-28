package process.identifyStation;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import signature.SignatureForIFAT;
import parser.IEEE80211Parser;
import process.identifyStation.stationInfoMap.StationInfoWithIFAT;
import structure.IEEE80211ManagementFrame;
import util.DTWDistance;

/**
 * 使用增加了IFAT的方式追踪只用随机MAC地址的终端
 * @author longlong
 *
 */
public class StationIdentifyWithIFAT {
	private IEEE80211Parser parser;
	
	private Map<Integer, StationInfoWithIFAT> stationMap;
	
	private final static int MaxSeqNum = 4095;
	private final static int SeqNumMaxDiff = 600;
	private final static int HTCapabilitiesID = 45;
	
	private int numForMac = 0; //通过mac地址判断的burst数
	private int numForSeq = 0; //通过Seq判断的burst数
	private int numForIFAT = 0; //通过IFAT判断的burst数
	private int burstNum = 0; // burst总数
	
	public StationIdentifyWithIFAT() {
		parser = new IEEE80211Parser();
		stationMap = new HashMap<>();
	}
	
	public void process(String fileName) throws IOException {
		this.parser.setFile(new File(fileName));
		this.parser.parse();
		
		//将frame根据mac地址分为一个一个的burst
		Set<ArrayList<IEEE80211ManagementFrame>> burstSet = getBurstSetByMac(this.parser.getTimeArray());
		for (ArrayList<IEEE80211ManagementFrame> burst : burstSet) {
			judgeForBurst(burst);
			burstNum++;
		}
		
	}
	
	/**
	 * judge that which station the burst belong to
	 * @param burst
	 */
	private void judgeForBurst(ArrayList<IEEE80211ManagementFrame> burst) {
		String mac = burst.get(0).getSr_mac();
		
		if (stationMap.size() == 0) {
			//终端map中还没有终端
			StationInfoWithIFAT stationInfo = new StationInfoWithIFAT(burst);
			stationMap.put(1, stationInfo);
			return;
		}
		
		Long[] burst_arr = paddingBurst(burst);
		
		//匹配mac地址
		int index = matchMAC(burst.get(0).getSr_mac());
		if (index > 0) {
			ArrayList<Long> tt = new ArrayList<>();
			for (Long ifat: burst_arr) tt.add(ifat);
			stationMap.get(index).getSig().updateSig(tt);
			stationMap.get(index).setLastSeq(burst.get(burst.size()-1).getSeq_num());
			stationMap.get(index).getMACSet().add(burst.get(0).getSr_mac());
			
			numForMac++;
			return;
		}
		
		//找到签名距离最小的。
		DTWDistance dtw = new DTWDistance();
		double minDistance = Double.MAX_VALUE;
		index = 0; //标记归类的是那个终端
		
		
		for (int i = 1; i <= stationMap.size(); i++) {
			//匹配seq
			if (matchSeqNum(stationMap.get(i).getLastSeq(), burst.get(0).getSeq_num())) {
				index = i;
				ArrayList<Long> tt = new ArrayList<>();
				for (Long ifat: burst_arr) tt.add(ifat);
				stationMap.get(index).getSig().updateSig(tt);
				stationMap.get(index).setLastSeq(burst.get(burst.size()-1).getSeq_num());
				stationMap.get(index).getMACSet().add(burst.get(0).getSr_mac());
				
				numForSeq++;
				return;
			}
			
			StationInfoWithIFAT stationInfoWithIFAT = stationMap.get(i);
			SignatureForIFAT signature = stationInfoWithIFAT.getSig();
			
			Double sig[] = signature.getSig().get(burst.size());
			if (sig == null) {
				//当该设备的签名中不含有 对应的 burst大小的签名，就跳过。
				continue;
			}
			if (burst_arr.length == 0) {
				//也就是只出现了1个probe reausst帧的情况
				/************************************
				//暂时先不管，跳过
				************************************/
				return;
			}
			double distance = dtw.getDTWDistance(sig, burst_arr);
			System.out.println("distance: " + distance);
			
			if (minDistance > distance) {
				minDistance = distance;
				index = i;
			}
		}
		
		System.out.println("最小距离为："+minDistance);
		
		if (minDistance > 40000) {
			//当最小距离都很大时，则认为时一个新的终端
			StationInfoWithIFAT stationInfo = new StationInfoWithIFAT(burst);
			int size = this.stationMap.size();
			this.stationMap.put(size+1, stationInfo);
		} else {
			ArrayList<Long> tt = new ArrayList<>();
			for (Long ifat: burst_arr) tt.add(ifat);
			stationMap.get(index).getSig().updateSig(tt);
			stationMap.get(index).setLastSeq(burst.get(burst.size()-1).getSeq_num());
			stationMap.get(index).getMACSet().add(burst.get(0).getSr_mac());
			
			numForIFAT++;

		}
		
	}

	/**
	 * group frame in different burst set according to MAC address
	 * @param list
	 * @return
	 */
	public Set<ArrayList<IEEE80211ManagementFrame>> getBurstSetByMac(ArrayList<IEEE80211ManagementFrame> list) {
		Set<ArrayList<IEEE80211ManagementFrame>> burstSet = new HashSet<ArrayList<IEEE80211ManagementFrame>>();
		IEEE80211ManagementFrame last = list.get(0);
		ArrayList<IEEE80211ManagementFrame> arr = new ArrayList<>();
		arr.add(last);
		
		for (int i = 1; i < list.size(); i++) {
			IEEE80211ManagementFrame now = list.get(i);
			if (last.getSr_mac().equals(now.getSr_mac())) {
				arr.add(now);
			} else {
				burstSet.add(arr);
				arr = new ArrayList<>();
				arr.add(now);				
			}
			last = now;
		}
		
		return burstSet;
	}
	
	/**
	 * complete each burst with average IFAT
	 * @param item a burst
	 * @return a array of IFAT
	 */
	public Long[] paddingBurst(ArrayList<IEEE80211ManagementFrame> item) {
		ArrayList<Long> new_time_diff_list = new ArrayList<>();
		IEEE80211ManagementFrame lastFrame = item.get(0);
		//将burst中的丢帧部分的IFAT补齐 到new_time_diff_list中
		for (int i = 1; i < item.size(); i++) {
			IEEE80211ManagementFrame nowFrame = item.get(i);
			long diff = nowFrame.getMacTimestamp()-lastFrame.getMacTimestamp();
			
			if (diff > 300000) System.err.println("padding时的IFAT超过300000，帧号为：:"+lastFrame.getSeq_num());
			
			if (nowFrame.getSeq_num() - lastFrame.getSeq_num() > 1) {
				int num = nowFrame.getSeq_num() - lastFrame.getSeq_num();
				for (int j = 0; j < num; j++) {
					new_time_diff_list.add(diff/num);
				}
			} else if (nowFrame.getSeq_num() - lastFrame.getSeq_num() == 1) {
				new_time_diff_list.add(diff);
			} else {
				//new burst
				System.out.println("wrong");
			}
			lastFrame = nowFrame;
		}
		
		return new_time_diff_list.toArray(new Long[0]);
	}
	
	private void print() {
		int stationSize = this.stationMap.size();
		System.out.println("总共检测到的设备有"+stationSize);
		for (int i = 1; i <= stationSize; i++) {
			System.out.println(stationMap.get(i).toString());
			ArrayList<IEEE80211ManagementFrame> frames = stationMap.get(i).getFrameList();
			Set<String> macSet = new HashSet<>();
			for (IEEE80211ManagementFrame frame : frames) {
				macSet.add(frame.getSr_mac());
			}
//			System.out.print("设备MAC地址集为：");
//			for (String mac: macSet) System.out.print(mac+", ");
			System.out.println("");
//			System.out.println();
		}
		
		System.out.println("通过mac地址判断的burst数目为：" + numForMac);
		System.out.println("通过seq判断的burst数目为：" + numForSeq);
		System.out.println("通过IFAT判断的burst数目为：" + numForIFAT);
		System.out.println("判断的burst总数目为：" + burstNum);
		
	}
	
	private boolean matchSeqNum(int lastSeq, int seq) {
		//首先seq一定是比上一帧要大,且在一定范围内
		//另一种情况就是seq的值达到最大需要从头开始计数时
		if ((seq > lastSeq && seq - lastSeq < SeqNumMaxDiff) || (seq + MaxSeqNum - lastSeq < SeqNumMaxDiff)) {
			return true;
		}
		
		return false;
	}
	
	public int matchMAC(String mac) {
		int stationSize = this.stationMap.size();
		for (int i = 1; i <= stationSize; i++) {
			for (String hasMac : stationMap.get(i).getMACSet()) {
				if (mac.equals(hasMac)) {
					return i;
				}
			}
		}
		return 0;
	}
	
	public static void main(String[] args) throws IOException {
		String path = "/Users/longlong/Documents/周报/研一下学期/ifat实验/packets/";
		String fileName = "honor10-2.pcap";
//		String fileName = "iphone7-1.pcap";
		StationIdentifyWithIFAT identify = new StationIdentifyWithIFAT();
		identify.process(path+fileName);
		
		identify.print();
		System.out.println("finish");
		
	}

	
}
