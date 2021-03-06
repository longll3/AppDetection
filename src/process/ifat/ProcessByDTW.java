package process.ifat;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.jfree.ui.RefineryUtilities;

import DrawFigure.BarChart;
import parser.IEEE80211Parser;
import signature.SignatureForIFAT;
import structure.IEEE80211ManagementFrame;
import util.DTWDistance;
import util.StatisticUtil;

public class ProcessByDTW {
	private static int BIN_SIZE = 10000; //以10000us(10ms)为单位create bin
	
	private Map<String, SignatureForIFAT> sigMap;
	
	private DTWDistance dtw;
	
	private IEEE80211Parser parser;
	private String path = "/Users/longlong/Documents/研究生工作/ifat实验/packets/";
	
	public ProcessByDTW() {
		this.parser = new IEEE80211Parser();
		this.dtw = new DTWDistance();
		this.sigMap = new HashMap<>();
	}
	
	/**
	 * 
	 * @param filename
	 * @param deviceName
	 * @param type
	 * @throws IOException
	 */
	public void getBurstFeature(String filename, String deviceName, int type) throws IOException {
		this.parser.setFile(new File(this.path+filename));
		this.parser.parse();
		
		Set<ArrayList<Long>> burstSet = new HashSet<>();
		
		if (type == 0) {
			//use getBinSetBySeqNum
			burstSet = getBurstSetBySeqNum(parser.getTimeArray());
		} else if (type == 1) {
			//use getBinSetByMAC
			burstSet = getBurstSetByMAC(this.parser.getTimeArray());
		}
		
		int sum = 0;
		int min = Integer.MAX_VALUE;
		int max = Integer.MIN_VALUE;
		int[] burstSizeArr = new int[burstSet.size()];
		int i = 0;
		for (ArrayList<Long> item : burstSet) {
			sum += item.size();
			if (item.size() < min) min = item.size();
			if (item.size() > max) max = item.size();
			burstSizeArr[i++] = item.size();
		}
		
		Arrays.sort(burstSizeArr);
		
		System.out.println("mean: " + (double)sum/burstSet.size());
		System.out.println("min: " + min);
		System.out.println("max: " + max);
		
//		BarChart barChart1 = new BarChart("IFAT attack", deviceName + " burst feature", burstSet);
		BarChart barChart1 = new BarChart("IFAT attack", deviceName + " burst feature", burstSizeArr);
		barChart1.pack( );
		RefineryUtilities.centerFrameOnScreen( barChart1 );  
		barChart1.setVisible( true );
		
	}

	/**
	 * 对mate7进行签名计算，以及计算人工分离的单个burst与签名的距离，并计算签名的中位数和均值，以及给出签名距离数组的柱形图
	 */
	public void processOnMate7() throws IOException {
//		String f1 = "mate72_1000-all.pcap";
		
		this.parser.setFile(new File(this.path+"mate71-all.pcap"));
		this.parser.parse();
		
		Set<ArrayList<Long>> burstSet = getBurstSetBySeqNum(this.parser.getTimeArray());
		
		this.sigMap.put("mate7", new SignatureForIFAT(burstSet));
		
	}
	
	public void processOnMate9() throws IOException {
		this.parser.setFile(new File(this.path+"mate9-all.pcap"));
//		this.parser.setFile(new File(this.path+"mate9-1-503.pcap"));
		this.parser.parse();
		
		Set<ArrayList<Long>> burstSet = getBurstSetBySeqNum(this.parser.getTimeArray());
		
		this.sigMap.put("mate9", new SignatureForIFAT(burstSet));
	}
	
	//要记录两个
	public void processOnHonor10() throws IOException {
		this.parser.setFile(new File(this.path+"honor10-2.pcap"));
//		this.parser.setFile(new File(this.path+"honor10-2.pcap"));
		this.parser.parse();
		
		Set<ArrayList<Long>> burstSet = getBurstSetByMAC(this.parser.getTimeArray());
		
		this.sigMap.put("honor10", new SignatureForIFAT(burstSet));
		
		
		
	}
	
	public void processOnHWPad() throws IOException {
		this.parser.setFile(new File(this.path+"pad-all.pcap"));
		this.parser.parse();
		
		Set<ArrayList<Long>> burstSet = getBurstSetBySeqNum(this.parser.getTimeArray());
		
		this.sigMap.put("pad", new SignatureForIFAT(burstSet));
	}


	public void processOnHuaWei() throws IOException {
		processOnHonor10();
		processOnHWPad();
		processOnMate7();
		processOnMate9();
	}


	public void processOnApple() throws IOException {
		processOniPhone("iphone7p/iphone7-1.pcap", "iphone7");
		processOniPhone("iphon6s_1.pcap", "iphone6s");
		processOnMac();
		processOniPad();

	}

	public void processOniPhone(String filename, String device) throws IOException {
		
//		String filename = "iphone7_nowifi_probe_request.pcap";
//		String filename = "iphone7_nowifi_probe_request.pcap";
//		String filename = "iphon6s_1.pcap";
		File file = new File(this.path+filename);
		this.parser.setFile(file);
		this.parser.parse();
		
		Set<ArrayList<Long>> burstSet = getBurstSetByMAC(this.parser.getTimeArray());
		
		this.sigMap.put(device, new SignatureForIFAT(burstSet));
		
	}
	
	public void processOniPad() throws IOException {
		this.parser.setFile(new File(this.path+"pad-all.pcap"));
		this.parser.parse();
		
		Set<ArrayList<Long>> burstSet = getBurstSetBySeqNum(this.parser.getTimeArray());
		
		this.sigMap.put("ipad", new SignatureForIFAT(burstSet));
	}
	
	public void processOnMac() throws IOException {
		this.parser.setFile(new File(this.path+"lll-mac-pure.pcap"));
		this.parser.parse();
		
		Set<ArrayList<Long>> burstSet = getBurstSetBySeqNum(this.parser.getTimeArray());
		
		this.sigMap.put("mac", new SignatureForIFAT(burstSet));
	}
	
	public void calDisFromOtherOfMate9() throws IOException {
		
	}
	
	public void calDisFromOtherOfMate7() throws IOException {
		String f1 = "mate71-203-1000.pcap";
//		String f1 = "mate9-504-999.pcap";
//		String f1 = "pad_no_in_list.pcap";
//		String f1 = "honor10-1.pcap";
		
		this.parser.setFile(new File(this.path+f1));
		this.parser.parse();
		
		Set<ArrayList<Long>> burstSet = getBurstSetBySeqNum(this.parser.getTimeArray());
		Map<String, ArrayList<Double>> distance_list = new HashMap<>();
		
		int i=0;
		Set<String> keys = this.sigMap.keySet();
		Map<String, Integer> predicRate = new HashMap<>();

		double allMinDistance = Double.MAX_VALUE;
		double allMaxDistance = Double.MIN_VALUE;

		for (ArrayList<Long> burst: burstSet) {
			Long[] burst_arr = burst.toArray(new Long[0]);
			System.out.println("No"+i+". burst");
			double minDistance = Double.MAX_VALUE;
			String predictionDevice = "";
			
			for (String key: keys) {
				
				SignatureForIFAT sig = sigMap.get(key);
//				for (int j = 0; j < sig.getBurstSizeDistribution().size(); j++) {
					if (sig.getBurstSizeDistribution().containsKey(burst.size()) ) {
						double distance = dtw.getDTWDistance(sig.getSig().get(burst.size()), burst_arr);
						double realDistance = distance*(1-sig.getBurstSizeDistribution().get(burst.size()));
//						double haffmandistance = dtw.haffumanDistance(sig.getSig().get(burst.size()), burst_arr);
						
						if (minDistance > realDistance) {
							if (allMinDistance > realDistance) {
								allMinDistance = realDistance;
							}
							minDistance = realDistance;
							predictionDevice = key;
						}
						
//						System.out.println("signature device:" + key+",burst size is:"+burst.size()+" distance is :"+distance);
						System.out.println("signature device:" + key+",burst size is:"+burst.size()+" real distance is :"+realDistance);
//						System.out.println("signature device:" + key+",burst size is:"+burst.size()+" haffman distance is :"+ haffmandistance);

						if (distance_list.containsKey(key)) {
							distance_list.get(key).add(realDistance);
						} else {
							ArrayList<Double> distanceArr = new ArrayList<>();
							distanceArr.add(realDistance);
							distance_list.put(key, distanceArr);
						}
					}
//				}
			}
			
			System.out.println("belong to device " + predictionDevice);

			if (minDistance > allMaxDistance) {
				allMaxDistance = minDistance;
			}

			if (predicRate.containsKey(predictionDevice)) {
				int temp = predicRate.get(predictionDevice);
				predicRate.put(predictionDevice, temp+1);
			} else {
				predicRate.put(predictionDevice, 1);
			}
			
			i++;
		}
		
		for (String device: predicRate.keySet()) {
			System.out.println("预测所属品牌为"+device+", 所占百分比为："+ (double)predicRate.get(device)/burstSet.size());
		}

		System.out.println("最小距离为："+allMinDistance);
		System.out.println("最大距离为："+allMaxDistance);

		
		
//		printMeanAndMedium(distance_list.get("mate7").toArray(new Double[0]), "mate7 tp mate7");
//		drawDisListBarChart(distance_list.get("mate7").toArray(new Double[0]), "mate7 to mate7");
//		
//		printMeanAndMedium(distance_list.get("mate9").toArray(new Double[0]), "mate7 tp mate9");
//		drawDisListBarChart(distance_list.get("mate9").toArray(new Double[0]), "mate7 to mate9");
//		
//		printMeanAndMedium(distance_list.get("pad").toArray(new Double[0]), "mate7 tp pad");
//		drawDisListBarChart(distance_list.get("pad").toArray(new Double[0]), "mate7 to pad");
//	
//		printMeanAndMedium(distance_list.get("honor10").toArray(new Double[0]), "mate7 tp honor10");
//		drawDisListBarChart(distance_list.get("honor10").toArray(new Double[0]), "mate7 to honor10");
	
	}
	
	public void calDisFromOtherOfIphone7() throws IOException {
//		String f1 = "pad-all.pcap";
		String f1 = "iphone7p/iphone7p-test-101frames.pcap";
//		String f1 = "iphon6s_nowifi_IFAT.pcap";

		this.parser.setFile(new File(this.path+f1));
		this.parser.parse();
		
		Set<ArrayList<Long>> burstSet = getBurstSetBySeqNum(this.parser.getTimeArray());
		Map<String, ArrayList<Double>> distance_list = new HashMap<>();
		
		int i=0;
		Set<String> keys = this.sigMap.keySet();
		Map<String, Integer> predicRate = new HashMap<>();
		
		for (ArrayList<Long> burst: burstSet) {
			if (burst.size() == 0) continue;
			Long[] burst_arr = burst.toArray(new Long[0]);
			System.out.println("No"+i+". burst");
			double minDistance = Double.MAX_VALUE;
			String predictionDevice = "";
			
			for (String key: keys) {
				
				SignatureForIFAT sig = sigMap.get(key);
//				for (int j = 0; j < sig.getBurstSizeDistribution().size(); j++) {
					if (sig.getBurstSizeDistribution().containsKey(burst.size()) ) {
						double distance = dtw.getDTWDistance(sig.getSig().get(burst.size()), burst_arr);
//						double haffmandistance = dtw.haffumanDistance(sig.getSig().get(burst.size()), burst_arr);
						double realDistance = distance*(1-sig.getBurstSizeDistribution().get(burst.size()));
						
						if (minDistance > realDistance) {
							minDistance = realDistance;
							predictionDevice = key;
						}
						
//						System.out.println("signature device:" + key+",burst size is:"+burst.size()+" distance is :"+distance);
						System.out.println("signature device:" + key+",burst size is:"+burst.size()+" real distance is :"+realDistance);
//						System.out.println("signature device:" + key+",burst size is:"+burst.size()+" haffman distance is :"+ haffmandistance);

						if (distance_list.containsKey(key)) {
							distance_list.get(key).add(realDistance);
						} else {
							ArrayList<Double> distanceArr = new ArrayList<>();
							distanceArr.add(realDistance);
							distance_list.put(key, distanceArr);
						}
					}
//				}
			}
			
//			System.out.println("belong to device " + predictionDevice);
			if (predicRate.containsKey(predictionDevice)) {
				int temp = predicRate.get(predictionDevice);
				predicRate.put(predictionDevice, temp+1);
			} else {
				predicRate.put(predictionDevice, 1);
			}
			
			i++;
		}
		
		for (String device: predicRate.keySet()) {
			System.out.println("预测所属品牌为"+device+", 所占百分比为："+ (double)predicRate.get(device)/burstSet.size());
		}
	}
	
	/**
	 * complete each burst with average IFAT
	 * @param item a burst
	 * @return a array of IFAT
	 */
	public ArrayList<Long> paddingBurst(ArrayList<IEEE80211ManagementFrame> item) {
		ArrayList<Long> new_time_diff_list = new ArrayList<>();
		IEEE80211ManagementFrame lastFrame = item.get(0);
		//将burst中的丢帧部分的IFAT补齐 到new_time_diff_list中
		for (int i = 1; i < item.size(); i++) {
			IEEE80211ManagementFrame nowFrame = item.get(i);
			long diff = nowFrame.getMacTimestamp()-lastFrame.getMacTimestamp();
			
			if (diff > 300000) System.out.println(lastFrame.getSeq_num());
			
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
		
		return new_time_diff_list;
	}
	
	public Long[] getDTWSignature(Set<ArrayList<Long>> burstSet) {
		Long[] sig;
		
		//选择burst中size的均值作为该设备的签名，再对同一个size大小的ifat取对应均值
		int sum = 0;
		for (ArrayList<Long> burst: burstSet) {
			sum += burst.size();
		}
		
		int mean = sum / burstSet.size();
		sig = new Long[mean];
		for (int j = 0; j < sig.length; j++) {
			sig[j] = 0l;
		}
		int count = 0;
		for (ArrayList<Long> burst: burstSet) {
			if (burst.size() == mean) {
				count++;
				for (int i = 0; i < mean; i++) {
					System.out.print(burst.get(i)+ " ");
					sig[i] += burst.get(i);
				}
			}
			System.out.println();
		}
		
		for (int i = 0; i < sig.length; i++) {
			sig[i] /= count;
		}
		
		return sig;
	}
	
	public void drawDisListBarChart(Double[] distance_list, String title) {
		BarChart barChart1 = new BarChart("IFAT attack", title, distance_list, "", "distance", false);
		barChart1.pack( );
		RefineryUtilities.centerFrameOnScreen( barChart1 );  
		barChart1.setVisible( true );
	}
	
	public void printMeanAndMedium(Double[] distance_list, String start) {
		//计算距离的均值、中位数		
			
		System.out.println(start+ " mean:"+StatisticUtil.getMean(distance_list));
		System.out.println(start+ " medium value:"+StatisticUtil.getMediumValue(distance_list));
	}
	
	/**
	 * get the burst set according to the sequence number of each frames , only the difference between two sequence number is less than 10, the two corresponding frames are belong to a same burst
	 * then padding each burst 
	 * @param list the all frames list
	 * @return burst set
	 */
	public Set<ArrayList<Long>> getBurstSetBySeqNum(ArrayList<IEEE80211ManagementFrame> list) {
		Set<ArrayList<Long>> set = new HashSet<>();
		
		//mate9&pad的特点是每一个burst间seq num的差值一般在36～41，即只要seq num相差大于30就可以认为是一个新的burst了
		IEEE80211ManagementFrame last = list.get(0);
		ArrayList<IEEE80211ManagementFrame> node = new ArrayList<>();
		node.add(last);
		for (int i = 1; i < list.size(); i++) {
			IEEE80211ManagementFrame now = list.get(i);
			if (now.getSeq_num() - last.getSeq_num() < 15 && now.getSeq_num() - last.getSeq_num() >= 0) {
				//belongs to a same burst
				node.add(now);
			} else {
				//padding burst
				set.add(paddingBurst(node));
				node = new ArrayList<>();
				node.add(now);
			}
			last = now;
		}
		
		return set;
	}
	
	/**
	 * get the burst set according to the source MAC address of each frame, the frames which have the same source MAC address belong to a same burst 
	 * then padding the burst
	 * @param list the all frames list
	 * @return the burst set
	 */
	public Set<ArrayList<Long>> getBurstSetByMAC(ArrayList<IEEE80211ManagementFrame> list) {
		Set<ArrayList<Long>> burstSet = new HashSet<ArrayList<Long>>();
		IEEE80211ManagementFrame last = list.get(0);
		ArrayList<IEEE80211ManagementFrame> arr = new ArrayList<>();
		arr.add(last);
		
		for (int i = 1; i < list.size(); i++) {
			IEEE80211ManagementFrame now = list.get(i);
			if (last.getSr_mac().equals(now.getSr_mac())) {
				arr.add(now);
			} else {
				burstSet.add(paddingBurst(arr));
				arr = new ArrayList<>();
				arr.add(now);				
			}
			last = now;
		}
		
		return burstSet;
	}
	
}
