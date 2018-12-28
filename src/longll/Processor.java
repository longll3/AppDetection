package longll;

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
import structure.IEEE80211ManagementFrame;
import util.DataUtils;
import util.StatisticUtil;
/**
 * 计算IFAT实验用的这个类
 * @author longlong
 *
 */
public class Processor {
	private static int BIN_SIZE = 10000; //以10000us(10ms)为单位create bin
	private Signature honor10;
	private Signature mate7;
	private Signature mate9;
	private Signature pad;
	
	private Signature iphone7;
	private Signature iphone6s;
	private Signature mac;
	private Signature ipad;
	
	private IEEE80211Parser parser;
	
	private String path = "/Users/longlong/Documents/周报/研一下学期/ifat实验/packets/";
//	private String path = "/Users/longlong/Documents/周报/研一下学期/周报8_龙俐伶/";
	
	public Processor() {
		this.honor10 = new Signature();
		this.mate7 = new Signature();
		this.mate9 = new Signature();
		this.pad = new Signature();
		parser = new IEEE80211Parser();
	}
	
	public void getBurstFeature(String filename, String deviceName, int type) throws IOException {
		this.parser.setFile(new File(this.path+filename));
		this.parser.parse();
		
		Set<ArrayList<Long>> burstSet = new HashSet<>();
		ArrayList<Long> timeDiffSeq = new ArrayList<>();
		Map<Long, ArrayList<Long>> binSet;
		
		if (type == 0) {
			//use getBinSetBySeqNum
			 binSet = getBinSetBySeqNum(parser.getTimeArray(), timeDiffSeq, burstSet);
		} else if (type == 1) {
			//use getBinSetByMAC
			binSet = getBinSetByMAC(this.parser.getTimeArray(), timeDiffSeq, burstSet);
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
	
	public void start(String[] args) throws IOException {
		processOnHonor10WithOneSig();
		processOnMate9();
		processOnHuaweiPad();
		processOnMate7();
		
//		processOnHonor10();
		calDisHonor10(honor10);
//		calDisMate9(mate9);
//		calDisMate7(mate7);
//		calDisHuaweiPad(pad);
		
	}
	
	/**
	 * 对mate7进行签名计算，以及计算人工分离的单个burst与签名的距离，并计算签名的中位数和均值，以及给出签名距离数组的柱形图
	 */
	public void processOnMate7() throws IOException {
		String path = "/Users/longlong/Documents/周报/研一下学期/周报10_龙俐伶/packets/";
		String f1 = "mate72_1000-all.pcap";
		
		File f = new File(path+f1);
		IEEE80211Parser parser = new IEEE80211Parser(f);
		parser.parse();
		
		Set<ArrayList<IEEE80211ManagementFrame>> set = new HashSet<>();
		
		//mate7的特点是seq number只到26，且下一个burst的第一个编号一定比上一个burst的最后一个小
		ArrayList<IEEE80211ManagementFrame> list = parser.getTimeArray();
		IEEE80211ManagementFrame last = list.get(0);
		ArrayList<IEEE80211ManagementFrame> node = new ArrayList<>();
		node.add(last);
		for (int i = 1; i < list.size(); i++) {
			IEEE80211ManagementFrame now = list.get(i);
			if (now.getSeq_num() > last.getSeq_num()) {
				//belongs to a same burst
				node.add(now);
			} else {
				set.add(node);
				node = new ArrayList<>();
				node.add(now);
			}
			last = now;
		}
		
		int count_frame = 0;
		int count_burst = 0;
		
		int validFrameNum = 0; //记录在bin_set中总共的帧数
		
		Map<Long, ArrayList<Long>> bin_set = new HashMap<>();
		
		for (ArrayList<IEEE80211ManagementFrame> item : set) {
			count_burst++;
			count_frame += item.size();
			
			IEEE80211ManagementFrame lastFrame = item.get(0);
			
			ArrayList<Long> new_time_diff_list = new ArrayList<>();
			
			//将burst中的丢帧部分的IFAT补齐 到new_time_diff_list中
			for (int i = 1; i < item.size(); i++) {
				IEEE80211ManagementFrame nowFrame = item.get(i);
				long diff = nowFrame.getMacTimestamp()-lastFrame.getMacTimestamp();
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
			
			//group in bin set
			for (int i = 0; i < new_time_diff_list.size(); i++) {
				long nowIFAT = new_time_diff_list.get(i) / BIN_SIZE;
				if (bin_set.containsKey(nowIFAT)) {
					bin_set.get(nowIFAT).add(new_time_diff_list.get(i));
				} else {
					ArrayList<Long> bin_item = new ArrayList<>();
					bin_item.add(new_time_diff_list.get(i));
					bin_set.put(nowIFAT, bin_item);
				}
				validFrameNum++;
			}
			
			
		}
		
		//生成签名
		Signature signature = new Signature();
		Set<Long> keys = bin_set.keySet();
        Long[] key_array = keys.toArray(new Long[0]);
        
        for (int i = 0; i < key_array.length; i++) {
        		int sum = 0;
        		int count = 0;
        		for (int j = 0; j < bin_set.get(key_array[i]).size(); j++) {
        			sum += bin_set.get(key_array[i]).get(j);
        			count++;
        		}
        		
        		signature.getMean().put(key_array[i], (double)sum/count);
        		signature.getPercentege().put(key_array[i], (double)count/validFrameNum);
        }
        
        mate7 = signature;
        
//		System.out.println("burst count number is :" + count_burst+", mean is: "+count_frame/count_burst);
		
        /*
		//将签名用柱状图表示
		BarChart barChart1 = new BarChart("IFAT attack", "mate71 signature", signature);
		barChart1.pack( );
		RefineryUtilities.centerFrameOnScreen( barChart1 );  
		barChart1.setVisible( true );
		*/
//		
		
		
	}
	
	public void calDisMate7(Signature signature) throws IOException {
		//对每个人工分出来的mate7 的single burst构建签名并与上面已知的签名进行比较
        ArrayList<Double> distance_list = new ArrayList<>();
        //计算与其他签名间的距离
  		ArrayList<Double> distance_list_to_honor10 = new ArrayList<>();
  		ArrayList<Double> distance_list_to_mate9 = new ArrayList<>();
  		ArrayList<Double> distance_list_to_pad = new ArrayList<>();
        
		for (int file_seq = 1; file_seq <= 33; file_seq++) {
			String burst_path = "/Users/longlong/Documents/周报/研一下学期/周报10_龙俐伶/packets/burst set/";
			String burst_file = "mate7-1_"+file_seq+".pcap";
			File burst_f = new File(burst_path + burst_file);
			IEEE80211Parser parser = new IEEE80211Parser(burst_f);
			parser.parse();
			
			ArrayList<IEEE80211ManagementFrame> burst_list = parser.getTimeArray();
			ArrayList<Long> new_time_diff_list = new ArrayList<>();
			Map<Long, ArrayList<Long>> burst_bin_set = new HashMap<>();
			
			int burst_validFrameCount = 0;
			
			//将burst中的丢帧部分的IFAT补齐 到new_time_diff_list中
			IEEE80211ManagementFrame lastFrame = burst_list.get(0);
			for (int j = 1; j < burst_list.size(); j++) {
				IEEE80211ManagementFrame nowFrame = burst_list.get(j);
				long diff = nowFrame.getMacTimestamp()-lastFrame.getMacTimestamp();
				if (nowFrame.getSeq_num() - lastFrame.getSeq_num() > 1) {
					int num = nowFrame.getSeq_num() - lastFrame.getSeq_num();
					for (int k = 0; k < num; k++) {
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
			
			//group in bin set
			for (int i = 0; i < new_time_diff_list.size(); i++) {
				long nowIFAT = new_time_diff_list.get(i) / BIN_SIZE;
				if (burst_bin_set.containsKey(nowIFAT)) {
					burst_bin_set.get(nowIFAT).add(new_time_diff_list.get(i));
				} else {
					ArrayList<Long> bin_item = new ArrayList<>();
					bin_item.add(new_time_diff_list.get(i));
					burst_bin_set.put(nowIFAT, bin_item);
				}
				burst_validFrameCount++;
			}
			
			//generate signature for the single burst
			Signature burst_sig = new Signature();
			
			Set<Long> burst_keys = burst_bin_set.keySet();
	        
	        for (long key: burst_keys) {
	        		int sum = 0;
	        		for (int j = 0; j < burst_bin_set.get(key).size(); j++) {
	        			sum += burst_bin_set.get(key).get(j);
	        		}
	        		
	        		burst_sig.getMean().put(key, (double)sum/ burst_bin_set.get(key).size());
	        		burst_sig.getPercentege().put(key, (double) burst_bin_set.get(key).size()/burst_validFrameCount);
	        }
	        
	        distance_list.add(getDistanceFrom(burst_sig, signature));
	        System.out.println(getDistanceFrom(burst_sig, signature));
	        
	        distance_list_to_honor10.add(getDistanceFrom(burst_sig, honor10));
			distance_list_to_mate9.add(getDistanceFrom(burst_sig, mate9));
			distance_list_to_pad.add(getDistanceFrom(burst_sig, pad));
			
		}
		
		printMeanAndMedium(distance_list, "to mate7(self)");
		printMeanAndMedium(distance_list_to_pad, "to pad");
		printMeanAndMedium(distance_list_to_mate9, "to mate9");
		printMeanAndMedium(distance_list_to_honor10, "to honor10");
		
		
	}
	
	

	public void BurstTest() throws IOException {
		String path = "/Users/longlong/Documents/周报/研一下学期/周报10_龙俐伶/packets/burst set/";
		String head = "mate7-1_";
		String end = ".pcap";
		IEEE80211Parser parser = new IEEE80211Parser();
		for (int i = 1; i <= 20; i++) {
			File file = new File(path+head+i+end);
			
			parser.setFile(file);
			parser.parse();
			
			IFATBurst ifatBurst = new IFATBurst(parser.getTimeArray());
			ifatBurst.paddingBurst();
			System.out.println(ifatBurst.getIFATList());
		}
		
		
		
	}
	

	/**
	 * 对荣耀10进行burst大小的统计、求均值
	 * @throws IOException
	 */
/**	
//	public void getHonor10Feature() throws IOException {
//		String path = "/Users/longlong/Documents/周报/研一下学期/周报10_龙俐伶/packets/";
//		String f1 = "honor10-2.pcap";
//		
//		int first = 0;
//		int second = 0;
//		int count_f = 0;
//		int count_s = 0;
//		
//		SignatureForIFAT sig1 = new SignatureForIFAT(); // size > 8
//		SignatureForIFAT sig2 = new SignatureForIFAT(); // size < 8
//		
//		File f = new File(path+f1);
//		IEEE80211Parser parser = new IEEE80211Parser(f);
//		parser.parse();
//		
//		IFATG_identify process.process.ifat.ifat = new IFATG_identify(parser.getTimeArray());
//		Set<ArrayList<IEEE80211ManagementFrame>> set = process.process.ifat.ifat.groupInBurstSet();
//		
//		
//		for (ArrayList<IEEE80211ManagementFrame> item: set) {
//			if (item.size() > 8) {
//				count_s += item.size();
//				second++;
//				
//				
//			} else if (item.size() >= 6) {
//				count_f += item.size();
//				first++;
//			} else {
//				continue;
//			}
//		}
//		
//		
//		parser.setFile(new File(path+"honor10-1.pcap"));
//		parser.parse();
//		process.process.ifat.ifat.initial(parser.getTimeArray());
//		set = process.process.ifat.ifat.groupInBurstSet();
//		for (ArrayList<IEEE80211ManagementFrame> item: set) {
//			if (item.size() > 8) {
//				count_s += item.size();
//				second++;
//			} else if (item.size() >= 6) {
//				count_f += item.size();
//				first++;
//			} else {
//				continue;
//			}
//		}
//		
//		System.out.println("first pattern: size: "+first+", mean:"+count_f/first);
//		System.out.println("second pattern: size: "+second+", mean:"+count_s/second);
//		
//		
//		BarChart barChart1 = new BarChart("IFAT attack", "burst size", set, "", "burst size");
//		barChart1.pack( );
//		RefineryUtilities.centerFrameOnScreen( barChart1 );  
//		barChart1.setVisible( true );
//		
//		
//	}
//*/
	
	
	/**
	 * 对honor10进行签名计算，以及计算人工分离的单个burst与签名的距离，并计算签名的中位数和均值，以及给出签名距离数组的柱形图
	 * 分为2个签名，一个对应burst大小为21～24的，一个对应大小为6～8的
	 * @throws IOException 
	 * mean:460.6373967256229
	 * medium value284.8337916600535
	 * mean:619.508929931925
	 * medium value487.09083450210403
	 * mean:390.0278264117108
	 * medium value280.2847867527471
	 */
	public void processOnHonor10() throws IOException {
		String path = "/Users/longlong/Documents/周报/研一下学期/周报10_龙俐伶/packets/";
		String f1 = "honor10-2.pcap";
		
		Signature sig1 = new Signature(); // size > 8
		Signature sig2 = new Signature(); // size < 8
		HashMap<Long, ArrayList<Long>> bin_set_1 = new HashMap<>();
		HashMap<Long, ArrayList<Long>> bin_set_2 = new HashMap<>();
		int validFrameNum1 = 0; //记录在bin_set_1中总共的帧数
		int validFrameNum2 = 0; //记录在bin_set_2中总共的帧数
		
		File f = new File(path+f1);
		IEEE80211Parser parser = new IEEE80211Parser(f);
		parser.parse();
		
		IFATG_identify ifat = new IFATG_identify(parser.getTimeArray());
		Set<ArrayList<IEEE80211ManagementFrame>> burst_set = ifat.groupInBurstSet();
		
		//for each burst
		for (ArrayList<IEEE80211ManagementFrame> item : burst_set) {
			if (item.size() < 6) continue;
			
			IEEE80211ManagementFrame lastFrame = item.get(0);
			
			ArrayList<Long> new_time_diff_list = new ArrayList<>();
			
			//将burst中的丢帧部分的IFAT补齐 到new_time_diff_list中
			for (int i = 1; i < item.size(); i++) {
				IEEE80211ManagementFrame nowFrame = item.get(i);
				long diff = nowFrame.getMacTimestamp()-lastFrame.getMacTimestamp();
				if (nowFrame.getSeq_num() - lastFrame.getSeq_num() > 1) {
					int num = nowFrame.getSeq_num() - lastFrame.getSeq_num();
					for (int j = 0; j < num; j++) {
						new_time_diff_list.add(diff/num);
					}
				} else if (nowFrame.getSeq_num() - lastFrame.getSeq_num() == 1 || (lastFrame.getSeq_num() == 4095 && nowFrame.getSeq_num() == 0)) {
					new_time_diff_list.add(diff);
				} else {
					//new burst
					System.out.println("wrong");
				}
				lastFrame = nowFrame;
			}
			
			//group in bin set
			for (long diff: new_time_diff_list) {
				System.out.println("honor:"+diff);
				
				long nowIFAT = diff/BIN_SIZE;
				if (item.size() > 8) {
					//sig1
					if (bin_set_1.containsKey(nowIFAT)) {
						bin_set_1.get(nowIFAT).add(diff);
					} else {
						ArrayList<Long> bin_item = new ArrayList<>();
						bin_item.add(diff);
						bin_set_1.put(nowIFAT, bin_item);
					}
					validFrameNum1++;
				} else {
					//sig2
					if (bin_set_2.containsKey(nowIFAT)) {
						bin_set_2.get(nowIFAT).add(diff);
					} else {
						ArrayList<Long> bin_item = new ArrayList<>();
						bin_item.add(diff);
						bin_set_2.put(nowIFAT, bin_item);
					}
					validFrameNum2++;
				}
			}
		}
		
		//生成2个签名
		sig1 = generateSig(bin_set_1, validFrameNum1);
		sig2 = generateSig(bin_set_2, validFrameNum2);
		
		//对另一个文件中的burst进行距离计算
		parser.setFile(new File(path+"honor10-1.pcap"));
		parser.parse();
		
		IFATG_identify ifat_burst = new IFATG_identify(parser.getTimeArray());
		Set<ArrayList<IEEE80211ManagementFrame>> test_burst_set = ifat_burst.groupInBurstSet();
		
		ArrayList<Double> distance_list = new ArrayList<>();
		ArrayList<Double> distance_list_1 = new ArrayList<>();
		ArrayList<Double> distance_list_2 = new ArrayList<>();
		for (ArrayList<IEEE80211ManagementFrame> item: test_burst_set) {
			if (item.size() < 6) continue;
			
			Signature sig_burst = new Signature(); 
			HashMap<Long, ArrayList<Long>> burst_bin_set = new HashMap<>();
			int validFrameNum = 0;
			
			IEEE80211ManagementFrame lastFrame = item.get(0);
			
			ArrayList<Long> new_time_diff_list = new ArrayList<>();
			
			//将burst中的丢帧部分的IFAT补齐 到new_time_diff_list中
			for (int i = 1; i < item.size(); i++) {
				IEEE80211ManagementFrame nowFrame = item.get(i);
				long diff = nowFrame.getMacTimestamp()-lastFrame.getMacTimestamp();
				if (nowFrame.getSeq_num() - lastFrame.getSeq_num() > 1) {
					int num = nowFrame.getSeq_num() - lastFrame.getSeq_num();
					for (int j = 0; j < num; j++) {
						new_time_diff_list.add(diff/num);
					}
				} else if (nowFrame.getSeq_num() - lastFrame.getSeq_num() == 1 || (lastFrame.getSeq_num() == 4095 && nowFrame.getSeq_num() == 0)) {
					new_time_diff_list.add(diff);
				} else {
					//new burst
					System.out.println("wrong");
				}
				lastFrame = nowFrame;
			}
			
			//group in bin set
			for (long diff: new_time_diff_list) {
				long nowIFAT = diff/BIN_SIZE;
				if (burst_bin_set.containsKey(nowIFAT)) {
					burst_bin_set.get(nowIFAT).add(diff);
				} else {
					ArrayList<Long> bin_item = new ArrayList<>();
					bin_item.add(diff);
					burst_bin_set.put(nowIFAT, bin_item);
				}
				validFrameNum++;
			}
			sig_burst = generateSig(burst_bin_set, validFrameNum);
			double distance = 0;
			if (item.size() > 8) {
				distance = getDistanceFrom(sig_burst, sig1);
				distance_list_1.add(distance);
			} else {
				distance = getDistanceFrom(sig_burst, sig2);
				distance_list_2.add(distance);
			}
			distance_list.add(distance);
			System.out.println(distance);
			
		
		}
		
		//计算距离的均值、中位数
		Double[] distance_arr = new Double[distance_list.size()];
		distance_list.toArray(distance_arr);
				
		System.out.println("mean:"+StatisticUtil.getMean(distance_arr));
		System.out.println("medium value"+StatisticUtil.getMediumValue(distance_arr));
				
		BarChart barChart1 = new BarChart("IFAT attack", "hornor10 distance", distance_list.toArray(new Double[0]), "", "distance", false);
		barChart1.pack( );
		RefineryUtilities.centerFrameOnScreen( barChart1 );  
		barChart1.setVisible( true );
		
		//计算距离的均值、中位数
		Double[] distance_arr_1 = new Double[distance_list_1.size()];
		distance_list_1.toArray(distance_arr_1);
		
		System.out.println("mean:"+StatisticUtil.getMean(distance_arr_1));
		System.out.println("medium value"+StatisticUtil.getMediumValue(distance_arr_1));
		
		BarChart barChart2 = new BarChart("IFAT attack", "honor10 distance 1", distance_list_1.toArray(new Double[0]), "", "distance", true);
		barChart2.pack( );
		RefineryUtilities.centerFrameOnScreen( barChart2 );  
		barChart2.setVisible( true );
		
		//计算距离的均值、中位数
		Double[] distance_arr_2 = new Double[distance_list_2.size()];
		distance_list_2.toArray(distance_arr_2);
		System.out.println("mean:"+StatisticUtil.getMean(distance_arr_2));
		System.out.println("medium value"+StatisticUtil.getMediumValue(distance_arr_2));
		
		BarChart barChart3 = new BarChart("IFAT attack", "honor10 distance 2", distance_list_2.toArray(new Double[0]), "", "distance", true);
		barChart3.pack( );
		RefineryUtilities.centerFrameOnScreen( barChart3 );  
		barChart3.setVisible( true );
		
	}
	
	/**
	 * 对honor10进行签名计算，以及计算人工分离的单个burst与签名的距离，并计算签名的中位数和均值，以及给出签名距离数组的柱形图
	 * 只记录一个签名。不区分为2个
	 * @throws IOException 
	 * mean:1986.2754023240932
	 * medium value:2236.991318514751
	 */
	public void processOnHonor10WithOneSig() throws IOException {
		String path = "/Users/longlong/Documents/周报/研一下学期/周报10_龙俐伶/packets/";
		String f1 = "honor10-2.pcap";
		
		Signature sig1 = new Signature(); 
		HashMap<Long, ArrayList<Long>> bin_set_1 = new HashMap<>();
		int validFrameNum1 = 0; //记录在bin_set_1中总共的帧数
		
		File f = new File(path+f1);
		IEEE80211Parser parser = new IEEE80211Parser(f);
		parser.parse();
		
		IFATG_identify ifat = new IFATG_identify(parser.getTimeArray());
		Set<ArrayList<IEEE80211ManagementFrame>> burst_set = ifat.groupInBurstSet();
		
		//for each burst
		for (ArrayList<IEEE80211ManagementFrame> item : burst_set) {
			if (item.size() < 6) continue;
			
			IEEE80211ManagementFrame lastFrame = item.get(0);
			
			ArrayList<Long> new_time_diff_list = new ArrayList<>();
			
			//将burst中的丢帧部分的IFAT补齐 到new_time_diff_list中
			for (int i = 1; i < item.size(); i++) {
				IEEE80211ManagementFrame nowFrame = item.get(i);
				long diff = nowFrame.getMacTimestamp()-lastFrame.getMacTimestamp();
				if (nowFrame.getSeq_num() - lastFrame.getSeq_num() > 1) {
					int num = nowFrame.getSeq_num() - lastFrame.getSeq_num();
					for (int j = 0; j < num; j++) {
						new_time_diff_list.add(diff/num);
					}
				} else if (nowFrame.getSeq_num() - lastFrame.getSeq_num() == 1 || (lastFrame.getSeq_num() == 4095 && nowFrame.getSeq_num() == 0)) {
					new_time_diff_list.add(diff);
				} else {
					//new burst
					System.out.println("wrong");
				}
				lastFrame = nowFrame;
			}
			
			//group in bin set
			for (long diff: new_time_diff_list) {
				
				System.out.println("honor:"+diff);
				
				long nowIFAT = diff/BIN_SIZE;
					//sig1
				if (bin_set_1.containsKey(nowIFAT)) {
					bin_set_1.get(nowIFAT).add(diff);
				} else {
					ArrayList<Long> bin_item = new ArrayList<>();
					bin_item.add(diff);
					bin_set_1.put(nowIFAT, bin_item);
				}
				validFrameNum1++;
			}
		}
		
		//生成2个签名
		sig1 = generateSig(bin_set_1, validFrameNum1);
		
		honor10 = sig1;
		
		
		
	}
	
	
	public void calDisHonor10(Signature signature) throws IOException{
		//对另一个文件中的burst进行距离计算
		String path = "/Users/longlong/Documents/周报/研一下学期/周报10_龙俐伶/packets/";
		IEEE80211Parser parser = new IEEE80211Parser(new File(path+"honor10-1.pcap"));
		parser.parse();
		
		IFATG_identify ifat_burst = new IFATG_identify(parser.getTimeArray());
		Set<ArrayList<IEEE80211ManagementFrame>> test_burst_set = ifat_burst.groupInBurstSet();
		
		ArrayList<Double> distance_list = new ArrayList<>();
		
		//计算与其他签名间的距离
		ArrayList<Double> distance_list_to_mate7 = new ArrayList<>();
		ArrayList<Double> distance_list_to_mate9 = new ArrayList<>();
		ArrayList<Double> distance_list_to_pad = new ArrayList<>();
		for (ArrayList<IEEE80211ManagementFrame> item: test_burst_set) {
			if (item.size() < 6) continue;
			
			Signature sig_burst = new Signature(); 
			HashMap<Long, ArrayList<Long>> burst_bin_set = new HashMap<>();
			int validFrameNum = 0;
			
			IEEE80211ManagementFrame lastFrame = item.get(0);
			
			ArrayList<Long> new_time_diff_list = new ArrayList<>();
			
			//将burst中的丢帧部分的IFAT补齐 到new_time_diff_list中
			for (int i = 1; i < item.size(); i++) {
				IEEE80211ManagementFrame nowFrame = item.get(i);
				long diff = nowFrame.getMacTimestamp()-lastFrame.getMacTimestamp();
				if (nowFrame.getSeq_num() - lastFrame.getSeq_num() > 1) {
					int num = nowFrame.getSeq_num() - lastFrame.getSeq_num();
					for (int j = 0; j < num; j++) {
						new_time_diff_list.add(diff/num);
					}
				} else if (nowFrame.getSeq_num() - lastFrame.getSeq_num() == 1 || (lastFrame.getSeq_num() == 4095 && nowFrame.getSeq_num() == 0)) {
					new_time_diff_list.add(diff);
				} else {
					//new burst
					System.out.println("wrong");
				}
				lastFrame = nowFrame;
			}
			
			//group in bin set
			for (long diff: new_time_diff_list) {
				long nowIFAT = diff/BIN_SIZE;
				if (burst_bin_set.containsKey(nowIFAT)) {
					burst_bin_set.get(nowIFAT).add(diff);
				} else {
					ArrayList<Long> bin_item = new ArrayList<>();
					bin_item.add(diff);
					burst_bin_set.put(nowIFAT, bin_item);
				}
				validFrameNum++;
			}
			sig_burst = generateSig(burst_bin_set, validFrameNum);
			double distance = 0;
			distance = getDistanceFrom(sig_burst, signature);
			
			distance_list_to_mate7.add(getDistanceFrom(sig_burst, mate7));
			distance_list_to_mate9.add(getDistanceFrom(sig_burst, mate9));
			distance_list_to_pad.add(getDistanceFrom(sig_burst, pad));
			
			distance_list.add(distance);
			System.out.println(distance);
			
		
		}
		
		printMeanAndMedium(distance_list, "to honor 10(self)");
		printMeanAndMedium(distance_list_to_pad, "to pad");
		printMeanAndMedium(distance_list_to_mate7, "to mate7");
		printMeanAndMedium(distance_list_to_mate9, "to mate9");
		
		drawDisListBarChart(distance_list, "hornor10 distance");
		drawDisListBarChart(distance_list_to_mate7, "hornor10 to mate7 distance");
		drawDisListBarChart(distance_list_to_mate9, "hornor10 to mate9 distance");
		drawDisListBarChart(distance_list_to_pad, "hornor10 to pad distance");
				
	}
	
	/**
	 * 对mate9进行签名计算，以及计算人工分离的单个burst与签名的距离，并计算签名的中位数和均值，以及给出签名距离数组的柱形图
	 * 文件mate9-all的前503帧用于计算签名，余下的帧用于计算距离
	 * @throws IOException
	 * mean:4958.130367450758
	 * medium value4181.243380108647
	 */
	public void processOnMate9() throws IOException {
		String path = "/Users/longlong/Documents/周报/研一下学期/周报10_龙俐伶/packets/";
		String f1 = "mate9-1-503.pcap";
		
		Signature sig = new Signature(); 
		HashMap<Long, ArrayList<Long>> bin_set = new HashMap<>();
		int validFrameNum = 0; //记录在bin_set中总共的帧数
		
		File f = new File(path+f1);
		IEEE80211Parser parser = new IEEE80211Parser(f);
		parser.parse();
		
		Set<ArrayList<IEEE80211ManagementFrame>> set = new HashSet<>();
		
		//mate9的特点是每一个burst间seq num的差值一般在36～41，即只要seq num相差大于30就可以认为是一个新的burst了
		ArrayList<IEEE80211ManagementFrame> list = parser.getTimeArray();
		IEEE80211ManagementFrame last = list.get(0);
		ArrayList<IEEE80211ManagementFrame> node = new ArrayList<>();
		node.add(last);
		for (int i = 1; i < list.size(); i++) {
			IEEE80211ManagementFrame now = list.get(i);
			if (now.getSeq_num() - last.getSeq_num() < 10) {
				//belongs to a same burst
				node.add(now);
			} else {
				set.add(node);
				node = new ArrayList<>();
				node.add(now);
			}
			last = now;
		}
		
		for (ArrayList<IEEE80211ManagementFrame> item : set) {
			
			IEEE80211ManagementFrame lastFrame = item.get(0);
			
			ArrayList<Long> new_time_diff_list = new ArrayList<>();
			
			//将burst中的丢帧部分的IFAT补齐 到new_time_diff_list中
			for (int i = 1; i < item.size(); i++) {
				IEEE80211ManagementFrame nowFrame = item.get(i);
				long diff = nowFrame.getMacTimestamp()-lastFrame.getMacTimestamp();
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
			
			//group in bin set
			for (int i = 0; i < new_time_diff_list.size(); i++) {
				long nowIFAT = new_time_diff_list.get(i) / BIN_SIZE;
				if (bin_set.containsKey(nowIFAT)) {
					bin_set.get(nowIFAT).add(new_time_diff_list.get(i));
				} else {
					ArrayList<Long> bin_item = new ArrayList<>();
					bin_item.add(new_time_diff_list.get(i));
					bin_set.put(nowIFAT, bin_item);
				}
				validFrameNum++;
			}
			
			
		}
		
		//生成签名
		Signature signature = new Signature();
		Set<Long> keys = bin_set.keySet();
        Long[] key_array = keys.toArray(new Long[0]);
        
        for (int i = 0; i < key_array.length; i++) {
        		int sum = 0;
        		int count = 0;
        		for (int j = 0; j < bin_set.get(key_array[i]).size(); j++) {
        			sum += bin_set.get(key_array[i]).get(j);
        			count++;
        		}
        		
        		signature.getMean().put(key_array[i], (double)sum/count);
        		signature.getPercentege().put(key_array[i], (double)count/validFrameNum);
        }
		
        mate9 = signature;
        
      
		
	}
	
	public void calDisMate9(Signature signature) throws IOException {
		String path = "/Users/longlong/Documents/周报/研一下学期/周报10_龙俐伶/packets/";
		//对另一个文件中的burst进行距离计算
		IEEE80211Parser parser = new IEEE80211Parser(new File(path+"mate9-504-999.pcap"));
  		parser.parse();
  		
  		Set<ArrayList<IEEE80211ManagementFrame>> test_burst_set = new HashSet<>();
		
		//mate9的特点是每一个burst间seq num的差值一般在36～41，即只要seq num相差大于30就可以认为是一个新的burst了
		ArrayList<IEEE80211ManagementFrame> burst_list = parser.getTimeArray();
		IEEE80211ManagementFrame burst_last = burst_list.get(0);
		ArrayList<IEEE80211ManagementFrame> burst_node = new ArrayList<>();
		burst_node.add(burst_last);
		for (int i = 1; i < burst_list.size(); i++) {
			IEEE80211ManagementFrame now = burst_list.get(i);
			if (now.getSeq_num() - burst_last.getSeq_num() < 10) {
				//belongs to a same burst
				burst_node.add(now);
			} else {
				test_burst_set.add(burst_node);
				burst_node = new ArrayList<>();
				burst_node.add(now);
			}
			burst_last = now;
		}
  		
  		
  		ArrayList<Double> distance_list = new ArrayList<>();
  		
  		//计算与其他签名间的距离
		ArrayList<Double> distance_list_to_mate7 = new ArrayList<>();
		ArrayList<Double> distance_list_to_honor10 = new ArrayList<>();
		ArrayList<Double> distance_list_to_pad = new ArrayList<>();
  		for (ArrayList<IEEE80211ManagementFrame> item: test_burst_set) {
  			
  			Signature sig_burst = new Signature(); 
  			HashMap<Long, ArrayList<Long>> burst_bin_set = new HashMap<>();
  			int validFrameNum_burst = 0;
  			
  			IEEE80211ManagementFrame lastFrame = item.get(0);
  			
  			ArrayList<Long> new_time_diff_list = new ArrayList<>();
  			
  			//将burst中的丢帧部分的IFAT补齐 到new_time_diff_list中
  			for (int i = 1; i < item.size(); i++) {
  				IEEE80211ManagementFrame nowFrame = item.get(i);
  				long diff = nowFrame.getMacTimestamp()-lastFrame.getMacTimestamp();
  				if (nowFrame.getSeq_num() - lastFrame.getSeq_num() > 1) {
  					int num = nowFrame.getSeq_num() - lastFrame.getSeq_num();
  					for (int j = 0; j < num; j++) {
  						new_time_diff_list.add(diff/num);
  					}
  				} else if (nowFrame.getSeq_num() - lastFrame.getSeq_num() == 1 || (lastFrame.getSeq_num() == 4095 && nowFrame.getSeq_num() == 0)) {
  					new_time_diff_list.add(diff);
  				} else {
  					//new burst
  					System.out.println("wrong");
  				}
  				lastFrame = nowFrame;
  			}
  			
  			//group in bin set
  			for (long diff: new_time_diff_list) {
  				long nowIFAT = diff/BIN_SIZE;
  				if (burst_bin_set.containsKey(nowIFAT)) {
  					burst_bin_set.get(nowIFAT).add(diff);
  				} else {
  					ArrayList<Long> bin_item = new ArrayList<>();
  					bin_item.add(diff);
  					burst_bin_set.put(nowIFAT, bin_item);
  				}
  				validFrameNum_burst++;
  			}
  			sig_burst = generateSig(burst_bin_set, validFrameNum_burst);
  			double distance = 0;
  			distance = getDistanceFrom(sig_burst, signature);
  			
  			distance_list_to_mate7.add(getDistanceFrom(sig_burst, mate7));
			distance_list_to_honor10.add(getDistanceFrom(sig_burst, honor10));
			distance_list_to_pad.add(getDistanceFrom(sig_burst, pad));
  			
  			distance_list.add(distance);
  			System.out.println(distance);
  			
  		
  		}
  		
  		printMeanAndMedium(distance_list, "to mate9(self)");
		printMeanAndMedium(distance_list_to_pad, "to pad");
		printMeanAndMedium(distance_list_to_mate7, "to mate7");
		printMeanAndMedium(distance_list_to_honor10, "to honor10");
		
		drawDisListBarChart(distance_list, "mate9 distance");
		drawDisListBarChart(distance_list_to_mate7, "mate9 to mate7 distance");
		drawDisListBarChart(distance_list_to_honor10, "mate9 to hornor10 distance");
		drawDisListBarChart(distance_list_to_pad, "mate9 to pad distance");
  		
  		
	}
	
	/**
	 * 对huawei pad进行签名计算，以及计算人工分离的单个burst与签名的距离，并计算签名的中位数和均值，以及给出签名距离数组的柱形图
	 * @throws IOException
	 * mean:4945.678067195458
	 * medium value:4346.891770058768
	 */
	public void processOnHuaweiPad() throws IOException {
		String path = "/Users/longlong/Documents/周报/研一下学期/周报10_龙俐伶/packets/";
		String f1 = "pad-all.pcap";
		
		Signature sig = new Signature(); 
		HashMap<Long, ArrayList<Long>> bin_set = new HashMap<>();
		int validFrameNum = 0; //记录在bin_set中总共的帧数
		
		File f = new File(path+f1);
		IEEE80211Parser parser = new IEEE80211Parser(f);
		parser.parse();
		
		Set<ArrayList<IEEE80211ManagementFrame>> set = new HashSet<>();
		
		//pad的特点与mate9一样
		ArrayList<IEEE80211ManagementFrame> list = parser.getTimeArray();
		IEEE80211ManagementFrame last = list.get(0);
		ArrayList<IEEE80211ManagementFrame> node = new ArrayList<>();
		node.add(last);
		for (int i = 1; i < list.size(); i++) {
			IEEE80211ManagementFrame now = list.get(i);
			if (now.getSeq_num() - last.getSeq_num() < 10 && now.getSeq_num() - last.getSeq_num() >= 0) {
				//belongs to a same burst
				node.add(now);
			} else {
				set.add(node);
				node = new ArrayList<>();
				node.add(now);
			}
			last = now;
		}
		
		for (ArrayList<IEEE80211ManagementFrame> item : set) {
			
			IEEE80211ManagementFrame lastFrame = item.get(0);
			
			ArrayList<Long> new_time_diff_list = new ArrayList<>();
			
			//将burst中的丢帧部分的IFAT补齐 到new_time_diff_list中
			for (int i = 1; i < item.size(); i++) {
				IEEE80211ManagementFrame nowFrame = item.get(i);
				long diff = nowFrame.getMacTimestamp()-lastFrame.getMacTimestamp();
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
			
			//group in bin set
			for (int i = 0; i < new_time_diff_list.size(); i++) {
				long nowIFAT = new_time_diff_list.get(i) / BIN_SIZE;
				if (bin_set.containsKey(nowIFAT)) {
					bin_set.get(nowIFAT).add(new_time_diff_list.get(i));
				} else {
					ArrayList<Long> bin_item = new ArrayList<>();
					bin_item.add(new_time_diff_list.get(i));
					bin_set.put(nowIFAT, bin_item);
				}
				validFrameNum++;
			}
			
			
		}
		
		//生成签名
		Signature signature = new Signature();
		Set<Long> keys = bin_set.keySet();
        Long[] key_array = keys.toArray(new Long[0]);
        
        for (int i = 0; i < key_array.length; i++) {
        		int sum = 0;
        		int count = 0;
        		for (int j = 0; j < bin_set.get(key_array[i]).size(); j++) {
        			sum += bin_set.get(key_array[i]).get(j);
        			count++;
        		}
        		
        		signature.getMean().put(key_array[i], (double)sum/count);
        		signature.getPercentege().put(key_array[i], (double)count/validFrameNum);
        }
		
        pad = signature;
	}

	public void calDisHuaweiPad(Signature signature) throws IOException {
		//对另一个文件中的burst进行距离计算
		String path = "/Users/longlong/Documents/周报/研一下学期/周报10_龙俐伶/packets/";
		IEEE80211Parser parser = new IEEE80211Parser(new File(path+"pad_no_in_list.pcap"));
  		parser.parse();
  		
  		Set<ArrayList<IEEE80211ManagementFrame>> test_burst_set = new HashSet<>();
		
		//pad的特点与mate9一样
		ArrayList<IEEE80211ManagementFrame> burst_list = parser.getTimeArray();
		IEEE80211ManagementFrame burst_last = burst_list.get(0);
		ArrayList<IEEE80211ManagementFrame> burst_node = new ArrayList<>();
		burst_node.add(burst_last);
		for (int i = 1; i < burst_list.size(); i++) {
			IEEE80211ManagementFrame now = burst_list.get(i);
			if (now.getSeq_num() - burst_last.getSeq_num() < 10 && now.getSeq_num() - burst_last.getSeq_num() >= 0) {
				//belongs to a same burst
				burst_node.add(now);
			} else {
				test_burst_set.add(burst_node);
				burst_node = new ArrayList<>();
				burst_node.add(now);
			}
			burst_last = now;
		}
  		
  		int debug=0;
		
  		ArrayList<Double> distance_list = new ArrayList<>();
  		//计算与其他签名间的距离
  		ArrayList<Double> distance_list_to_honor10 = new ArrayList<>();
  		ArrayList<Double> distance_list_to_mate9 = new ArrayList<>();
  		ArrayList<Double> distance_list_to_mate7 = new ArrayList<>();
  		
  		for (ArrayList<IEEE80211ManagementFrame> item: test_burst_set) {
  			
  			debug++;
  			
  			Signature sig_burst = new Signature(); 
  			HashMap<Long, ArrayList<Long>> burst_bin_set = new HashMap<>();
  			int validFrameNum_burst = 0;
  			
  			IEEE80211ManagementFrame lastFrame = item.get(0);
  			
  			ArrayList<Long> new_time_diff_list = new ArrayList<>();
  			
  			//将burst中的丢帧部分的IFAT补齐 到new_time_diff_list中
  			for (int i = 1; i < item.size(); i++) {
  				IEEE80211ManagementFrame nowFrame = item.get(i);
  				long diff = nowFrame.getMacTimestamp()-lastFrame.getMacTimestamp();
  				if (nowFrame.getSeq_num() - lastFrame.getSeq_num() > 1) {
  					int num = nowFrame.getSeq_num() - lastFrame.getSeq_num();
  					for (int j = 0; j < num; j++) {
  						new_time_diff_list.add(diff/num);
  					}
  				} else if (nowFrame.getSeq_num() - lastFrame.getSeq_num() == 1 || (lastFrame.getSeq_num() == 4095 && nowFrame.getSeq_num() == 0)) {
  					new_time_diff_list.add(diff);
  				} else {
  					//new burst
  					System.out.println("wrong");
  				}
  				lastFrame = nowFrame;
  			}
  			
  			//group in bin set
  			for (long diff: new_time_diff_list) {
  				long nowIFAT = diff/BIN_SIZE;
  				if (burst_bin_set.containsKey(nowIFAT)) {
  					burst_bin_set.get(nowIFAT).add(diff);
  				} else {
  					ArrayList<Long> bin_item = new ArrayList<>();
  					bin_item.add(diff);
  					burst_bin_set.put(nowIFAT, bin_item);
  				}
  				validFrameNum_burst++;
  			}
  			sig_burst = generateSig(burst_bin_set, validFrameNum_burst);
  			double distance = 0;
  			distance = getDistanceFrom(sig_burst, signature);
  			distance_list.add(distance);
  			System.out.println(distance);
  			
  			distance_list_to_mate7.add(getDistanceFrom(sig_burst, mate7));
			distance_list_to_honor10.add(getDistanceFrom(sig_burst, honor10));
			distance_list_to_mate9.add(getDistanceFrom(sig_burst, mate9));
  			
  		
  		}
  		
  		printMeanAndMedium(distance_list, "to pad(self)");
		printMeanAndMedium(distance_list_to_mate9, "to mate9");
		printMeanAndMedium(distance_list_to_mate7, "to mate7");
		printMeanAndMedium(distance_list_to_honor10, "to honor10");
		
	}
	
	public void processOniPhone() throws IOException {
		
		String filename = "iphone7_nowifi_probe_request.pcap";
//		String filename = "iphon6s_1.pcap";
		File file = new File(this.path+filename);
		parser.setFile(file);
		parser.parse();
		
		ArrayList<Long> timeDiffSeq = new ArrayList<>();
		Set<ArrayList<Long>> burstSet = new HashSet<>();
		
		HashMap<Long, ArrayList<Long>> bin_set = getBinSetByMAC(parser.getTimeArray(), timeDiffSeq, burstSet);
		int validFrameNum = timeDiffSeq.size();
		
		/**
		 * 将iphone7的bin set画出来
		 */
		BarChart barChart1 = new BarChart("IFAT attack", "iPhone7 Plus" + "帧间时间差统计", bin_set);
		barChart1.pack( );
		RefineryUtilities.centerFrameOnScreen( barChart1 );  
		barChart1.setVisible( true );
		
		/**
		 * 将iPhone的IFAT序列画出来
		 */
		BarChart barChart2 = new BarChart("IFAT attack", "iPhone7 Plus", timeDiffSeq);
		barChart2.pack( );
		RefineryUtilities.centerFrameOnScreen( barChart2 );  
		barChart2.setVisible( true ); 
		
		this.iphone7 = generateSig(bin_set, validFrameNum);
		
	}
	
	public void calDisIPhone() throws IOException {
		//对另一个文件中的burst进行距离计算
		this.parser.setFile(new File(path+"iphone7_nowifi_probe_request.pcap"));
		this.parser.parse();
		
		Set<ArrayList<IEEE80211ManagementFrame>> burst_set = getBurstSetByMAC(parser.getTimeArray());
		
		ArrayList<Double> distance_list_iphone7 = new ArrayList<>();
		//计算与其他签名间的距离
		ArrayList<Double> distance_list_to_mate7 = new ArrayList<>();
		ArrayList<Double> distance_list_to_mate9 = new ArrayList<>();
		ArrayList<Double> distance_list_to_honor10 = new ArrayList<>();
		ArrayList<Double> distance_list_to_pad = new ArrayList<>();
		
		for (ArrayList<IEEE80211ManagementFrame> item : burst_set) {
			Signature sig_burst = new Signature();
			HashMap<Long, ArrayList<Long>> burst_bin_set = new HashMap<>();
			
			IEEE80211ManagementFrame lastFrame = item.get(0);
			ArrayList<Long> new_time_diff_list = paddingBurst(item);
			hashInBin(new_time_diff_list, burst_bin_set);
			
			sig_burst = generateSig(burst_bin_set, new_time_diff_list.size());
			distance_list_iphone7.add(getDistanceFrom(sig_burst, iphone7));
			distance_list_to_mate7.add(getDistanceFrom(sig_burst, mate7));
			distance_list_to_mate9.add(getDistanceFrom(sig_burst, mate9));
			distance_list_to_pad.add(getDistanceFrom(sig_burst, pad));
			distance_list_to_honor10.add(getDistanceFrom(sig_burst, honor10));
		}
		
		printMeanAndMedium(distance_list_iphone7, "to iphon7(self)");
		printMeanAndMedium(distance_list_to_pad, "to pad");
		printMeanAndMedium(distance_list_to_mate7, "to mate7");
		printMeanAndMedium(distance_list_to_mate9, "to mate9");
		printMeanAndMedium(distance_list_to_honor10, "to honor10");
		
	}
	
	public void processOniPad() throws IOException {
		this.parser.setFile(new File(this.path+"ipad-1.pcap"));
		parser.parse();
		
		ArrayList<Long> timeDiffSeq = new ArrayList<>();
		Set<ArrayList<Long>> burstSet = new HashSet<>();
		HashMap<Long, ArrayList<Long>> bin_set = getBinSetBySeqNum(parser.getTimeArray(), timeDiffSeq, burstSet);
		int validFrameNum = timeDiffSeq.size();
		
		/**
		 * 将bin set画出来
		 */
		BarChart barChart1 = new BarChart("IFAT attack", "iPad mini 2" + "帧间时间差统计", bin_set);
		barChart1.pack( );
		RefineryUtilities.centerFrameOnScreen( barChart1 );  
		barChart1.setVisible( true );
		
		/**
		 * 将IFAT序列画出来
		 */
		BarChart barChart2 = new BarChart("IFAT attack", "iPad mini 2", timeDiffSeq);
		barChart2.pack( );
		RefineryUtilities.centerFrameOnScreen( barChart2 );  
		barChart2.setVisible( true ); 
		
		this.ipad = generateSig(bin_set, validFrameNum);
		
	}
	
	public void processOnMac() throws IOException {
//		this.parser.setFile(new File(this.path+"mac-sam-in-wifi-list-pure.pcap"));
		this.parser.setFile(new File(this.path+"lll-mac-pure.pcap"));
		this.parser.parse();
		
		ArrayList<Long> timeDiffSeq = new ArrayList<>();
		Set<ArrayList<Long>> burstSet = new HashSet<>();
		HashMap<Long, ArrayList<Long>> bin_set = getBinSetBySeqNum(parser.getTimeArray(), timeDiffSeq, burstSet);
		
		int validFrameNum = timeDiffSeq.size();
		this.mac = generateSig(bin_set, validFrameNum);
		
		/**
		 * 将bin set画出来
		 */
		BarChart barChart1 = new BarChart("IFAT attack", "MacBook Pro 2" + "帧间时间差统计", bin_set);
		barChart1.pack( );
		RefineryUtilities.centerFrameOnScreen( barChart1 );  
		barChart1.setVisible( true );
		
		/**
		 * 将IFAT序列画出来
		 */
		BarChart barChart2 = new BarChart("IFAT attack", "MacBook Pro 2", timeDiffSeq);
		barChart2.pack( );
		RefineryUtilities.centerFrameOnScreen( barChart2 );  
		barChart2.setVisible( true ); 
	}
	
	
	public Signature generateSig(HashMap<Long, ArrayList<Long>> bin_set, int validFrameNum) {
		Signature sig = new Signature();
		Set<Long> key_set = bin_set.keySet();
		for (long key: key_set) {
			long sum = 0;
			for (int j = 0; j < bin_set.get(key).size(); j++) {
    				sum += bin_set.get(key).get(j);
			}
			
			sig.getMean().put(key, (double)sum/bin_set.get(key).size());
    			sig.getPercentege().put(key, (double)bin_set.get(key).size()/validFrameNum);
    			
//    			double mean = 0;
//    			Long[] diff_arr = new Long[bin_set.get(key).size()];
//    			bin_set.get(key).toArray(diff_arr);
//    			mean = StatisticUtil.getMean(diff_arr);
    		}
		return sig;
	}

	public void drawDisListBarChart(ArrayList<Double> distance_list, String title) {
		BarChart barChart1 = new BarChart("IFAT attack", title, distance_list.toArray(new Double[0]), "", "distance", false);
		barChart1.pack( );
		RefineryUtilities.centerFrameOnScreen( barChart1 );  
		barChart1.setVisible( true );
	}
	
	public void printMeanAndMedium(ArrayList<Double> distance_list, String start) {
		//计算距离的均值、中位数
		Double[] distance_arr = new Double[distance_list.size()];
		distance_list.toArray(distance_arr);
				
		System.out.println(start+ " mean:"+StatisticUtil.getMean(distance_arr));
		System.out.println(start+ " medium value:"+StatisticUtil.getMediumValue(distance_arr));
	}
	
	
	/**
	 * get the burst set according to the sequence number of each frames , only the difference between two sequence number is less than 10, the two corresponding frames are belong to a same burst 
	 * @param list the all frames list
	 * @return burst set
	 */
	public Set<ArrayList<IEEE80211ManagementFrame>> getBurstSetBySeqNum(ArrayList<IEEE80211ManagementFrame> list) {
		Set<ArrayList<IEEE80211ManagementFrame>> set = new HashSet<>();
		
		//mate9&pad的特点是每一个burst间seq num的差值一般在36～41，即只要seq num相差大于30就可以认为是一个新的burst了
		IEEE80211ManagementFrame last = list.get(0);
		ArrayList<IEEE80211ManagementFrame> node = new ArrayList<>();
		node.add(last);
		for (int i = 1; i < list.size(); i++) {
			IEEE80211ManagementFrame now = list.get(i);
			if (now.getSeq_num() - last.getSeq_num() < 10 && now.getSeq_num() - last.getSeq_num() >= 0) {
				//belongs to a same burst
				node.add(now);
			} else {
				set.add(node);
				node = new ArrayList<>();
				node.add(now);
			}
			last = now;
		}
		
		return set;
	}

	
	/**
	 * get the burst set according to the source MAC address of each frame, the frames which have the same source MAC address belong to a same burst 
	 * @param list the all frames list
	 * @return the burst set
	 */
	public Set<ArrayList<IEEE80211ManagementFrame>> getBurstSetByMAC(ArrayList<IEEE80211ManagementFrame> list) {
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
	 * get the bin set for one device, which key is IFAT/BIN_SIZE, the value is the IFAT sequence which hash in to the bin
	 * the rule deciding two frames if belong to a same burst is about the source MAC adress
	 * @param list a IEEE80211ManagementFrame list of a pcap file
	 * @param timeDiffSeq a ArrayList to store all the time differences sequence
	 * @return
	 */
	public HashMap<Long, ArrayList<Long>> getBinSetByMAC(ArrayList<IEEE80211ManagementFrame> list, ArrayList<Long> timeDiffSeq, Set<ArrayList<Long>> burstSet) {
		HashMap<Long, ArrayList<Long>> binSet = new HashMap<>();
		
//		Set<ArrayList<IEEE80211ManagementFrame>> burstSet = new HashSet<ArrayList<IEEE80211ManagementFrame>>();
		IEEE80211ManagementFrame last = list.get(0);
		ArrayList<IEEE80211ManagementFrame> arr = new ArrayList<>();
		arr.add(last);
		
		for (int i = 1; i < list.size(); i++) {
			IEEE80211ManagementFrame now = list.get(i);
			if (last.getSr_mac().equals(now.getSr_mac())) {
				arr.add(now);
			} else {
//				burstSet.add(arr);
				//now the arr is a burst in which the frames have the same source MAC address, now padding it
				ArrayList<Long> completeBurst = paddingBurst(arr);
				timeDiffSeq.addAll(completeBurst);
				burstSet.add(completeBurst);
				
				hashInBin(completeBurst, binSet);
				
				arr = new ArrayList<>();
				arr.add(now);				
			}
			last = now;
		}
		
		return binSet;
	}
	
	/**
	 * get the bin set for one device, which key is IFAT/BIN_SIZE, the value is the IFAT sequence which hash in to the bin
	 * the rule deciding two frames if belong to a same burst is about the sequence number
	 * @param list a IEEE80211ManagementFrame list of a pcap file
	 * @param timeDiffSeq a ArrayList to store all the time differences sequence
	 * @return
	 */
	public HashMap<Long, ArrayList<Long>> getBinSetBySeqNum(ArrayList<IEEE80211ManagementFrame> list, ArrayList<Long> timeDiffSeq, Set<ArrayList<Long>> burstSet) {
		HashMap<Long, ArrayList<Long>> binSet = new HashMap<>();
		
//		Set<ArrayList<IEEE80211ManagementFrame>> burstSet = new HashSet<ArrayList<IEEE80211ManagementFrame>>();
		IEEE80211ManagementFrame last = list.get(0);
		ArrayList<IEEE80211ManagementFrame> arr = new ArrayList<>();
		arr.add(last);
		
		for (int i = 1; i < list.size(); i++) {
			IEEE80211ManagementFrame now = list.get(i);
			if (now.getSeq_num() - last.getSeq_num() < 15 && now.getSeq_num() > last.getSeq_num()) {
				arr.add(now);
			} else {
//				burstSet.add(arr);
				//now the arr is a burst in which the frames have the same source MAC address, now padding it
				ArrayList<Long> completeBurst = paddingBurst(arr);
				timeDiffSeq.addAll(completeBurst);
				
				burstSet.add(completeBurst);
				hashInBin(completeBurst, binSet);
				
				arr = new ArrayList<>();
				arr.add(now);				
			}
			last = now;
		}
		
		return binSet;
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

	public void hashInBin(ArrayList<Long> burst, HashMap<Long, ArrayList<Long>> bin_set) {
		//group in bin set
		for (int i = 0; i < burst.size(); i++) {
			long nowIFAT = burst.get(i) / BIN_SIZE;
			if (bin_set.containsKey(nowIFAT)) {
				bin_set.get(nowIFAT).add(burst.get(i));
			} else {
				ArrayList<Long> bin_item = new ArrayList<>();
				bin_item.add(burst.get(i));
				bin_set.put(nowIFAT, bin_item);
			}
//			validFrameNum++;
		}
	}

	
	/**
	 * 计算与已知的签名之间的距离
	 * @param Signature toCompare 已知的签名
	 * @return double 签名之间的距离 
	 */
	public double getDistanceFrom(Signature signature, Signature toCompare) {
		double distance = 0.0;
		
		//since HashMap mean and percentage have the same key set, the size of them are same
		Set<Long> keys_m = toCompare.getMean().keySet();
		for (Long i : keys_m) {
			double absolute_m;
			double absolute_p;
			double sum_p;
			if (signature.getMean().containsKey(i)) {
				absolute_m = DataUtils.getAbsoluteValue(toCompare.getMean().get(i), signature.getMean().get(i));
			} else {
				absolute_m = toCompare.getMean().get(i);
			}
			
			if (signature.getPercentege().containsKey(i)) {
				absolute_p = DataUtils.getAbsoluteValue(toCompare.getPercentege().get(i), signature.getPercentege().get(i));
				sum_p = toCompare.getPercentege().get(i) + signature.getPercentege().get(i);
			} else {
				absolute_p = toCompare.getPercentege().get(i);
				sum_p = toCompare.getPercentege().get(i);
			}
			
//			distance += absolute_p*sum_p;
			distance += (absolute_p + (sum_p / 2 * absolute_m));
			
		}
		
		return distance;
	}
	

}
