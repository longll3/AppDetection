package process.brandByIE;

import java.io.File;
import java.io.IOException;
import java.util.*;

import parser.IEEE80211Parser;
import signature.*;
import structure.IEEE80211ManagementFrame;


public class BrandIdentify {
	
	private IEEE80211Parser parser = new IEEE80211Parser();
	public int frameNun = 0;
	
//	private Map<String, SignatureForSequenceIE> sigs = new HashMap<>();
//	private Map<String, SignatureForIE> sigs = new HashMap<>();
	private Map<String, SigControl> sigs = new HashMap<>();

	
	public static void main(String[] args) throws IOException {
		BrandIdentify brandIdentify = new BrandIdentify();
		brandIdentify.generateSigs();
		
		String path = "/Users/longlong/Documents/研究生工作/ifat实验/packets/";

		//小米
//		String fileNames[] = new String[]{"mi4-test-251frames.pcap", "mi6-test-391frames.pcap"};

		//苹果系列
//		"mate9-all.pcap", "mate71-1-202.pcap"};
//		String fileNames[] = new String[]{"iphone7p/iphone7-nowifi-to-withwifi.pcap"};
		String fileNames[] = new String[]{"iphon6s_nowifi_IFAT.pcap", "iphone7p/iphone7p-test-101frames.pcap",
								"sam-mac-test-1-150.pcap", "lll-mac-test-1-150.pcap", "ipad-test-1-150.pcap"};

		//华为系列
//		String fileNames[] = new String[]{"mate71-1-202.pcap","mate72-size1000-1-208.pcap"};
//		String fileNames[] = new String[]{"mate9-201-503.pcap", "honor10-2-test-1-200.pcap",
//				"mate71-1-202.pcap","mate72-size1000-1-208.pcap"};
		for (String fileName : fileNames) {
			brandIdentify.frameNun = 0;
			brandIdentify.parser.setFile(new File(path+fileName));
			brandIdentify.parser.parse();

			Map<String, Integer> result = new HashMap<>();

			for (IEEE80211ManagementFrame frame: brandIdentify.parser.getTimeArray()) {
				String brand = brandIdentify.judgeForFrame(SignatureForIE.extractSignature(frame.getIEs()));
//				String brand = brandIdentify.judgeForFrame(SignatureForSequenceIE.extractSignature(frame.getSequenceIEs()));
				if (result.containsKey(brand)) {
					int count = result.get(brand);
					result.put(brand, count+1);
				} else {
					result.put(brand, 1);
				}
				brandIdentify.frameNun++;
			}

			System.out.println("测试设备："+fileName+", probe request帧总数为"+brandIdentify.frameNun);
			Set<String> brands = result.keySet();
			for (String brand : brands) {
				System.out.println("属于 "+brand+" 的probe request 帧个数为"+result.get(brand));
			}
			System.out.println();

		}

		
	}

	private static Set<ArrayList<IEEE80211ManagementFrame>> getBurstSetByMac(
			ArrayList<IEEE80211ManagementFrame> list) {
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

//	private String judgeForFrame(Map<Integer, byte[]> IEs) {
//		Set<String> brands = this.sigs.keySet();
//		for (String brand : brands) {
//			SignatureForIE signature = this.sigs.get(brand);
//			if (signature.isBelongTo(IEs)) {
//				return brand;
//			}
//		}
//
//		return "no brand match";
//
//
//	}

	private String judgeForFrameBySequenceIE(LinkedHashMap<Integer, byte[]> IEs) {
		Set<String> brands = this.sigs.keySet();
		for (String brand : brands) {
//			SignatureForSequenceIE signature = this.sigs.get(brand);
//			SignatureForIE signature = this.sigs.get(brand);
			SigControl signature = this.sigs.get(brand);
			if (signature.isBelongToTheType(new FigureForIE(IEs, null))) {
				return brand;
			}
		}

		return "no brand match";


	}

	private String judgeForFrame(Map<Integer, byte[]> IEs) {
		Set<String> brands = this.sigs.keySet();
		for (String brand : brands) {
//			SignatureForSequenceIE signature = this.sigs.get(brand);
//			SignatureForIE signature = this.sigs.get(brand);
			SigControl signature = this.sigs.get(brand);
			if (signature.isBelongToTheType(new FigureForIE(IEs, null))) {
				return brand;
			}
		}

		return "no brand match";


	}

	private void generateSigs() throws IOException {
		String path = "/Users/longlong/Documents/研究生工作/ifat实验/packets/";

//		Runtime run = Runtime.getRuntime();
//		System.out.println(run.totalMemory());

		for (DeviceMap device : DeviceMap.values()) {
//			SignatureForSequenceIE sig = new SignatureForSequenceIE();
//			SignatureForIE sig = new SignatureForIE();
			SigControl sig = new SigForIE();
			for (String fileName : device.getFileNames()) {
//				System.out.println(fileName+" parser前的内存："+(run.freeMemory()));

				IEEE80211Parser r = new IEEE80211Parser();

				r.setFile(new File(path+fileName));
//				System.out.println(fileName+" setFile后的内存："+(run.freeMemory()));
				r.parse();

//				System.out.println(fileName+" parser后的内存："+(run.freeMemory()));

				for (IEEE80211ManagementFrame frame : r.getTimeArray()) {
//					sig.updateSignature(frame.getSequenceIEs());
					sig.updateSignature(new FigureForIE(frame.getIEs(), frame.getIE()));
				}

			}
			this.sigs.put(device.getDeviceName(), sig);

		}
		
		
		
	}


	
	public static Set<ArrayList<IEEE80211ManagementFrame>> getBurstSetBySeqNum(ArrayList<IEEE80211ManagementFrame> list) {
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
}


