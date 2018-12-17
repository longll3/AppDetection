package longll;

import java.io.File;
import java.io.IOException;
import java.lang.reflect.Array;
import java.util.ArrayList;
import java.util.Map;
import java.util.Set;

import parser.IEEE80211Parser;
import parser.PcapFileParser;
import process.ProcessCombinedIFATAndIE;
import process.ifat.ProcessByDTW;
import process.identifyStation.StationIdentify;
import process.ifat.Processor;
import signature.SigForIFAT;

public class APP {
	
	public static void main(String[] args) throws IOException {
//		StationIdentify id = new StationIdentify();
//		id.generateDataBase();


		testProcessorByDTW();
	}
	
	public static void testProcessorByDTW() throws IOException {
		
//		ProcessByDTW processorByDTW = new ProcessByDTW();
//		processorByDTW.processOnHuaWei();
////		processor.processOniPhone("iphone7_nowifi_probe_request.pcap", "iphone7");
////		processorByDTW.processOnApple();
//		processorByDTW.calDisFromOtherOfMate7();
////		processorByDTW.calDisFromOtherOfIphone7();

		ProcessCombinedIFATAndIE process = new ProcessCombinedIFATAndIE();
		process.generatesSignature();
		process.process();

//		process.ifat.Processor processor = new Processor();
//		processor.generatesSigs();
//
//		System.out.println("签名构建完毕");
//
//		processor.calDisFromOther();
	}
	

	public static void IFATTest() throws IOException {
//		String path = "/Users/longlong/Documents/周报/研一下学期/周报8_龙俐伶/";
//		String path = "/Users/longlong/Documents/周报/研一下学期/周报9_龙俐伶/packet/";
		String path = "/Users/longlong/Documents/周报/研一下学期/周报10_龙俐伶/packets/";
		
//		String file = "huaweipad-1-1-218.pcap";
//		String file = "honor10-1.pcap";
//		String file = "mate71-1-202.pcap";
//		String file = "mate72-size1000-1-208.pcap";
//		String file = "mate9-1-200.pcap";
		String file = "iphone7_nowifi_probe_request.pcap";
//		String file = "iphone_with_wifi_IFAT.pcap";
//		String file = "iphone7_with_wifi_IFAT_in206.pcap";
//		String file = "jiali_probe_request.pcap";
//		String file = "MyProbeRequest.pcap";
//		String file = "iphon6s_nowifi_IFAT.pcap";
//		String file = "wlans8_part1.pcap";
//		String file = "wlans8_part2.pcap";
//		String file = "wlans8.pcap";
//		String file = "wlans8_255～485.pcap";
		File f = new File(path+file);
		IEEE80211Parser parser = new IEEE80211Parser(f);
		parser.parse();
		
		
		IFAT ifat = new IFAT();
		ifat.setTimeArray(parser.getTimeArray());
//		process.process.ifat.ifat.process();
		ifat.process_by_IFAT("iphone7");
		
	}
	
	public static void ifat_expe_Test() throws IOException {
		String path = "/Users/longlong/Documents/周报/研一下学期/周报10_龙俐伶/packets/";
		String f1 = "mate71-203-1000.pcap";
		String f2 = "mate72-size1000-1-208.pcap";
		
		String originFile, testFile;
		originFile = path+f1;
		testFile = path+f2;
		
		File f = new File(originFile);
		IEEE80211Parser parser = new IEEE80211Parser(f);
		parser.parse();
		
		IFATG_identify ifat_origin = new IFATG_identify(parser.getTimeArray());
		ifat_origin.generateSignature();
		
		System.out.println(ifat_origin.getSignature().getMean());
		System.out.println(ifat_origin.getSignature().getPercentege());
		
		File test = new File(testFile);
		
		parser.setFile(test);
		parser.parse();
		
		IFATG_identify ifat_test = new IFATG_identify(parser.getTimeArray());
		ifat_test.generateSignature();
		
		System.out.println(ifat_test.getSignature().getMean());
		System.out.println(ifat_test.getSignature().getPercentege());
		
		IFATG_identify.drawBarchart(ifat_origin.getSignature(), ifat_test.getSignature());
		
		System.out.println(ifat_test.getDistanceFrom(ifat_origin.getSignature()));
	}
	
	public static void getVirtualInfo() throws IOException {
		String path = "/Users/longlong/tungee/app识别/package/";
		String file = "meituan.pcap";
		
		File f = new File(path+file);
		
		PcapFileParser parser = new PcapFileParser(f, "192.168.22.197");
		parser.parse();
		
		System.out.println("捕捉到的虚拟身份信息如下");
		Map<String, String> infoMap = parser.getInfo();
		System.out.println(infoMap);
	}

	public static void BurstTest() throws IOException {
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
	

	
}

