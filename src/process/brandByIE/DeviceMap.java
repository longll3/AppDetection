package process.brandByIE;

public enum DeviceMap {
//    	IPHONE7("iPhone7 Plus", new String[]{"iphone7p/iphone7-1.pcap"}),
//    IPHONE7("iPhone7 Plus", new String[]{"iphone7p/iphone7-1.pcap"}, "iphone7p/iphone7p-test-101frames.pcap"),
//    IPHONE6S("iPhone6s", new String[]{"iphon6s_1.pcap"}, "iphon6s_nowifi_IFAT.pcap"),
////    MACBOOK("MacBook Pro", new String[]{"lll-mac-pure.pcap","sam-mac-1.pcap"}),
//    MACBOOK1("MacBook Pro1", new String[]{"lll-mac-pure.pcap"}, null),//"sam-mac-1.pcap"}),
////    MACBOOK2("MacBook Pro2", new String[]{"sam-mac-1.pcap"}),
//    IPAD("iPad", new String[]{"ipad-1-.pcap"}, null);

	MATE7_1("华为mate7", new String[]{"mate71-all.pcap"}, "mate71-1-202.pcap"),
//	MATE7_1("华为mate7", new String[]{"mate72-size1000-209-1000.pcap", "mate71-203-1000.pcap"}, "mate71-1-202.pcap"),
//	MATE7_1("华为mate71", new String[]{"mate72-size1000-209-1000.pcap"}),
//	MATE7_2("华为mate72", new String[]{"mate71-203-1000.pcap"}),
//	MATE7_2("华为mate72", new String[]{"mate71-203-1000.pcap"}),
	HONOR10("华为荣耀10", new String[]{"honor10-2.pcap"}, "honor10-1.pcap"),
//	HONOR10("华为荣耀10", new String[]{"honor10-2.pcap"}, "honor10-2-test-1-200.pcap"),
//	HONOR10("华为荣耀10", new String[]{"honor1.pcap"}, "honor10-2-test-1-200.pcap"),
	MATE_9("华为mate9",new String[]{"mate9-all.pcap"}, "mate9-504-999.pcap"),
//	HUAWEIPAD("华为 Pad", new String[]{"huaweipad-1-1-218.pcap"}),//pad-all.pcap
	HUAWEIPAD("华为 Pad", new String[]{"pad-all.pcap"}, null);

//	MI4("小米4",new String[]{"mi4-1-200.pcap"}, "mi4-test-251frames.pcap"),
//    MI6("小米6",new String[]{"mi6-1-149.pcap"}, "mi6-test-391frames.pcap");

    private String deviceName;
    private String[] fileNames;
    private String testFileNames;

    private DeviceMap(String name, String[] fileNames, String testFileNames) {
        this.deviceName = name;
        this.fileNames = fileNames;
        this.testFileNames = testFileNames;
    }

    public String getDeviceName() {
        return this.deviceName;
    }

    public String[] getFileNames() {
        return this.fileNames;
    }

    public String getTestFileNames() {
        return testFileNames;
    }
}
