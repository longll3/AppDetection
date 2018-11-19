package parser;

import structure.IEEE80211ManagementFrame;
import structure.PcapDataHeader;

import java.io.File;
import java.io.IOException;
import java.lang.reflect.Array;
import java.util.ArrayList;
import java.util.List;

public class ParserTest {

    public static void main(String[] args) throws IOException {

        IEEE80211Parser parser = new IEEE80211Parser();

        parser.setFile(new File("/Users/longlong/Documents/研究生工作/ifat实验/packets/iphon6s_nowifi_IFAT.pcap"));
        parser.parse();

        ArrayList<Long> timeDiffForFrame = new ArrayList<>();
        ArrayList<Long> timeDiffForPcapHeader = new ArrayList<>();
        ArrayList<IEEE80211ManagementFrame> timestamps = parser.getTimeArray();
        List<PcapDataHeader> dataHeaders = parser.getPcapStruct().getDataHeaders();

        Long lastTimeFrame = timestamps.get(0).getTimestamp();
        Long lastTimePcapHeader = (long) dataHeaders.get(0).getTimeS()*1000000+dataHeaders.get(0).getTimeMs();

        for (int i = 1; i < timestamps.size(); i++) {
            timeDiffForFrame.add(timestamps.get(i).getTimestamp()-lastTimeFrame);
            lastTimeFrame = timestamps.get(i).getTimestamp();

            Long current = (long) dataHeaders.get(i).getTimeS()*1000000+dataHeaders.get(i).getTimeMs();
            timeDiffForPcapHeader.add(current-lastTimePcapHeader);
            lastTimePcapHeader = current;

        }


        for (int i = 0; i < timeDiffForFrame.size(); i++) {
//            System.out.println(timeDiffForFrame.get(i)+" "+ timeDiffForPcapHeader.get(i));
            System.out.println(timeDiffForFrame.get(i) - timeDiffForPcapHeader.get(i));
        }


    }
}
