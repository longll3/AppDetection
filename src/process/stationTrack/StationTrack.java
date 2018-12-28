package process.stationTrack;

import parser.IEEE80211Parser;
import structure.IEEE80211ManagementFrame;

import java.io.File;
import java.io.IOException;
import java.util.*;

public class StationTrack {

    private final static int MaxTimeDiff = 1000000; //每次处理超过1秒间隔的帧。
    private final static int MaxSeqNum = 4095;
    private final static int SeqNumMaxDiff = 100;
    //	private final static int SeqNumMaxDiff = 600;

    private int no = 0;

    private ArrayList<StationInfo> stationList = new ArrayList<>();
    private int stationSize = 0;


    // to store the relative information about a station
    private class StationInfo {

        int frameLength = 0; // frame body length not include radiotap header and the length of ssid
        int frameCount = 0; // the number of all frames
        int macCount = 0; // the number of all macs
        int lastTimestamp = -1; // the time of the pcap header of the last frame
        int lastSequenceNum = -1;

        ArrayList<String> macList = new ArrayList<>();
        ArrayList<Integer> IEType = null; //IE 种类
        Map<Integer, byte[]> IEs; // IE及其具体值

        boolean hasRealMAC = false;

        String realMAC = null;

        public void addBurst(Burst burst) {
            frameCount += burst.frameCount;
            macCount ++;
            lastTimestamp = burst.endTimestamp;
            lastSequenceNum = burst.endSeqNum;

            macList.add(burst.mac);

            if (!hasRealMAC && !ifRandomMac(burst.mac)) {
                hasRealMAC = true;
                realMAC = burst.mac;
            }
        }

        public String toString() {
            String re = "frame number: " + frameCount;

            re += "\n";

            re += "IE types: " + "[";
            for (Integer ie : IEType) {
                re += ie + ", ";
            }
            re += ("]\n");

            re += ("mac set: " + "[");
            for (String mac : macList) {
                re += (mac + ", ");
            }
            re += ("]\n");


            return re;
        }

    }

    // to store information of frames send in meanwhile
    private class Burst {
        int startSeqNum = -1;
        int endSeqNum = -1;
        int startTimestamp = -1;
        int endTimestamp = -1;
        int frameCount = 0;
        int frameLength = -1;

        String mac = null;

        ArrayList<Integer> IEType = null; //IE 种类
        Map<Integer, byte[]> IEs; // IE及其具体值

    }

    public void process(String filename) throws IOException {
        //parse pcap file
        IEEE80211Parser parser = new IEEE80211Parser();
        parser.setFile(new File(filename));
        parser.openInfoElementsFlag();
        parser.parse();
        parser.printIE();

        //group frames
        groupFrames(parser.getTimeArray());

        printResult();
    }

    private void printResult() {
        System.out.println("总共检测到的设备有"+stationSize);

        for (int i = 0; i < stationSize; i++) {
            System.out.println(stationList.get(i).toString());
        }
    }

    public void groupFrames(ArrayList<IEEE80211ManagementFrame> list) {
        int lastTimestamp;

        ArrayList<IEEE80211ManagementFrame> group = new ArrayList<>();

        lastTimestamp = list.get(0).getTimestamp();
        group.add(list.get(0));

        for (int i = 1; i < list.size(); i++) {
            IEEE80211ManagementFrame frame = list.get(i);

            if (frame.getTimestamp() - lastTimestamp > MaxTimeDiff) {
                // send to group in burst
                LinkedHashMap<String, Burst> map = groupByMAC(group);

                //associate staionInfo with each burst in the map
                Iterator iterator = map.entrySet().iterator();

                while (iterator.hasNext()) {

                    Map.Entry entry = (Map.Entry) iterator.next();

                    Burst busrt = (Burst) entry.getValue();

                    //decide which station each burst belong to
                    associateToStaion(busrt);

                }


                group = new ArrayList<>();
                lastTimestamp = frame.getTimestamp();
                group.add(frame);

            } else {
                group.add(frame);
                lastTimestamp = frame.getTimestamp();
            }
        }

    }

    //group some frames in different bursts according to src mac
    public LinkedHashMap<String, Burst> groupByMAC(ArrayList<IEEE80211ManagementFrame> list) {
        LinkedHashMap<String, Burst> map = new LinkedHashMap<>();

        for (int i = 0; i < list.size(); i++) {
            IEEE80211ManagementFrame frame = list.get(i);
            String mac = frame.getSr_mac();

            if (map.containsKey(mac)) {
                Burst burst = map.get(mac);

                burst.endTimestamp = frame.getTimestamp();
                burst.endSeqNum = frame.getSeq_num();
                burst.frameCount++;

            } else {
                Burst burst = new Burst();
                burst.startSeqNum = frame.getSeq_num();
                burst.startTimestamp = frame.getTimestamp();
                burst.endTimestamp = frame.getTimestamp();
                burst.endSeqNum = frame.getSeq_num();
                burst.mac = mac;
                burst.IEType = frame.getIE();
                burst.IEs = frame.getIEs();
                burst.frameCount++;
                burst.frameLength = frame.getFrame_len();

                map.put(mac, burst);
            }
        }

        return map;
    }

    //return true if it belongs to a new station
    public boolean associateToStaion (Burst burst) {

        boolean match = false;
        int index = -1;
        for (int i = 0; i < stationSize; i++) {
            if (match) {
                break;
            }

            StationInfo station = stationList.get(i);

            if (burst.IEType.equals(station.IEType) && burst.frameLength == station.frameLength) {
//					if (seq > stationMap.get(i).getLastSeq() && seq - stationMap.get(i).getLastSeq() < 150 && seq - stationMap.get(i).getLastSeq() > 10&& seq - stationMap.get(i).getLastSeq() > 10) {
//					if (seq > stationMap.get(i).getLastSeq() && seq - stationMap.get(i).getLastSeq() < 600) {
                if (matchSeqNum(station.lastSequenceNum, burst.startSeqNum)) {
                    //MAC地址不一样时，首先比较sequence number的大小，若小于上一个的大小，则为另一个终端，或者相差超过40的，则也为另一个终端
                    //但是有一个问题，就是有些设备的序列号不会递增到4096才重置，如mate7（是另一个设备，具体是哪一个，还得去看一下），其序列号的范围则只在30以内（大概），这个问题应该怎么解决呢？

                    index = i;
//							this.stationMap.get(i).addFrame(frame);
                    match = true;


                }
            }

        }

        if (match) {
            if (ifRandomMac(burst.mac)) {
                stationList.get(index).addBurst(burst);
                return false;
            } else {
                //该burst为真实MAC地址
                if (!stationList.get(index).hasRealMAC) {
                    //且还没有真实MAC地址
                    this.stationList.get(index).addBurst(burst);
                    return false;
                } else if (stationList.get(index).realMAC.equals(burst.mac)) {
                    this.stationList.get(index).addBurst(burst);
                    return false;
                } else {
                    StationInfo stationInfo = new StationInfo();

                    stationInfo.IEs = burst.IEs;
                    stationInfo.IEType = burst.IEType;
                    stationInfo.frameLength = burst.frameLength;

                    stationInfo.addBurst(burst);

                    stationList.add(stationInfo);

                }
            }

        } else {
            StationInfo stationInfo = new StationInfo();

            stationInfo.IEs = burst.IEs;
            stationInfo.IEType = burst.IEType;
            stationInfo.frameLength = burst.frameLength;

            stationInfo.addBurst(burst);

            stationList.add(stationInfo);
        }

        stationSize++;

        return true;
    }

    private boolean matchSeqNum(int lastSeq, int seq) {
        //首先seq一定是比上一帧要大,且在一定范围内
        //另一种情况就是seq的值达到最大需要从头开始计数时
        if ((seq > lastSeq && seq - lastSeq < SeqNumMaxDiff) || (seq + MaxSeqNum - lastSeq < SeqNumMaxDiff)) {
            return true;
        }

        return false;
    }

    /**
     *
     * @param mac
     * @return true if mac is a random mac address.
     */
    public boolean ifRandomMac(String mac) {
        Character c = mac.charAt(1);
        return (c == '2' || c == '6' || c == 'A' || c == 'E');
    }

    public static void main(String[] args) throws IOException {
        StationTrack track = new StationTrack();
//		track.process("/Users/longlong/Documents/周报/研一下学期/ifat实验/packets/"+"proreq-iphone7-others.pcap");
//		track.process("/Users/longlong/Documents/周报/研一下学期/ifat实验/packets/"+"iphone7-1.pcap");
//		track.process("/Users/longlong/master_work/学校内的研究工作/AppDetection&IFATexperience/test_data/"+"packet1.pcap");
//		track.process("/Users/longlong/Documents/研究生工作/ifat实验/packets/"+"honor10-2.pcap");
//		track.process("/Users/longlong/Documents/研究生工作/ifat实验/packets/"+"honor10_all.pcap");
        track.process("/Users/longlong/Documents/研究生工作/终端追踪实验/packets/"+"five-apples-exp-2-pure-pr.pcap");
//		track.process("/Users/longlong/Documents/研究生工作/终端追踪实验/packets/"+"iphone7p-connect-to-wifi-pure-pr-2.pcap");
//		track.process("/Users/longlong/Documents/研究生工作/终端追踪实验/"+"2018-12-14-a207.pcap");
//		track.process("/Users/longlong/Documents/研究生工作/终端追踪实验/"+"2018-12-14-a207-only-randomMAC.pcap");

//		track.process("/Users/longlong/Documents/研究生工作/ifat实验/packets/"+"honor2.pcap");
//		track.process("/Users/longlong/Documents/研究生工作/ifat实验/packets/"+"honor10.pcap");


        System.out.println("finish");
    }


}
