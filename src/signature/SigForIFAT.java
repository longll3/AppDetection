package signature;

import com.sun.tools.corba.se.idl.Preprocessor;
import org.w3c.dom.ls.LSOutput;
import process.ifat.Processor;
import structure.IEEE80211ManagementFrame;
import util.PreProcess;

import java.util.*;

public class SigForIFAT implements SigControl {
    private static int TIME_DIFF_BETWEEN_BURST = 300000; //300微秒


    private Map<Integer, Double[]> sig; //key，burst大小，value，对应burst大小下的平均IFAT
    private Map<Integer, Double[]> IFATSum; //key，burst大小，value，对应burst大小下的IFAT总和的序列
    private Map<Integer, Double> burstSizeDistribution; //key, burst大小，value，该大小的burst所占的比例
    private Map<Integer, Integer> burstSizeCount; //key, burst的大小，value， 该burst的大小出现的次数

    private int burstNum; // burst种类记数

    //	private int mean;
    private int mode; //burst size的众数
    private int min; //burst size的最小值
    private int max; //burst size的最大值

    public SigForIFAT() {}

    public SigForIFAT(Set<ArrayList<Double>> burstSet) {
        this.burstNum = burstSet.size();
        this.burstSizeCount = new HashMap<>();
        burstSizeDistribution = new HashMap<>();
        sig = new HashMap<>();
        this.IFATSum = new HashMap<>();
        //将每个burst的大小统计到burstSizeCount中，key：burst的大小，value：该大小的burst出现的次数
        for (ArrayList<Double> burst: burstSet) {
            if (burstSizeCount.containsKey(burst.size())) {
                int temp = burstSizeCount.get(burst.size());
                burstSizeCount.put(burst.size(), temp+1);
            } else {
                burstSizeCount.put(burst.size(), 1);
            }
        }

        Set<Integer> keys = burstSizeCount.keySet();
        this.max = 0;
        this.min = Integer.MAX_VALUE;
        double maxRate = 0.0;
        for (Integer key: keys) {
            double rate = (double)burstSizeCount.get(key)/burstSet.size();

//			if (rate > 0.10) {
            if (rate > maxRate) {
                maxRate = rate;
                this.mode = key;
            }
            if (key > this.max) this.max = key;
            if (key < this.min) this.min = key;

            //只留下大小占比超过20%的burst
            this.burstSizeDistribution.put(key, rate);
//			}
        }

        for (ArrayList<Double> burst: burstSet) {
            if (burstSizeDistribution.containsKey(burst.size())) {
                if (IFATSum.containsKey(burst.size())) {
                    Double[] temp = IFATSum.get(burst.size());
                    for (int i = 0; i < temp.length; i++) {
                        temp[i] += burst.get(i);
                    }
                } else {
                    IFATSum.put(burst.size(), burst.toArray(new Double[0]));
                }
            }
        }


        Set<Integer> sizeKeys = burstSizeDistribution.keySet();
        for(Integer size: sizeKeys) {
            Double[] temp = IFATSum.get(size);
            Double[] meanArr = new Double[size];
            for (int i = 0; i < temp.length; i++) {
                meanArr[i] = (double) temp[i] / burstSizeCount.get(size);

            }

//            this.sig.put(size, PreProcess.minMaxNormalization(meanArr));
            this.sig.put(size, meanArr);
        }



    }

    public SigForIFAT(ArrayList<Long> burstList) {

        ArrayList<Double> burst = PreProcess.minMaxNormalization(burstList);

        this.burstSizeCount = new HashMap<>();
        this.burstSizeDistribution = new HashMap<>();
        this.sig = new HashMap<>();
        this.IFATSum = new HashMap<>();

        int size = burst.size();;
        mode = size;
        min = size;
        max = size;
        burstNum = 1;

        if (burst.size() < 2) {
            System.err.println("burst size is < 2");
        }

        Double[] a = burst.toArray(new Double[0]);
        int s = burst.size();
        IFATSum.put(s, a);
        burstSizeCount.put(size, 1);

        Double[] p = new Double[size];
        for (int i = 0; i < size; i++ ) {
            p[i] =  (double) IFATSum.get(size)[i] /burstSizeCount.get(size);
        }
        sig.put(size, p);
        burstSizeDistribution.put(size, 1.0);
    }


    //新添加一个burst，对signature进行更新
    public void updateSig(ArrayList<Double> burst) {

//        ArrayList<Double> burst = PreProcess.minMaxNormalization(burstList);

        int burstSize = burst.size();
        Set<Integer> sigSetKey = burstSizeDistribution.keySet();
        burstNum++;
        for (Integer key: sigSetKey) {
            double p = 0.0;
            if (key == burstSize) {
                p = (burstSizeDistribution.get(key)+1) / (burstNum);
            } else {
                p = (burstSizeDistribution.get(key)) / (burstNum);
            }
            burstSizeDistribution.put(key, p);
        }

        if (burstSizeCount.containsKey(burstSize)) {
            int temp = burstSizeCount.get(burstSize);
            temp++;
            burstSizeCount.put(burstSize, temp);

            Double[] ifat = this.IFATSum.get(burst.size());
            for (int i = 0; i < ifat.length; i++) {
                ifat[i] += burst.get(i);
            }

            Double[] meanIfat = this.sig.get(burstSize);
            for (int i = 0; i < meanIfat.length; i++) {
                meanIfat[i] =(double)ifat[i]/temp;
            }

            System.out.println("sig 更新完毕");

        } else {
            burstSizeCount.put(burstSize, 1);
            IFATSum.put(burstSize, burst.toArray(new Double[0]));

            Double[] p = new Double[burstSize];
            for (int i = 0; i < burstSize; i++ ) {
                p[i] =  (double) burst.get(i);
            }
            sig.put(burstSize, p);
        }





    }



    /**
     * get the burst set according to the sequence number of each frames, mac address and timestamp,
     * only the difference between two sequence number is less than 15,
     * and the difference between timestamps is less than 300000,
     * and has the same mac address,
     * the two corresponding frames are belong to a same burst
     *
     * then padding each burst
     * @param list the all frames list
     * @return burst set
     */
    public static Set<ArrayList<Double>> getBurstSetBySeqNum(ArrayList<IEEE80211ManagementFrame> list) {

        int busrtSizeOne = 0;
        int busrtSizeTwo = 0;

        Set<ArrayList<Double>> set = new HashSet<>();

        IEEE80211ManagementFrame last = list.get(0);
        ArrayList<IEEE80211ManagementFrame> node = new ArrayList<>();
        node.add(last);
        for (int i = 1; i < list.size(); i++) {
            IEEE80211ManagementFrame now = list.get(i);

            boolean flag = false;

            if (now.getSr_mac().equals(last.getSr_mac())) {
                if (((now.getSeq_num() - last.getSeq_num() < 15 && now.getSeq_num() - last.getSeq_num() >= 0) ||
                     (now.getSeq_num() < last.getSeq_num() && 4096 - last.getSeq_num() < 15))

                     && now.getTimestamp() - last.getTimestamp() < TIME_DIFF_BETWEEN_BURST) {
                    //belongs to a same burst
                    node.add(now);

                    flag = true;
                }
            }

            if (!flag) {
                //padding burst
                if (node.size() == 1) {
                    busrtSizeOne++;
                } else if (node.size() == 2) {
                    busrtSizeTwo++;
                } else {

//                    没有归一化
//                    ArrayList<Long> padding = paddingBurst(node);
//                    ArrayList<Double> dnode = new ArrayList<>(padding.size());
//                    for (Long item : padding) {
//                        dnode.add(item.doubleValue());
//                    }
//                    set.add(dnode);

                    //归一化
                  set.add(PreProcess.minMaxNormalization(paddingBurst(node)));

                }

                node = new ArrayList<>();
                node.add(now);
            }

            last = now;
        }

        System.out.println("busrtSizeOne: " + busrtSizeOne + ", rate: " + ((double)(busrtSizeOne )/ list.size()));
        System.out.println("busrtSizeTwo: " + busrtSizeTwo + ", rate: " + (((double)(busrtSizeTwo))*2) / list.size());

        return set;
    }



    public static Set<ArrayList<Double>> getBurstSetBySeqNumByNormalization(ArrayList<IEEE80211ManagementFrame> list) {

        int busrtSizeOne = 0;
        int busrtSizeTwo = 0;

        Set<ArrayList<Double>> set = new HashSet<>();
        Set<ArrayList<Double>> setByNormalization = new HashSet<>();

        IEEE80211ManagementFrame last = list.get(0);
        ArrayList<IEEE80211ManagementFrame> node = new ArrayList<>();
        node.add(last);
        for (int i = 1; i < list.size(); i++) {
            IEEE80211ManagementFrame now = list.get(i);

            boolean flag = false;

            if (now.getSr_mac().equals(last.getSr_mac())) {
                if (((now.getSeq_num() - last.getSeq_num() < 15 && now.getSeq_num() - last.getSeq_num() >= 0) ||
                        (now.getSeq_num() < last.getSeq_num() && 4096 - last.getSeq_num() < 15))

                        && now.getTimestamp() - last.getTimestamp() < TIME_DIFF_BETWEEN_BURST) {
                    //belongs to a same burst
                    node.add(now);

                    flag = true;
                }
            }

            if (!flag) {
                //padding burst
                if (node.size() == 1) {
                    busrtSizeOne++;
                } else if (node.size() == 2) {
                    busrtSizeTwo++;
                } else {
//                  没有归一化
                    ArrayList<Long> padding = paddingBurst(node);
                    ArrayList<Double> dnode = new ArrayList<>(padding.size());
                    for (Long item : padding) {
                        dnode.add(item.doubleValue());
                    }
                    set.add(dnode);

                    //归一化
                    ArrayList<Double> dnodeByNormalization = PreProcess.minMaxNormalization(paddingBurst(node));

                    for (int j = 0; j < dnode.size(); j++) {
                        System.out.print(dnode.get(j));
                        if (dnodeByNormalization.size() != 0) {
                            System.out.print("            " + dnodeByNormalization.get(j));
                        }
                        System.out.println();
                    }
                    System.out.println();

                }

                node = new ArrayList<>();
                node.add(now);
            }

            last = now;
        }

        System.out.println("busrtSizeOne: " + busrtSizeOne + ", rate: " + ((double)(busrtSizeOne )/ list.size()));
        System.out.println("busrtSizeTwo: " + busrtSizeTwo + ", rate: " + (((double)(busrtSizeTwo))*2) / list.size());

        return set;
    }


    /**
     * complete each burst with average IFAT
     * @param item a burst
     * @return a array of IFAT
     */
    public static ArrayList<Long> paddingBurst(ArrayList<IEEE80211ManagementFrame> item) {
        ArrayList<Long> new_time_diff_list = new ArrayList<>();
        IEEE80211ManagementFrame lastFrame = item.get(0);
        //将burst中的丢帧部分的IFAT补齐 到new_time_diff_list中
        for (int i = 1; i < item.size(); i++) {
            IEEE80211ManagementFrame nowFrame = item.get(i);
            long diff = nowFrame.getTimestamp()-lastFrame.getTimestamp();

            if (diff > 300000) {
                System.err.println(lastFrame.getSeq_num());
            }

            if (nowFrame.getSeq_num() - lastFrame.getSeq_num() > 1) {
                int num = nowFrame.getSeq_num() - lastFrame.getSeq_num();
                for (int j = 0; j < num; j++) {
                    new_time_diff_list.add(diff/num);
                }
            } else if (nowFrame.getSeq_num() - lastFrame.getSeq_num() == 1) {

                new_time_diff_list.add(diff);
//
//          } else if (nowFrame.getSeq_num() < lastFrame.getSeq_num() && (4096-lastFrame.getSeq_num()<15)){
            } else {
                //new burst
                System.out.println("wrong");
            }

            lastFrame = nowFrame;
        }

        return new_time_diff_list;
    }


    public Map<Integer, Double[]> getSig() {
        return sig;
    }

    public Map<Integer, Double[]> getIFATSum() {
        return IFATSum;
    }

    public Map<Integer, Double> getBurstSizeDistribution() {
        return burstSizeDistribution;
    }

    public Map<Integer, Integer> getBurstSizeCount() {
        return burstSizeCount;
    }

    public int getBurstNum() {
        return burstNum;
    }

    public int getMode() {
        return mode;
    }

    public int getMin() {
        return min;
    }

    public int getMax() {
        return max;
    }

    @Override
    public void updateSignature(Figure fig) {
        ArrayList<Double> arr = new ArrayList<Double>(Arrays.asList(fig.getIFATList()));

        this.updateSig(arr);
    }



    @Override
    public boolean isBelongToTheType(Figure fig) {
        System.out.println("不适用");
        return false;
    }

    @Override
    public Map extractSignature(Figure fig) {
        //可以把归一化放在这里
        return null;
    }
}
