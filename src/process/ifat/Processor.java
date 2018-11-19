package process.ifat;

import parser.IEEE80211Parser;
import process.brandByIE.DeviceMap;
import signature.Figure;
import signature.FigureForIFAT;
import signature.SigControl;
import signature.SigForIFAT;
import util.DTWDistance;
import util.PreProcess;
import util.PropertiesReader;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

public class Processor {

    private Map<String, SigControl> sigMap = new HashMap<>();

    public void generatesSigs() throws IOException {
        PropertiesReader propertiesReader = PropertiesReader.getPropertiesReader();
        String path = propertiesReader.getProperty("rootPath");

        IEEE80211Parser parser = new IEEE80211Parser();

        for (DeviceMap device : DeviceMap.values()) {
            SigControl sigControl = new SigForIFAT();
            for (String fileName : device.getFileNames()) {
                parser.setFile(new File(path+fileName));

                parser.parse();

                System.out.println(device.getDeviceName()+": ");
                Set<ArrayList<Double>> burstSet = SigForIFAT.getBurstSetBySeqNum(parser.getTimeArray());

                this.sigMap.put(device.getDeviceName(), new SigForIFAT(burstSet));
            }
        }

    }

    public void calDisFromOther() throws IOException {
        PropertiesReader propertiesReader = PropertiesReader.getPropertiesReader();
        String path = propertiesReader.getProperty("rootPath");

        IEEE80211Parser parser = new IEEE80211Parser();

        for (DeviceMap device : DeviceMap.values()) {

            Map<String, Integer> statis = new HashMap<>();

            SigControl sigControl = new SigForIFAT();

            if (device.getTestFileNames() == null) {
                continue;
            }

            Map<String, Integer> deviceCount = new HashMap<>();

            parser.setFile(new File(path+device.getTestFileNames()));

            parser.parse();

            System.out.println(device.getDeviceName()+": ");
            Set<ArrayList<Double>> burstSet = SigForIFAT.getBurstSetBySeqNum(parser.getTimeArray());

            for (ArrayList<Double> burst : burstSet) {
                String result = calOneBurstDis(burst);

                if (deviceCount.containsKey(result)) {
                    deviceCount.put(result, deviceCount.get(result)+1);
                } else {
                    deviceCount.put(result, 1);
                }

            }

            Set<String> preDevName = deviceCount.keySet();
            for (String preDev : preDevName) {
                System.out.println(preDev+": "+ deviceCount.get(preDev) + ", 占" + (double) deviceCount.get(preDev)/burstSet.size());
            }

            System.out.print("down\n\n");

        }

    }


    public String calOneBurstDis(ArrayList<Double> burst) {

        Double[] burst_arr = burst.toArray(new Double[0]);
        double minDistance = Double.MAX_VALUE;

        String predictiveDeviceName = "";

        Set<String> keys = this.sigMap.keySet();

        for (String key : keys) {
            SigForIFAT sig = (SigForIFAT) sigMap.get(key);

            Figure figure = new FigureForIFAT(burst_arr);

            if (sig.getBurstSizeDistribution().containsKey(burst.size())) {

                double distance = DTWDistance.haffumanDistance(sig.getSig().get(burst.size()), burst_arr);
//                double distance = DTWDistance.haffumanDistance(sig.getSig().get(burst.size()), PreProcess.minMaxNormalization(burst_arr));
                distance = distance*(1-sig.getBurstSizeDistribution().get(burst.size()));

                if (minDistance > distance) {
                    minDistance = distance;
                    predictiveDeviceName = key;
                }

                System.out.println("signature device:" + key + ",burst size is:"+burst.size()+" distance is :"+distance);
            }

        }

//        System.out.println("\nbelong to device " + predictiveDeviceName + "\n");

        return predictiveDeviceName;
    }


    public static void main(String[] args) throws IOException {
        Processor processor = new Processor();
        processor.generatesSigs();

        System.out.println("签名构建完毕");

        processor.calDisFromOther();
    }





}
