package process;


import parser.IEEE80211Parser;
import process.brandByIE.DeviceMap;
import signature.*;
import structure.IEEE80211ManagementFrame;
import util.DTWDistance;
import util.PropertiesReader;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/**
 * a method combining IFAT method and IE method
 */
public class ProcessCombinedIFATAndIE implements Processor  {
    IEEE80211Parser parser = new IEEE80211Parser();

    Map<String, SigControl> sigIFAT = new HashMap<>();
    Map<String, SigControl> sigIE = new HashMap<>();


    public ProcessCombinedIFATAndIE() {}


    @Override
    public void generatesSignature() throws IOException {
        PropertiesReader propertiesReader = PropertiesReader.getPropertiesReader();
        String path = propertiesReader.getProperty("rootPath");

        IEEE80211Parser parser = new IEEE80211Parser();

        for (DeviceMap device : DeviceMap.values()) {
            SigControl sigIE = new SigForIE();
            SigControl sigIFAT = new SigForIFAT();

            for (String fileName : device.getFileNames()) {
                parser.setFile(new File(path+fileName));

                parser.parse();

                System.out.println(device.getDeviceName()+": ");
                ArrayList<ArrayList<IEEE80211ManagementFrame>> frameSet = new ArrayList<>();
                Set<ArrayList<Double>> burstSet = SigForIFAT.getBurstSetBySeqNum(parser.getTimeArray(), frameSet);
                for (ArrayList<Double> burst : burstSet) {
                    ((SigForIFAT) sigIFAT).updateSig(burst);
                }


                for (IEEE80211ManagementFrame frame : parser.getTimeArray()) {
//					sig.updateSignature(frame.getSequenceIEs());
                    sigIE.updateSignature(new FigureForIE(frame.getIEs(), frame.getIE()));
                }



            }
            this.sigIE.put(device.getDeviceName(), sigIE);
            this.sigIFAT.put(device.getDeviceName(), sigIFAT);
        }

    }

    @Override
    public void process() throws IOException {
        PropertiesReader propertiesReader = PropertiesReader.getPropertiesReader();
        String path = propertiesReader.getProperty("rootPath");

        int frameNun = 0;

        for (DeviceMap device : DeviceMap.values()) {

            int index = 0;

            Map<String, Integer> statis = new HashMap<>();

            SigControl sigControl = new SigForIFAT();

            if (device.getTestFileNames() == null) {
                continue;
            }

            Map<String, Integer> deviceCount = new HashMap<>();

            parser.setFile(new File(path+device.getTestFileNames()));

            parser.parse();

            System.out.println(device.getDeviceName()+": ");
            ArrayList<ArrayList<IEEE80211ManagementFrame>> frameSet = new ArrayList<>();
            Set<ArrayList<Double>> burstSet = SigForIFAT.getBurstSetBySeqNum(parser.getTimeArray(), frameSet);


            for (ArrayList<Double> burst : burstSet) {
                String result = calOneBurstDis(burst);

                if (deviceCount.containsKey(result)) {
                    deviceCount.put(result, deviceCount.get(result)+1);
                } else {
                    deviceCount.put(result, 1);
                }

                String brand = judgeForFrame(SignatureForIE.extractSignature(frameSet.get(index).get(0).getIEs()));

                System.out.println("测试设备："+device.getDeviceName()+", 属于"+ brand);
                index ++;

            }

            Set<String> preDevName = deviceCount.keySet();
            for (String preDev : preDevName) {
                System.out.println(preDev+": "+ deviceCount.get(preDev) + ", 占" + (double) deviceCount.get(preDev)/burstSet.size());
            }

            System.out.print("down\n\n");

        }
    }

    private String judgeForFrame(Map<Integer, byte[]> IEs) {
        Set<String> brands = this.sigIE.keySet();
        for (String brand : brands) {
//			SignatureForSequenceIE signature = this.sigs.get(brand);
//			SignatureForIE signature = this.sigs.get(brand);
            SigControl signature = this.sigIE.get(brand);
            if (signature.isBelongToTheType(new FigureForIE(IEs, null))) {
                return brand;
            }
        }

        return "no brand match";


    }

    public String calOneBurstDis(ArrayList<Double> burst) {

        Double[] burst_arr = burst.toArray(new Double[0]);
        double minDistance = Double.MAX_VALUE;

        String predictiveDeviceName = "";

        Set<String> keys = this.sigIFAT.keySet();

        for (String key : keys) {
            SigForIFAT sig = (SigForIFAT) sigIFAT.get(key);

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

        System.out.println("\nbelong to device " + predictiveDeviceName + "\n");

        return predictiveDeviceName;
    }

}
