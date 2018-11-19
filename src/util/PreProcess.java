package util;

import com.sun.xml.internal.ws.api.message.ExceptionHasMessage;

import java.util.ArrayList;
import java.util.function.DoubleBinaryOperator;

public class PreProcess {


    /**
     * 将数组arr的值映射到0～1
     * @param arrList
     * @return
     */
    public static ArrayList<Double> minMaxNormalization(ArrayList<Long> arrList) {
        Long[] arr = arrList.toArray(new Long[0]);
        double min = getMinValue(arr);
        double max = getMaxValue(arr);
        double maxMinusMin = max - min;

        ArrayList<Double> newArr = new ArrayList<Double>(arr.length);

        if (maxMinusMin != 0) {
            for (int i = 0; i < arr.length; i++) {
                newArr.add((arr[i]-min) / maxMinusMin);
            }
        } else {
            System.err.println(maxMinusMin);
            System.err.println("归一化有异常，失败");

        }

        return newArr;
    }


    public static Double[] minMaxNormalization(Double[] arrList) {
        double min = getMinValue(arrList);
        double max = getMaxValue(arrList);
        double maxMinusMin = max - min;

        Double[] newArr = new Double[arrList.length];

        if (maxMinusMin != 0) {
            for (int i = 0; i < arrList.length; i++) {
                newArr[i] = ((arrList[i]-min) / maxMinusMin);
            }
        } else {
            System.err.println(maxMinusMin);
            System.err.println("归一化有异常，失败");

        }

        return newArr;
    }


    public static double getMinValue(Double[] arr) {
        double min = Double.MAX_VALUE;
        for (double item : arr) {
            if (min > item) {
                min = item;
            }
        }

        return min;
    }

    public static double getMinValue(Long[] arr) {
        double min = Double.MAX_VALUE;
        for (double item : arr) {
            if (min > item) {
                min = item;
            }
        }

        return min;
    }

    public static double getMaxValue(Double[] arr) {
        double max = Double.MIN_VALUE;
        for (double item : arr) {
            if (max < item) {
                max = item;
            }
        }
        return max;
    }

    public static double getMaxValue(Long[] arr) {
        double max = Double.MIN_VALUE;
        for (double item : arr) {
            if (max < item) {
                max = item;
            }
        }
        return max;
    }
}
