package util;

import java.util.Arrays;

public class StatisticUtil {
	//只适用于int、double型数组
	public static double getMean(Object[] a) {
		if (a.length == 0) {
			System.err.println("the array is empty");
			return 0;
		}
		double sum = 0;
		for (int i = 0 ; i < a.length; i++) {
			sum += (double)a[i];
		}
		
		return (sum/a.length);

	}
	
	//只适用于int型、double数组
	public static double getMediumValue(Object[] a) {
		int l = a.length;
		
		if (l == 0) {
			System.err.println("the array is empty");
			return 0;
		}
		
		Arrays.sort(a);
		
		if (l % 2 == 0) {
			return ((double)a[l/2]+(double)a[l/2 - 1]) / 2;
		} else {
			return (double)a[l/2];
		}
	}
	
	
}
