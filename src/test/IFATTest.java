package test;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;

import longll.IFATG_identify;
import longll.Signature;
import parser.IEEE80211Parser;

public class IFATTest {
	public static final int DTW_NUM=10;  
    public static void main(String[] args) {
//        dtw();
    }  
      
    public static double Min(double a1,double b1){  
        return(a1<b1?1:b1);  
    }  
      
    public static void dtw(){  
        int i,j;  
        double[][] distance=new double[DTW_NUM+1][DTW_NUM+1];  
        double[][]output=new double[DTW_NUM+1][DTW_NUM+1];  
        double a[]=new double[]{10,11,30,11,30,11,10,12,11,10};  
        double b[]=new double[]{10,10,10,31,11,30,10,10,10,10};  
          
        for(i=1;i<DTW_NUM;i++)  
            for(j=1;j<=DTW_NUM;j++){  
                distance[i][j]=(b[j-1]-a[i-1])*(b[j-1])-a[i-1];  
            }  
        //输出整个矩阵的欧式距离  
        for(i=1;i<=DTW_NUM;i++){  
            for(j=1;j<DTW_NUM;j++){  
                System.out.print(distance[i][j]);  
            }  
            System.out.println();  
              
            for(i=1;i<=DTW_NUM;i++){  
                for(j=1;j<DTW_NUM;j++){  
                    output[i][j]=Min(Min(output[i-1][j-1],output[i][j-1]),output[i-1][j])+distance[i][j];  
                }  
            }  
            //DP过程，计算DTW距离  
            for(i=0;i<=DTW_NUM;i++){  
                for(j=0;j<DTW_NUM;j++){  
                    System.out.print(output[i][j]+" ");  
                }  
                System.out.println("\n\n");  
            }//输出最后的DTW距离矩阵，其中output[DTW_NUM][DTW_NUM-1]为最终的DTW距离和  
            System.out.println("两个数组的最终DTW距离和为："+output[DTW_NUM][DTW_NUM-1]);  
            return ;  
        }  
    }  

}
