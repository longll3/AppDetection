package test;

import java.io.BufferedReader;  
import java.io.File;  
import java.io.FileReader;  
import java.io.IOException;  
import java.text.MessageFormat;  
import java.util.ArrayList;  
  
public class DTW_Tool {  
    private String filePath;  
    private double[][] distance;  
    private int[] X;  
    private int[] Y;  
    private double[][] dtw;  
    ArrayList<String[]> listTemp;  
    public DTW_Tool(String filePath){  
        this.filePath = filePath;  
        readDataFile();  
    }  
    public DTW_Tool(int[] X,int[] Y){  
        this.X = new int[X.length];  
        for(int i=0;i<X.length;i++){  
            this.X[i]=X[i];  
        }  
        this.Y = new int[Y.length];  
        for(int i=0;i<Y.length;i++){  
            this.Y[i]=Y[i];  
        }  
          
    }  
    private void readDataFile() {  
        File file = new File(filePath);  
         listTemp = new ArrayList<String[]>();  
        try{  
            BufferedReader in = new BufferedReader(new FileReader(filePath));  
            String str;  
            String[] strTemp;  
            while((str=in.readLine())!=null){  
                  
                strTemp = str.split(" ");  
                listTemp.add(strTemp);  
                  
            }  
        }catch(IOException e){  
            e.printStackTrace();  
              
        }  
        //利用listTemp初始化两个带比较的数列  
          
    }  
    public void initXAndY(){  
        int i;  
        X = new int[listTemp.get(0).length];  
        for(int k=0;k<listTemp.get(0).length;k++){  
            X[k] = Integer.parseInt(listTemp.get(0)[k]);  
        }  
        double dtw;  
        double minDtw = Double.MAX_VALUE;  
        int minDex =0;  
        //第一行作为模板  
        for(int j=1;j<listTemp.size();j++){  
            dtw =0;  
            Y = new int[listTemp.get(j).length];  
            for(int k=0;k<listTemp.get(j).length;k++){  
                Y[k] = Integer.parseInt(listTemp.get(j)[k]);  
                  
                  
            }  
            dtw = getDtwDist();  
            if(dtw<minDtw){  
                minDtw = dtw;  
                minDex = j;  
            }  
              
              
        }  
    /*  System.out.print(minDex);*/  
        System.out.print(MessageFormat.format("匹配程度最高的序号为{0}，距离为{1}", minDex,minDtw));  
        System.out.print("-------");  
          
        for(int l=0;l<listTemp.get(minDex).length;l++){  
            System.out.print(listTemp.get(minDex)[l]+"---");  
        }  
          
          
    }  
    private double computeDistance(int x,int y){  
        return Math.sqrt((x-y)*(x-y));  
          
    }  
    private void initDistance(){//先初始化点与点之间的距离  
        distance = new double[X.length][Y.length];  
        for(int i=0;i<X.length;i++){  
            for(int j =0;j<Y.length;j++){  
                distance[i][j] = computeDistance(X[i],Y[j]);  
                  
            }  
        }  
              
          
    }  
    private void computeDtw(){//初始化dtw数组  
        dtw = new double[X.length][Y.length];  
        initDistance();  
        //根据distance数组来初始化dtw数组  
        dtw[0][0]=0;  
        for(int i=0;i<X.length;i++){  
            for(int j=0;j<Y.length;j++){  
                //这里要对i,j进行判定，其实就是加入边界值的考虑  
                if(i>00&&j>0){  
                    dtw[i][j]=minDist(dtw[i][j-1]+distance[i][j],dtw[i-1][j]+distance[i][j],dtw[i-1][j-1]+2*distance[i][j]);  
                }  
                else if(i==0&&j>0){  
                    dtw[i][j] = dtw[i][j-1]+distance[i][j];  
                }  
                else if(i>0&&j==0){  
                    dtw[i][j]= dtw[i-1][j]+distance[i][j];  
                }else{  
                    dtw[i][j]=0;  
                }  
                  
            }  
        }  
          
    }  
    public double getDtwDist(){  
        computeDtw();  
        return dtw[X.length-1][Y.length-1];  
          
    }  
    private double minDist(double dist1,double dist2,double dist3){  
        return (dist1<dist2?(dist2<dist3?dist3:(dist1>dist3?dist3:dist1)):(dist2>dist3?dist3:dist2));  
          
    }  
      
}