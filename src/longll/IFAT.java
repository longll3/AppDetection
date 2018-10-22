package longll;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

import DrawFigure.BarChart;
import structure.IEEE80211ManagementFrame;


public class IFAT {
	private ArrayList<IEEE80211ManagementFrame> timeArray; //时间单位为us，微妙,{时间戳、源地址、目的地址}数组
	
	private ArrayList<Long> timeDifferenceArray; //时间单位为us，微妙， 每两个帧之间的时间差
	
	private static int DIFFERENCE = 1000; // 10ms
	private static int BIN_SIZE = 1000; //以10000us(10ms)为单位create bin
	
	private Map<Long, ArrayList<Long>> bin_set;
	
	public ArrayList<IEEE80211ManagementFrame> getTimeArray() {
		return timeArray;
	}

	public IFAT() {
		bin_set = new HashMap<Long, ArrayList<Long>>();
	}

	public void setTimeArray(ArrayList<IEEE80211ManagementFrame> timeArray) {
		this.timeArray = timeArray;
	}

	public void process(String title) {
		int len = timeArray.size();
		timeDifferenceArray = new ArrayList<>(len-1);
		
		int burst_count = 0;
		String last_mac = null;
		long min_inter_burst_time_difference = 0;
		
		//根据bin给IFAT分发进不同的bin
		for (int i = 1; i < len; i++) {
			System.out.println("seq num: "+timeArray.get(i).getSeq_num());
			
//			System.out.print("["+(i+1)+"-"+(i+2)+"]: ");
			
			Long difference = timeArray.get(i).getTimestamp() -timeArray.get(i-1).getTimestamp();
			
			
			
			//判断是否属于同一个burst,IFAT小于10ms的为一个burst,事实证明，几乎没有在10ms以内的ifat！
			if (difference < Long.MAX_VALUE) {
				System.out.println("time difference: "+difference);
				timeDifferenceArray.add(difference);
//				continue;
			}
			
			//判断是否属于同一个判断是否是用同一个MAC地址发送的，即同一burst
			
			
			
			if (i == 1) {
				//是第一个时间差
				last_mac = timeArray.get(i-1).getSr_mac();
			}
			
			if (timeArray.get(i).getSr_mac().equals(last_mac)) {
				//属于同一个burst
				if (bin_set.containsKey(difference/BIN_SIZE)) {
					bin_set.get(difference/BIN_SIZE).add(difference);
				} else {
					ArrayList<Long> arr = new ArrayList<>();
					arr.add(difference);
					bin_set.put((difference/BIN_SIZE), arr);
				}
				
				last_mac = timeArray.get(i).getSr_mac();
			} else {
				
				
				burst_count++;
				//重新开始的一个burst
				last_mac = timeArray.get(i).getSr_mac();
				System.out.println(burst_count+": "+difference);
				
				min_inter_burst_time_difference += difference;
				
				continue;
			}
			
//			System.out.println(difference.toString());
		}
		
//		System.out.println(bin_set);
		//System.out.println(min_inter_burst_time_difference/burst_count);
		generateFigure(title);
		
		
	}
	
	/**
	 * 根据帧的序列号判断是否属于同一组
	 * @param title 生成的图的标题
	 */
	public void process_by_IFAT( String title) {
		int last_seq_num = 0;
		timeDifferenceArray = new ArrayList<>(timeArray.size()-1);
		for (int i = 0; i < timeArray.size(); i++) {
			if (i == 0) {
				last_seq_num = timeArray.get(i).getSeq_num();
				continue;
			}
			
			long difference = timeArray.get(i).getTimestamp() - timeArray.get(i-1).getTimestamp();
			System.out.println("No." + i + " and the difference is :" + difference);
			
			int previous_seq_num = timeArray.get(i).getSeq_num();
			//如果是连续的两帧
			if ((previous_seq_num == last_seq_num + 1) && difference > 0) {
				//两帧的MAC地址需相同
				if (timeArray.get(i).getSr_mac().equals(timeArray.get(i-1).getSr_mac())) {
					timeDifferenceArray.add(difference/DIFFERENCE);
					System.out.println("last: "+ last_seq_num+"~previous: "+previous_seq_num);
					System.out.println(difference/BIN_SIZE);
					
					if (bin_set.containsKey(difference/BIN_SIZE)) {
						bin_set.get(difference/BIN_SIZE).add(difference);
					} else {
						ArrayList<Long> arr = new ArrayList<>();
						arr.add(difference);
						bin_set.put((difference/BIN_SIZE), arr);
					}
				}
			}
				
			last_seq_num = previous_seq_num;
			
		}
		
		generateFigure(title);
		
			
	}
	
	public void generateFigure(String title) {
//		BarChart barChart1 = new BarChart("IFAT attack", "iPhone7 plus 帧间时间差统计", bin_set);
//		BarChart barChart1 = new BarChart("IFAT attack", "iPhone6s 帧间时间差统计", bin_set);
//		BarChart barChart1 = new BarChart("IFAT attack", "Samsung Galaxy C7 Pro 帧间时间差统计", bin_set);
//		BarChart barChart1 = new BarChart("IFAT attack", "Samsung Galaxy S7 edge 帧间时间差统计", bin_set);
//		BarChart barChart1 = new BarChart("IFAT attack", "Samsung Galaxy S8 edge 帧间时间差统计", bin_set);
		BarChart barChart1 = new BarChart("IFAT attack", title+"帧间时间差统计", bin_set);
		barChart1.pack( );
		RefineryUtilities.centerFrameOnScreen( barChart1 );  
		barChart1.setVisible( true ); 
		
//		System.out.println(timeDifferenceArray);
		
//		BarChart barChart2 = new BarChart("IFAT attack", "iPhone7 plus", timeDifferenceArray);
//		BarChart barChart2 = new BarChart("IFAT attack", "iPhone6s", timeDifferenceArray);
//		BarChart barChart2 = new BarChart("IFAT attack", "Samsung Galaxy C7 Pro", timeDifferenceArray);
//		BarChart barChart2 = new BarChart("IFAT attack", "Samsung Galaxy S7 edge", timeDifferenceArray);
//		BarChart barChart2 = new BarChart("IFAT attack", "Samsung Galaxy S8 edge", timeDifferenceArray);
		BarChart barChart2 = new BarChart("IFAT attack", title, timeDifferenceArray);

		barChart2.pack( );
		RefineryUtilities.centerFrameOnScreen( barChart2 );  
		barChart2.setVisible( true ); 
		      
              
        
	}
	
}

