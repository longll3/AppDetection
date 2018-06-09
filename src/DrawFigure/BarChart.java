package DrawFigure;

import java.awt.Color;
import java.awt.Font;
import java.awt.image.TileObserver;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.jfree.chart.ChartFactory;
import org.jfree.chart.ChartPanel;
import org.jfree.chart.JFreeChart;
import org.jfree.chart.axis.AxisLabelLocation;
import org.jfree.chart.axis.CategoryAxis;
import org.jfree.chart.axis.CategoryLabelPositions;
import org.jfree.chart.axis.NumberAxis;
import org.jfree.chart.axis.ValueAxis;
import org.jfree.chart.labels.IntervalXYItemLabelGenerator;
import org.jfree.chart.labels.StandardCategoryItemLabelGenerator;
import org.jfree.chart.plot.CategoryPlot;
import org.jfree.chart.plot.PlotOrientation;
import org.jfree.chart.renderer.category.BarRenderer;
import org.jfree.chart.title.TextTitle;
import org.jfree.data.category.CategoryDataset;
import org.jfree.data.category.DefaultCategoryDataset;
import org.jfree.ui.ApplicationFrame;
import org.jfree.ui.RefineryUtilities;

import com.sun.org.apache.xpath.internal.operations.Bool;
import com.sun.xml.internal.bind.v2.runtime.unmarshaller.XsiNilLoader.Array;

import apple.laf.JRSUIUtils.Tree;
import longll.Signature;
import structure.IEEE80211ManagementFrame;
import sun.print.resources.serviceui;


public class BarChart extends ApplicationFrame{
	ChartPanel frame1; 
//	CategoryDataset dataset;
	JFreeChart barChart;
	
    public  BarChart(String applicationTitle , String chartTitle, Map<Long, ArrayList<Long>> bin_set){  
    		super( applicationTitle );
	    barChart = ChartFactory.createBarChart(
	    			chartTitle,           
	    		    "帧间到达时间差(单位：10ms)", //横坐标            
	    		    "帧数", //纵坐标        
	    		    createDataset(bin_set),          
	    		    PlotOrientation.VERTICAL, // 图标方向   
                true, // 是否显示legend   
                true, // 是否显示tooltips   
                false); // 是否显示URLs  
	    setProperties(true);
    }
    
    public  BarChart(String applicationTitle , String chartTitle, Set<ArrayList<Long>> burstSet){  
		super( applicationTitle );
	    barChart = ChartFactory.createBarChart(
	    			chartTitle,           
	    		    "burst", //横坐标            
	    		    "burst中的帧数", //纵坐标        
	    		    createDataset(burstSet),          
	    		    PlotOrientation.VERTICAL, // 图标方向   
	            true, // 是否显示legend   
	            true, // 是否显示tooltips   
	            false); // 是否显示URLs  
	    setProperties(true);
}
    
    private CategoryDataset createDataset(Set<ArrayList<Long>> burstSet) {
		DefaultCategoryDataset dataset = new DefaultCategoryDataset();
		int i = 1;
		for (ArrayList<Long> item : burstSet) {
			dataset.addValue((int)(item.size()), "", new Integer(i).toString());
			i++;
		}
		
		return dataset;
	}

	public BarChart(String applicationTitle, String chartTitle, ArrayList<Long> timeDifferenceArray) {
	    	super( applicationTitle );
	    	barChart = ChartFactory.createBarChart(
	    			chartTitle,           
	    		    "帧序号",            
	    		    "与上一帧的时间差(单位：us)",            
	    		    createDataset(timeDifferenceArray),          
	    		    PlotOrientation.VERTICAL,           
	    		    true, true, false);
	    	 setProperties(false);
	}
    
    public  BarChart(String applicationTitle , String chartTitle, Signature sig1, Signature sig2, int flag_p_m, String rowTable, String colTable){  
		super( applicationTitle );
	    barChart = ChartFactory.createBarChart(
	    			chartTitle,           
	    		    rowTable, //横坐标            
	    		    colTable, //纵坐标        
	    		    createDataset_p_m(sig1, sig2, flag_p_m),          
	    		    PlotOrientation.VERTICAL, // 图标方向   
	            true, // 是否显示legend   
	            true, // 是否显示tooltips   
	            false); // 是否显示URLs  
	    setProperties(true);
	}
    
//    public BarChart(String applicationTitle , String chartTitle, Set<ArrayList<IEEE80211ManagementFrame>> set,  String rowTable, String colTable) {
//	    	super( applicationTitle );
//		    barChart = ChartFactory.createBarChart(
//		    			chartTitle,           
//		    		    rowTable, //横坐标            
//		    		    colTable, //纵坐标        
//		    		    createDataset(set),          
//		    		    PlotOrientation.VERTICAL, // 图标方向   
//		            true, // 是否显示legend   
//		            true, // 是否显示tooltips   
//		            false); // 是否显示URLs  
//		    setProperties(true);
//    }
    
    public BarChart(String applicationTitle, String chartTitle, Signature signature) {
		super(applicationTitle);
		barChart = ChartFactory.createBarChart(
    			chartTitle,           
    		    "bin中的均值", //横坐标            
    		    "bin中帧数所占百分比", //纵坐标        
    		    createDataset(signature),          
    		    PlotOrientation.VERTICAL, // 图标方向   
            true, // 是否显示legend   
            true, // 是否显示tooltips   
            false); // 是否显示URLs  
    setProperties(true);
		
	}

	public BarChart(String applicationTitle, String chartTitle, Double[] distance_list, String rowTitile, String colTitiel, boolean flag) {
		super(applicationTitle);
		barChart = ChartFactory.createBarChart(
    			chartTitle,           
    		    rowTitile, //横坐标            
    		    colTitiel, //纵坐标        
    		    createDatasetByDoubleList(distance_list),          
    		    PlotOrientation.VERTICAL, // 图标方向   
            true, // 是否显示legend   
            true, // 是否显示tooltips   
            false); // 是否显示URLs  
    setProperties(flag);
	}

	public BarChart(String applicationTitle, String chartTitle, int[] burstSizeArr) {
		super(applicationTitle);
		barChart = ChartFactory.createBarChart(
    			chartTitle,           
    			"burst", //横坐标            
    		    "burst中的帧数", //纵坐标     
    		    createDatasetByIntList(burstSizeArr),          
    		    PlotOrientation.VERTICAL, // 图标方向   
            true, // 是否显示legend   
            true, // 是否显示tooltips   
            false); // 是否显示URLs  
		setProperties(true);
	}

	private CategoryDataset createDatasetByIntList(int[] burstSizeArr) {
		final DefaultCategoryDataset dataset = new DefaultCategoryDataset();
			
			for (int i = 0; i < burstSizeArr.length; i++) {
				dataset.addValue(burstSizeArr[i], "", new Integer(i).toString());
			}
		
		return dataset;
	}

	private CategoryDataset createDatasetByDoubleList(Double[] distance_list) {
		final DefaultCategoryDataset dataset = new DefaultCategoryDataset();
		
		for (int i = 0; i < distance_list.length; i++) {
			dataset.addValue(distance_list[i], "", new Integer(i).toString());
		}
		
		return dataset;
	}

	private CategoryDataset createDataset(Signature signature) {
		final DefaultCategoryDataset dataset = new DefaultCategoryDataset();
		Map<Long, Double> mean_map = signature.getMean();
		Map<Long, Double> perc_map = signature.getPercentege();
		Set<Long> key_set = perc_map.keySet();
		
		
		for (Long key : key_set) {
			dataset.addValue(perc_map.get(key), "", mean_map.get(key));
		}
		
		return dataset;
	}

	private void setProperties(boolean show_data_on_bar) {
    		//图表标题设置  
	    TextTitle mTextTitle = barChart.getTitle();  
	    mTextTitle.setFont(new Font("黑体",Font.BOLD, 20));
	    
	    CategoryPlot categoryPlot = barChart.getCategoryPlot();
	    categoryPlot.setBackgroundPaint(Color.WHITE); //背景色
	    categoryPlot.setDomainGridlinePaint(Color.GRAY); // 背景网格线中竖线的颜色
	    categoryPlot.setDomainGridlinesVisible(false);
	    categoryPlot.setRangeGridlinePaint(Color.GRAY); //背景网格线中横线的颜色
	    categoryPlot.setRangeGridlinesVisible(true);
	    
	    BarRenderer renderer = new BarRenderer();
	    renderer.setBaseItemLabelPaint(Color.BLACK);
	    
	    // 获取纵坐标  
        NumberAxis numberaxis = (NumberAxis) categoryPlot.getRangeAxis();  
          
        // 设置纵坐标的标题字体和大小  
        numberaxis.setLabelFont(new Font("黑体", Font.CENTER_BASELINE, 16));  
        // 设置丛坐标的坐标值的字体颜色  
        numberaxis.setLabelPaint(Color.BLACK);  
        // 设置丛坐标的坐标轴标尺颜色  
        numberaxis.setTickLabelPaint(Color.BLACK);  
        // 坐标轴标尺颜色  
        numberaxis.setTickMarkPaint(Color.BLUE);  
        // 丛坐标的默认间距值  
        // numberaxis.setAutoTickUnitSelection(true);  
        // 设置丛坐标间距值  
        numberaxis.setAutoTickUnitSelection(true);  
        // numberaxis.setTickUnit(new NumberTickUnit(150)); 
	    
        if (show_data_on_bar) {
//          在柱体的上面显示数据   
            BarRenderer custombarrenderer3d = new BarRenderer();   
            custombarrenderer3d.setBaseItemLabelPaint(Color.BLACK);//数据字体的颜色   
            custombarrenderer3d.setBaseItemLabelGenerator(new StandardCategoryItemLabelGenerator());   
            custombarrenderer3d.setBaseItemLabelsVisible(true);
            // 每个BAR之间的间隔  
            custombarrenderer3d.setItemMargin(0.5f);
            categoryPlot.setRenderer(custombarrenderer3d);
        }

	    
        // 获取横坐标  
        CategoryAxis domainAxis = categoryPlot.getDomainAxis();  
        // 设置横坐标的标题字体和大小  
        domainAxis.setLabelFont(new Font("宋体", Font.CENTER_BASELINE, 14));
//        domainAxis.setLabelFont(new java.awt.Font("黑体", java.awt.Font.CENTER_BASELINE, 20));
        // 设置横坐标的坐标值的字体颜色  
        domainAxis.setTickLabelPaint(Color.GRAY);  
        // 设置横坐标的坐标值的字体  
        domainAxis.setTickLabelFont(new Font("宋体", Font.PLAIN, 10));  
//        // 设置横坐标的显示  
//        domainAxis.setLabelAngle(HIDE_ON_CLOSE);
//        domainAxis.setCategoryLabelPositions(CategoryLabelPositions.UP_45);
        //分类轴下（左）边距,就是离左边的距离
//        domainAxis.setLowerMargin(0.1);
      //分类轴下（右）边距,就是离最右边的距离  
//        domainAxis.setUpperMargin(0.1);
        // 这句代码解决了底部汉字乱码的问题  
//      chart.getLegend().setItemFont(new Font("黑体", 0, 16)); 
        
        
//        // 设置图例标题  
//        Font font = new java.awt.Font("黑体", java.awt.Font.CENTER_BASELINE, 20);  
//        TextTitle title = new TextTitle("谁是评论你最多的人？");  
//        title.getBackgroundPaint();  
//        title.setFont(font);  
//        // 设置标题的字体颜色  
        
	    	ChartPanel chartPanel = new ChartPanel( barChart );        
	    chartPanel.setPreferredSize(new java.awt.Dimension( 800 , 600 ) );        
	    setContentPane( chartPanel ); 
    }

    private CategoryDataset createDataset_p_m(Signature origin, Signature test, int flag_p_m) {
    		final DefaultCategoryDataset dataset = new DefaultCategoryDataset();
    		
    		Set<Long> keys = origin.getMean().keySet();
    		Long[] key_arr = keys.toArray(new Long[0]);
    		
    		if (flag_p_m == 0) {
    			//mean
    			for (Long key: key_arr) {
        			double size1, size2;
        			size1 = origin.getMean().get(key);
        			if (test.getMean().containsKey(key)) {
        				size2 = test.getMean().get(key); 
        			} else {
        				size2 = 0;
        			}
        			
        			dataset.addValue(size1, "origin", key);
        			dataset.addValue(size2, "test", key);
        		}
    		} else {
    			for (Long key: key_arr) {
    				double size1, size2;
    				size1 = origin.getPercentege().get(key);
    				if (test.getPercentege().containsKey(key)) {
    					size2 = test.getPercentege().get(key); 
    				} else {
    					size2 = 0;
    				}
    				
    				dataset.addValue(size1, "origin", key);
    				dataset.addValue(size2, "test", key);
    			}
    		}
    		return dataset;
    		
    }
    
//    private CategoryDataset createDataset(Set<ArrayList<IEEE80211ManagementFrame>> set) {
//    		DefaultCategoryDataset dataset = new DefaultCategoryDataset();
//    		int i = 1;
//    		for (ArrayList<IEEE80211ManagementFrame> item : set) {
//    			dataset.addValue((int)(item.size()), "", new Integer(i).toString());
//    			i++;
//    		}
//    		
//    		return dataset;
//    		
//	}
    
	private CategoryDataset createDataset(Map<Long, ArrayList<Long>> bin_set) {
    		
        final DefaultCategoryDataset dataset = 
        new DefaultCategoryDataset( );
        
        Set<Long> keys = bin_set.keySet();
        Long[] key_array = keys.toArray(new Long[0]);
        
        Arrays.sort(key_array); //升序排序
        
        for (int i = 0; i < keys.size(); i++) {
        		int size = bin_set.get(key_array[i]).size();
        		dataset.addValue(size, "", key_array[i]);
        }              

        return dataset; 
     }
    
    private CategoryDataset createDataset(ArrayList<Long> timeDifferenceArray) {
    		final DefaultCategoryDataset dataset = new DefaultCategoryDataset( );
    		
    		for (int i = 0 ; i< timeDifferenceArray.size(); i++) {
//    			if (timeDifferenceArray.get(i) >= 361) {
//    				continue;
//    			}
    			dataset.addValue((timeDifferenceArray.get(i)), "", new Integer(i+1).toString());
    		}
    		
		return dataset;
    	
    }
    
    public JFreeChart createBarChart(CategoryDataset dataset, String title) {
	    	JFreeChart chart = ChartFactory.createBarChart(title, // chart title   
	                "Category", // domain axis label   
	                "Value", // range axis label   
	                dataset, // data   
	                PlotOrientation.VERTICAL, // 图标方向   
	                true, // 是否显示legend   
	                true, // 是否显示tooltips   
	                false // 是否显示URLs   
	        );   
	    return chart; 
	}
    
    
//    public static void main( String[ ] args ) {
//    		Map<Long, ArrayList<Long>> bin_set = new HashMap<>();
//    		BarChart chart = new BarChart("Car Usage Statistics", 
//           "Which car do you like?", bin_set);
//        chart.pack( );        
//        RefineryUtilities.centerFrameOnScreen( chart );        
//        chart.setVisible( true ); 
//     }
}

