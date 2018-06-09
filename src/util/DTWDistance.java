package util;

public class DTWDistance{ 
	private Long[] test;
	private Long[] signature;
	
	private Long[][] distanceMatrix;
	private Long[][] costMatrix;
	
	public DTWDistance(Long[] signature, Long[] test) {
//		this.test = test;
//		this.signature = signature;
//		//行对应signatu， 列对应test
//		distanceMatrix = new Long[signature.length][test.length];
//		costMatrix = new Long[signature.length][test.length];
		
		setVariable(signature, test);
	}
	
	public DTWDistance() {
	}

	public void setVariable(Long[] signature, Long[] test) {
		this.test = test;
		this.signature = signature;
		//行对应signatu， 列对应test
		distanceMatrix = new Long[signature.length][test.length];
		costMatrix = new Long[signature.length][test.length];
	
	}
	
	private void constructDistanceMatrix() {
		for (int i = 0; i < signature.length; i++) {
			for (int j = 0; j < test.length; j++) {
				distanceMatrix[i][j] = getDistance(signature[i], test[j]);
			}
		}
		return;
	}
	
	public Long getDTWDistance(Long[] sig, Long[] test) {
		setVariable(sig, test);
		constructDistanceMatrix();
		getCostMatrix();
	
		return costMatrix[signature.length-1][test.length-1];
	}
	
	/*
	 * 使用欧式距离（两点间直线距离）
	 */
	private Long getDistance(Long a, Long b) {
		return getAbsDiff(a, b);
	}
	
	public Long getAbsDiff(Long a, Long b) {
		if (a > b) return a - b;
		else return b - a;
	}
	
	public Long getMin(Long a, Long b, Long c) {
		if (a > b) return (b > c) ? c : b;
		else return (a > c) ? c : a;
	}
	
	public void getCostMatrix() {
		int i = 0, j = 0;
		costMatrix[i][j] = distanceMatrix[i][j];
		for (; i < signature.length; i++ ) {
			for (j = 0; j < test.length; j++) {
				if (i == 0 && j == 0) continue;
				if (i == 0) {
					costMatrix[i][j] = costMatrix[i][j-1] + distanceMatrix[i][j];
				} else if (j == 0) {
					costMatrix[i][j] = costMatrix[i-1][j] + distanceMatrix[i][j];
				} else {
					costMatrix[i][j] = getMin(costMatrix[i-1][j-1], costMatrix[i-1][j], costMatrix[i][j-1]) + distanceMatrix[i][j];
				}
				
			}
		}
	}
	
	public static void main(String[] agrs) {
		Long[] aLong = new Long[2];
		Long[] signature = {3l, 5l, 6l, 7l,7l, 1l};
		Long[] test1 = {3l,6l,6l,7l,8l,1l,1l };
		Long[] test2 = {2l,5l,7l,7l,7l,7l,2l};
		
		DTWDistance dwt = new DTWDistance();
		System.out.println(dwt.getDTWDistance(signature, test1));
		
		System.out.println(dwt.getDTWDistance(signature, test2));
	}
}
