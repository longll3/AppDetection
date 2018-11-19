package signature;

import java.util.*;

public class SigForIE implements SigControl {

	private Map<Integer, ArrayList<byte[]>> signature;


	public SigForIE(Map<Integer, byte[]> IE) {
		signature = new HashMap<>();
		add(IE);
	}

	public SigForIE() {
		signature = new HashMap<>();
	}

	public void add(Map<Integer, byte[]> ie) {
		if (signature.size() == 0) {
			for (Map.Entry<Integer, byte[]> entry : ie.entrySet()) {
				ArrayList<byte[]> arr = new ArrayList();
				arr.add(entry.getValue());
				signature.put(entry.getKey(), arr);
			}

		} else {
			for (Map.Entry<Integer, byte[]> entry : ie.entrySet()) {
				ArrayList<byte[]> arr = signature.get(entry.getKey());

				if (arr == null) {
					System.out.println("the signature does not have this IE");
					return;
				}

				byte[] ori = entry.getValue();
				boolean flag = true;
				for (int i = 0; i < arr.size(); i++) {
					flag = true;
					byte[] a = arr.get(i);
					if (a.length != ori.length) {
						System.err.println("a.length != ori.length");
					}
					for (int j =0 ; j < a.length; j++) {
						if (ori[j] != a[j]) {
							flag = false;
						}
					}
					if (flag == true) {
						break;
					}
				}
				if (flag == false) {
					arr.add(ori);
				}
			}
		}
	}

	@Override
	public void updateSignature(Figure fig) {
		Map<Integer, byte[]> ie = extractSignature(fig);
		add(ie);
	}

	@Override
	public boolean isBelongToTheType(Figure fig) {
		for (Map.Entry<Integer, byte[]> entry : fig.getIEMap().entrySet()) {
			ArrayList<byte[]> arr = signature.get(entry.getKey());

			if (arr == null) return false;

			byte[] ori = entry.getValue();
			boolean flag = true;
			for (int i = 0; i < arr.size(); i++) {
				flag = true;
				byte[] a = arr.get(i);
				for (int j =0 ; j < a.length; j++) {
					if (ori[j] != a[j]) {
						return false;
					}
				}
			}
		}

		return true;
	}


	public Map<Integer, byte[]> extractSignature(Figure fig) {
		Map<Integer, byte[]> IE = fig.getIEMap();
		Map<Integer, byte[]> element = new HashMap<>();
		for (Map.Entry<Integer, byte[]> entry : IE.entrySet()) {
			if (entry.getKey() == 0) {
				//ignore ssid information
				continue;
			}

			if (entry.getKey() == 221) {
				//ignore vendor information
				continue;
			}
			element.put(entry.getKey(), entry.getValue());
		}
		return element;
	}


}
