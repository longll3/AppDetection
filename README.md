# AppDetection
- detect app through ethernet package from a mobile phone
- identify a brand for an unkonw phone by analyze the IFAT of probe request frames from one phone
- identify an unknow phone which using random MAC addresses by ite information elements and sequence number

---

2018.9.8
### ADDING IFAT IN MAC DEFEATING
在识别使用随机mac地址的终端时，加入IFAT签名距离。

2018.9.9

在识别时，先通过mac地址判断一次，找不到再进入用序列号判断，再不成功则用IFAT签名距离。

对“/Users/longlong/Documents/周报/研一下学期/ifat实验/packets/honor10-2.pcap”的实验结果如下：

![实验结果1](/Users/longlong/Desktop/实验数据截图/WX20180910-095624.png)

可以看出，对于honor10终端的区分行不是很好，且将很多其他使用真实MAC地址的终端也归为honor的某些随机地址为一类了。

####2018.9.10
打算采用加权平均的方式
但是分数的计算方式还没有想好

####2018.9.18

Identify patent topic，around *IE*
---

- 今天在生成各个品牌的签名的时候，第一次遇到了outOfMemory的问题。但是读入的文件没有一个超过1M的，于是去idea/bin目录下的idea.vmoptions去查看jvm的最大堆和最小堆大小，-Xms是最小堆，是128m，-Xmx是最大堆，是750m，不可能因为文件太大而溢出。
- 于是回到代码中，

```java

for (DeviceMap device : DeviceMap.values()) {
			for (String fileName : device.getFileNames()) {
//				System.out.println(fileName+" parser前的内存："+(run.freeMemory()));

				IEEE80211Parser r = new IEEE80211Parser();

				r.setFile(new File(path+fileName));
//				System.out.println(fileName+" setFile后的内存："+(run.freeMemory()));
				r.parse();

//				System.out.println(fileName+" parser后的内存："+(run.freeMemory()));
				SignatureForIE sig = new SignatureForIE();
				for (IEEE80211ManagementFrame frame : r.getTimeArray()) {
					sig.updateSignature(frame.getIEs());
				}
				this.sigs.put(device.getDeviceName(), sig);
			}

		}

```
异常位于```r.parse();```中，于是使用```Runtime run = Runtime.getRuntime();
//		System.out.println(run.freeMemory());```查看内存，发现所有文件都正常，除了“mi4.pcap”，于是尝试将该文件的头200条另存为mi4-1-200.pcap，果然就没有溢出了。
然后定位到```r.parse();```函数题中的错误，```byte content[] = new byte[dataHeader.getCaplen()];```，问题出在这一行，将出错时的```dataHeader.getCaplen()```输出发现会有一个超过2000000000的值，也就是要读进超过2g的内容，所以内存溢出了。
		

#### 2018.9.21

---

对于手里所有的终端都进行了实验，要注意的一点是：IE中的SSID不应作为匹配元素，因为该值是终端的特有属性，因此因掠过其的比较。
但是iPhone7p和华为Pad的准确率低于正常水平，都低于了50%。还需要再研究一下。

2018.9.23

- iPhone7p准确率低的原因是因为测试数据中前半段是未连接状态，后半段是连接状态。连接上会有2个信息元素的值发生改变，具体请见周报3。但幸运的是在第一次使用真是mac地址建立连接时的信息元素与未连接时的信息元素是一样的。因此在采集时需注意是未连接状态。
- 华为pad是因为签名数据集覆盖面不够大，数据是上个学期使用的，命名时没有 **_有效命名_**，导致对每个文件到底是什么情况有点模糊了，以后也要记住， *_对每份实验数据标记备注清楚_*。

---
2018.11.19

在形成签名后，对签名进行归一化，目的是使得阈值比较号确定。因为不同设备的IFAT的数量级不同，导致最短距离的数量级也不同，因此阈值难以评判选定。
但是在加入了归一化之后，对于准确率的提升没有任何帮助，反而会降低准确率，这又是因为归一化其实只是展现了一个数列基于最大值和最小值的分布情况，所以会使得准确率**不增反降**。

