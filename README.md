# AppDetection
- detect app through ethernet package from a mobile phone
- identify a brand for an unkonw phone by analyze the IFAT of probe request frames from one phone
- identify an unknow phone which using random MAC addresses by ite information elements and sequence number

---

2018.9.8
# ADDING IFAT IN MAC DEFEATING
在识别使用随机mac地址的终端时，加入IFAT签名距离。

2018.9.9

在识别时，先通过mac地址判断一次，找不到再进入用序列号判断，再不成功则用IFAT签名距离。

对“/Users/longlong/Documents/周报/研一下学期/ifat实验/packets/honor10-2.pcap”的实验结果如下：

![实验结果1](/Users/longlong/Desktop/实验数据截图/WX20180910-095624.png)

可以看出，对于honor10终端的区分行不是很好，且将很多其他使用真实MAC地址的终端也归为honor的某些随机地址为一类了。

2018.9.10
打算采用加权平均的方式
但是分数的计算方式还没有想好





