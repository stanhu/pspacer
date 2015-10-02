Write Performance of ext4 filesystem on ioDrive duo

My PC box has dual Intel Xeon W5590 3.33~GHz (8 cores), 48 GB memory, and Fusion-io ioDriveDuo (320 GB SLC). The CentOS 5.4 and the Linux kernel is 2.6.16-164.15.1.el5 are running on the box.

I have measured the random write performance on several filesystems using fio benchmark (http://freshmeat.net/projects/fio/).

The XFS performance grows as the number of thread increases.  On the other hands, the ext3 and the ext4 do not. In the both cases, I mount filesystems with the "noatime" option only.

The results are shown below:

| **block size** | **XFS (1thr)** | **XFS (8thr)** | **ext4 (1thr)** | **ext4 (8thr)** |
|:---------------|:---------------|:---------------|:----------------|:----------------|
|1024            |20.943          |71.287          |21.563           |20.886           |
|2048            |40.130          |144             |42.063           |40.448           |
|4096            |73.668          |290             |75.598           |76.356           |
|8192            |131             |635             |133              |131              |
|16384           |212             |1029            |219              |215              |
|32768           |310             |1169            |326              |316              |
|65536           |399             |1236            |374              |374              |
|131072          |748             |1332            |718              |676              |
|262144          |895             |1336            |902              |804              |
|524288          |1000            |1327            |974              |905              |
|1048576         |1100            |1308            |1136             |995              |
|2097152         |1220            |1276            |1179             |1082             |
|4194304         |1230            |1233            |1270             |1149             |
|8388608         |1309            |1233            |1243             |1188             |

(The unit is MB/s.)

The question I have is what is the cause of the ext4 performance limitation.

### ext4 random write bandwidth ###
![http://pspacer.googlecode.com/svn/wiki/images/fio-ext4-write.png](http://pspacer.googlecode.com/svn/wiki/images/fio-ext4-write.png)

### XFS random write bandwidth ###
![http://pspacer.googlecode.com/svn/wiki/images/fio-xfs-write.png](http://pspacer.googlecode.com/svn/wiki/images/fio-xfs-write.png)

## Test script ##
```
for nj in 1 2 4 8 16 32; do
	fn="/mnt/raid_fs/test"
	param="--filename=/mnt/test --direct=1 --invalidate=1 --iodepth=1 --size=5g  --name=fio --numjobs=${nj} --runtime=30 --group_reporting"

	bn=randread
	for i in 1k 2k 4k 8k 16k 32k 64k 128k 256k 512k 1m 2m 4m 8m; do
		fio --rw=randread --bs=${i} ${param} 2>&1 > $LOG/${bn}_${nj}_${i}.txt
	done
done
```