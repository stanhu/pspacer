Problem of OCZ Z-Drive p84 read performance

# Summary #

I installed OCZ Z-Drive p84 into my Linux box.  I am using mptsas driver instead of the official binary driver
(megasar).  I ran two benchmark programs; bonnie++ and dd.  The results show the throughput
of sequential read achieves 260 MB/s, which is the half of write performance (520 MB/s).

I have not yet tried to work on Windows OS.

What is the bottleneck of read performance?

Any comments and suggestions will be welcome.

# Experiment #

## Experimental setting ##
My PC consists of two Intel Quad-core Xeon E5430 2.66~GHz, Intel 5100 chipset,
4 GB memory (DDR2-667), and OCZ Z-Drive p84 (256 GB MLC),
which plugged into a PCI-Express x8 lane.
The PC is running the Ubuntu 9.10 server edition and the Linux kernel is 2.6.31-14-server.
The version of mptsas driver is 3.04.10.  Z-Drive is formated with the ext3 file system.

## Experimental result 1 ##
### dd on ext3 without direct I/O (default) ###

| **block size** | **seq. write (MB/s)** | **seq. read (MB/s)** |
|:---------------|:----------------------|:---------------------|
|1024	           |201	                   |241                   |
|4096	           |472	                   |262                   |
|16384	          |486	                   |267                   |
|65536	          |502	                   |266                   |
|262144	         |472	                   |259                   |
|524288	         |525	                   |251                   |
|1048576	        |528	                   |245                   |
|2097152	        |517	                   |253                   |
|4194304	        |433	                   |247                   |
|8388608	        |406	                   |246                   |
|16777216	       |405	                   |243                   |
|33554432	       |405	                   |242                   |
|67108864	       |405	                   |242                   |

![http://pspacer.googlecode.com/svn/wiki/images/p84.dd.png](http://pspacer.googlecode.com/svn/wiki/images/p84.dd.png)

### dd on ext3 with direct I/O ###
Both option iflag=direct and oflag=direct are specified.

| **block size** | **seq. write (MB/s)** | **seq. read (MB/s)** |
|:---------------|:----------------------|:---------------------|
|1024	           |9.5	                   |9.7	                  |
|4096	           |34.4	                  |28.3	                 |
|16384	          |95.8	                  |47.0	                 |
|65536	          |186	                   |121	                  |
|262144	         |382	                   |307	                  |
|524288	         |417	                   |366	                  |
|1048576	        |449	                   |380	                  |
|2097152	        |497	                   |467	                  |
|4194304	        |511	                   |532	                  |
|8388608	        |498	                   |560                   |
|16777216	       |523	                   |545	                  |
|33554432	       |555	                   |541	                  |
|67108864	       |554	                   |543	                  |

![http://pspacer.googlecode.com/svn/wiki/images/p84.dd.direct.png](http://pspacer.googlecode.com/svn/wiki/images/p84.dd.direct.png)

### dd on btrfs without direct I/O ###
I tried btrfs with SSD mode, and I got better performance compared with ext3.

| **block size** | **seq. write (MB/s)** | **seq. read (MB/s)** |
|:---------------|:----------------------|:---------------------|
|1024            |162                    |583                   |
|4096            |427                    |603                   |
|16384           |579                    |608                   |
|65536           |604                    |610                   |
|262144          |604                    |610                   |
|524288          |611                    |611                   |
|1048576         |605                    |611                   |
|2097152         |612                    |605                   |
|4194304         |604                    |589                   |
|8388608         |598                    |587                   |
|16777216        |598                    |588                   |
|33554432        |599                    |584                   |
|67108864        |591                    |585                   |

![http://pspacer.googlecode.com/svn/wiki/images/p84.dd.btrfs.2.png](http://pspacer.googlecode.com/svn/wiki/images/p84.dd.btrfs.2.png)

## Experimental result 2 ##
In previous experiment, the read performance is constant, however the write performance gradually decreases due to continued usage (read & write), as shown in Figure 4.  It is an effect of buffer cache.

NOTE: The physical memory size is upgraded from 4GB to 8GB.

![http://pspacer.googlecode.com/svn/wiki/images/p84.aging.btrfs.png](http://pspacer.googlecode.com/svn/wiki/images/p84.aging.btrfs.png)

I retried dd with bs=1000000 count=16000.

![http://pspacer.googlecode.com/svn/wiki/images/p84.aging.btrfs.2.png](http://pspacer.googlecode.com/svn/wiki/images/p84.aging.btrfs.2.png)

## Test script ##
This script assumes the target drive is /dev/sdb1 and it is mounted on /media/test.

```
#!/bin/bash

BS=$((1024))
COUNT=$((1024*1024*10))

for i in 1 4 16 64 256 512 1024 2048 4096 8192 16384 32768 65536; do
        bs=$((BS * i))
        count=$((COUNT / i))

        echo bs=$bs count=$count
        sudo mount /dev/sdb1 /media/test
        dd if=/dev/zero of=/media/test/foo bs=$bs count=$count
        sudo umount /media/test
        sleep 1
        sudo mount /dev/sdb1 /media/test
        dd if=/media/test/foo of=/dev/null bs=$bs count=$count
        rm /media/test/foo
        sudo umount /media/test
done
```

# Related Links #
  * [OCZ Z-Drive p84 PCI-Express SSD](http://www.ocztechnology.com/products/solid_state_drives/ocz_z_drive_p84_pci_express_ssd) (OCZ)