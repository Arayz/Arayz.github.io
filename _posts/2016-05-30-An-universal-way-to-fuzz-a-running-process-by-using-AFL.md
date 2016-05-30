---
title: An universal way to fuzz a running process by using AFL
excerpt: "Fuzz a running process by using AFL"
modified: 2016-05-30
tags: [AFL,Fuzz]
category: DR01D-S3C
---

In [AFL on Android](http://arayz.github.io/dr01d-s3c/AFL-on-Android/), I introduced how 
am I porting AFL from Linux to Android. It's certainly that AFL could run on Android as 
it running on Linux, but I ran into a stone wall when I try to fuzz system_server on 
Android, the difficulty is AFL dosen't support for fuzzing an running process officially. 
Android system service dosen't provide any dirrect interface to transact data to its 
bussiness logic. AFL observe and send test cases by forking a subprocess to execute the 
tartget binary file, and system_server boots up in a very earlly time before all zygote 
processes.

An easily-come-up way to solve this problem is editting init.rc to let afl-fuzz boots up 
app_process so that system_server becomes afl-fuzz's subprocess. However, it's difficult to 
put into effect because this is a big change to whole Android system.

One another way is modifying source code of afl-fuzz to transact payload to system services 
instead pipe, this is a feasible scheme but I finally choose a universal way because it's 
better not to modify code of an native program as possible.

I design this as a bridge from afl-fuzz to target process. afl-fuzz execute bridge as 
subprocess and send test cases to it, bridge transact these test cases to target process 
and observe crashes by checking pid of it, bridge send back a signal by raise(SIGKILL) to 
afl-fuzz when target process gets crash. Both bridge and target process need to be instrumented 
by afl-gcc to get fork-server and coverage mesurements on.

A difficult point is that afl-fuzz delivers fd of shared_mem to target process by setenv() 
in native architecture and it takes no effect to whole shell so that target process could 
not receive env of afl-fuzz in the bridge architecture, so a shared file is needed to deliver 
fd of shared_mem.

The architecture is as follows:
![arch](/images/afl_arch.jpg)
