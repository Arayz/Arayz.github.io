---
title: AFL on Android
excerpt: "Porting AFL to Android"
modified: 2016-05-08
tags: [AFL,fuzz,porting]
category: CH402
---

AFL(American Fuzzy Lop) is a powerful fuzzer for binary on Linux, it employs 
genetic algorithms to discover interesting signals in runtime, but it doesn'
support for running on Android officially, so I just work to porting AFL to
Android and get afl-fuzz running on emulator with arch-x86.

In order to porting completly, I have to cross compile afl-fuzz with bionic 
and use afl-gcc to instrument the binary I want to fuzz to get fork server 
and coverage measurements on. 

Compiling afl-fuzz is much easier than instrumening the binary, just put whole 
source folder to "(AOSP)/development/" and execute "mm" on the path with an 
Android.mk in it, but if you do so, you will just get some errors. The key 
problem is expecting shm on bionic, Android use ashmem to replace shm, so you 
need to use ashmem_create_region to create fd instead shmget, and just mmap 
the address instead shmat, when work is done, just munmap it instead shmctl.
Another one thing you need to do is to comment the termminal size check in the 
afl-fuzz.c, or the UI won't appear as normal.  

The bigger challenge of porting AFL is instrumenting target binary. AFL's 
documents tell me to set CC and CXX env to replace compiler but AOSP use cross 
compile toolchains and the makefile is so complicated. By reading afl-gcc.c, 
I found it just set some params to replace assembler to instrument instructions, 
and deliver remaining work to the original compiler when instumenting work is 
done, so I could just replace the original compiler and point the cross compile 
toolchain to get binary instrumented and cross compiled.The flow diagram is as follows:

![flow-diagram](/images/flow-diagram.jpg)

To replace compiler, just add LOCAL_CXX and LOCAL_CC to your afl-gcc in Android.mk,
set AFL_CXX, AFL_CC and AFL_AS to your AOSP cross compile toolchain. After that, 
execute "lunch" to choose arch-x86 product and "mm" your source code.

One last problem is the shell code to be instrument produced by official AFL is x86 
based only, and it containing shm calling instructions, so you need to write ashmem 
calling shell codes to replace them, and you need to rewrite whole shell codes of AFL 
if you want to porting AFL to arch-arm, that's potential work to do in the future.

I made afl-fuzz running on Android-5.1.1-x86 successfully, and I add param '-t 100' to 
give emulator some more time to wait for signals because the binary running on emulator 
is much slower than host PC.  

![afl-fuzz](/images/afl-fuzz.jpg)

Sorry code is not published yet.
