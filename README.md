android-security-awesome [![Awesome](https://cdn.rawgit.com/sindresorhus/awesome/d7305f38d29fed78fa85652e3a63e154dd8e8829/media/badge.svg)](https://github.com/sindresorhus/awesome)
========================

A collection of android security related resources.

A lot of work is happening in academia and industry on tools to perform dynamic analysis, static analysis and reverse engineering of android apps.


## ONLINE ANALYZERS

1. [AndroTotal](http://andrototal.org/)
* [CopperDroid](http://copperdroid.isg.rhul.ac.uk/copperdroid/)
* [Dexter](https://dexter.dexlabs.org/)
* [Sandroid](http://sanddroid.xjtu.edu.cn/)
* [Tracedroid](http://tracedroid.few.vu.nl/)
* [Visual Threat](http://www.visualthreat.com/)
* [Mobile Malware Sandbox](http://www.mobilemalware.com.br/analysis/index_en.php)
* [MobiSec Eacus](http://www.mobiseclab.org/eacus.jsp)
* [IBM Security AppScan Mobile Analyzer](https://appscan.bluemix.net/mobileAnalyzer) - not free
* [NVISO ApkScan](https://apkscan.nviso.be/)
* [AVC UnDroid](http://www.av-comparatives.org/avc-analyzer/)
* [Fireeye](https://fireeye.ijinshan.com/)- max 60MB 15/day
* [habo](https://habo.qq.com/) 10/day
* [Virustotal](https://www.virustotal.com/)-max 128MB
* [Fraunhofer App-ray](https://www.app-ray.com) - not free
* ~~[Stowaway](http://www.android-permissions.org/)~~
* ~~[Anubis](http://anubis.iseclab.org/)~~
* ~~[Mobile app insight](http://www.mobile-app-insight.org)~~
* ~~[Mobile-Sandbox](http://mobile-sandbox.com)~~
* ~~[Ijiami](http://safe.ijiami.cn/)~~
* ~~[Comdroid](http://www.comdroid.org/)~~
* ~~[Android Sandbox](http://www.androidsandbox.net/)~~
* ~~[Foresafe](http://www.foresafe.com/scan)~~

## STATIC ANALYSIS TOOLS

1. [Androwarn](https://github.com/maaaaz/androwarn/) - detect and warn the user about potential malicious behaviours developped by an Android application.
* [ApkAnalyser](https://github.com/sonyxperiadev/ApkAnalyser)
* [APKInspector](https://github.com/honeynet/apkinspector/)
* [Droid Intent Data Flow Analysis for Information Leakage](https://www.cert.org/secure-coding/tools/didfail.cfm)
* [Several tools from PSU](http://siis.cse.psu.edu/tools.html)
* [Smali CFG generator](https://github.com/EugenioDelfa/Smali-CFGs)
* [FlowDroid](https://blogs.uni-paderborn.de/sse/tools/flowdroid/)
* [Android Decompiler](https://www.pnfsoftware.com/) – not free
* [PSCout](http://pscout.csl.toronto.edu/) - A tool that extracts the permission specification from the Android OS source code using static analysis
* [Amandroid](http://amandroid.sireum.org/)
* [SmaliSCA](https://github.com/dorneanu/smalisca) - Smali Static Code Analysis
* [CFGScanDroid](https://github.com/douggard/CFGScanDroid) - Scans and compares CFG against CFG of malicious applications
* [Madrolyzer](https://github.com/maldroid/maldrolyzer) - extracts actionable data like C&C, phone number etc.
* [SPARTA](http://www.cs.washington.edu/sparta) - verifies (proves) that an app satisfies an information-flow security policy; built on the [Checker Framework](http://types.cs.washington.edu/checker-framework/)
* [ConDroid](https://github.com/JulianSchuette/ConDroid) - Performs a combination of symoblic + concrete execution of the app

## APP VULNERABILITY SCANNERS
1. [QARK](https://github.com/linkedin/qark/) - QARK by LinkedIn is for app developers to scan app for security issues
* [AndroBugs](https://github.com/AndroBugs/AndroBugs_Framework)

## DYNAMIC ANALYSIS TOOLS

1. [Android DBI frameowork](http://www.mulliner.org/blog/blosxom.cgi/security/androiddbiv02.html)
* [Android Malware Analysis Toolkit](http://www.mobilemalware.com.br/amat/download.html) - (linux distro) Earlier it use to be an [online analyzer](http://dunkelheit.com.br/amat/analysis/index_en.html)
* [AppUse](https://appsec-labs.com/AppUse/) – custom build for pentesting
* [Cobradroid](https://thecobraden.com/projects/cobradroid/) – custom image for malware analysis
* [ViaLab Community Edition](https://www.nowsecure.com/blog/2014/09/10/introducing-vialab-community-edition/)
* [Droidbox](https://github.com/pjlantz/droidbox)
* [Mercury](http://labs.mwrinfosecurity.com/tools/2012/03/16/mercury/)
* [Drozer](https://labs.mwrinfosecurity.com/tools/drozer/)
* [Taintdroid](https://appanalysis.org/download.html) - requires AOSP compilation
* [Xposed](https://forum.xda-developers.com/showthread.php?t=1574401) - equivalent of doing Stub based code injection but without any modifications to the binary
* [Android Hooker](https://github.com/AndroidHooker/hooker) - API Hooking of java methods triggered by any Android application (requires the Substrate Framework)
* [Android tamer](https://androidtamer.com/) - custom image
* [Droidscope](https://code.google.com/p/decaf-platform/wiki/DroidScope) - custom image for dynamic analysis
* [CuckooDroid](https://github.com/idanr1986/cuckoo-droid) - Android extension for Cuckoo sandbox
* [Mem](https://github.com/MobileForensicsResearch/mem) - Memory analysis of Android (root required)
* [Crowdroid](http://www.ida.liu.se/labs/rtslab/publications/2011/spsm11-burguera.pdf) – unable to find the actual tool
* [AuditdAndroid](https://github.com/nwhusted/AuditdAndroid) – android port of auditd, not under active development anymore
* [Android Security Evaluation Framework](https://code.google.com/p/asef/) - not under active development anymore
* [Android Reverse Engineering](https://redmine.honeynet.org/projects/are/wiki) – ARE (android reverse engineering) not under active development anymore
* [Aurasium](https://github.com/xurubin/aurasium) – Practical security policy enforcement for Android apps via bytecode rewriting and in-place reference monitor.
* [Android Linux Kernel modules](https://github.com/strazzere/android-lkms)
*
* [Appie](https://manifestsecurity.com/appie/) - Appie is a software package that has been pre-configured to function as an Android Pentesting Environment.It is completely portable and can be carried on USB stick or smartphone.This is a one stop answer for all the tools needed in Android Application Security Assessment and an awesome alternative to existing virtual machines.
* [StaDynA](https://github.com/zyrikby/StaDynA) - a system supporting security app analysis in the presence of dynamic code update features (dynamic class loading and reflection). This tool combines static and dynamic analysis of Android applications in order to reveal the hidden/updated behavior and extend static analysis results with this information.
* [DroidAnalytics](https://github.com/zhengmin1989/DroidAnalytics) - incomplete
* [Vezir Project](https://github.com/oguzhantopgul/Vezir-Project) - Virtual Machine for Mobile Application Pentesting and Mobile Malware Analysis 

## REVERSE ENGINEERING

1. [Smali/Baksmali](https://github.com/JesusFreke/smali) – apk decompilation
* [emacs syntax coloring for smali files](https://github.com/strazzere/Emacs-Smali)
* [vim syntax coloring for smali files](http://codetastrophe.com/smali.vim)
* [AndBug](https://github.com/swdunlop/AndBug)
* [Androguard](https://github.com/androguard/androguard) – powerful, integrates well with other tools
* [Apktool](https://ibotpeaches.github.io/Apktool/) – really useful for compilation/decompilation (uses smali)
* [Android Framework for Exploitation](https://github.com/appknox/AFE)
* [Bypass signature and permission checks for IPCs](https://github.com/iSECPartners/Android-KillPermAndSigChecks)
* [Android OpenDebug](https://github.com/iSECPartners/Android-OpenDebug) – make any application on device debuggable (using cydia substrate).
* [Dare](http://siis.cse.psu.edu/dare/index.html) – .dex to .class converter
* [Dex2Jar](https://github.com/pxb1988/dex2jar) - dex to jar converter
* [Enjarify](https://github.com/google/enjarify) - dex to jar converter from Google
* [Dedexer](http://dedexer.sourceforge.net)
* [Fino](https://github.com/sysdream/fino)
* [Indroid](https://bitbucket.org/aseemjakhar/indroid) – thread injection kit
* [IntentSniffer](https://www.nccgroup.trust/us/about-us/resources/intent-sniffer/)
* [Introspy](https://github.com/iSECPartners/Introspy-Android)
* [Jad]( http://varaneckas.com/jad/) - Java decompiler
* [JD-GUI](https://github.com/java-decompiler/jd-gui) - Java decompiler
* [CFR](http://www.benf.org/other/cfr/) - Java decompiler
* [Krakatau](https://github.com/Storyyeller/Krakatau) - Java decompiler
* [Procyon](https://bitbucket.org/mstrobel/procyon/wiki/Java%20Decompiler) - Java decompiler
* [FernFlower](https://github.com/fesh0r/fernflower) - Java decompiler
* [Redexer](https://github.com/plum-umd/redexer) – apk manipulation
* [Smali viewer](http://blog.avlyun.com/wp-content/uploads/2014/04/SmaliViewer.zip)
* [ZjDroid](https://github.com/BaiduSecurityLabs/ZjDroid) (no longer available), [fork/mirror](https://github.com/yangbean9/ZjDroid)
* [Simplify Android deobfuscator](https://github.com/CalebFenton/simplify)
* [Bytecode viewer](https://github.com/Konloch/bytecode-viewer)
* [Radare2](https://github.com/radare/radare2)

## FUZZ TESTING

1. [IntentFuzzer](https://www.nccgroup.trust/us/about-us/resources/intent-fuzzer/)
* [Radamsa Fuzzer](https://github.com/anestisb/radamsa-android)
* [Honggfuzz](https://github.com/google/honggfuzz)
* [An Android port of the melkor ELF fuzzer](https://github.com/anestisb/melkor-android)
* [Media Fuzzing Framework for Android](https://github.com/fuzzing/MFFA)

##APP REPACKAGING DETECTORS

1. [FSquaDRA](https://github.com/zyrikby/FSquaDRA) - a tool for detection of repackaged Android applications based on app resources hash comparison.

## Exploitable Vulnerabilties

1. [Vulnerability Google
   doc](https://docs.google.com/spreadsheet/pub?key=0Am5hHW4ATym7dGhFU1A4X2lqbUJtRm1QSWNRc3E0UlE&single=true&gid=0&output=html)
* [Root Exploits (from Drozer issue #56)](https://github.com/mwrlabs/drozer/issues/56)

## SAMPLE SOURCES

1. [contagio mini dump](http://contagiominidump.blogspot.com)
* [Open Source database](https://code.google.com/p/androguard/wiki/DatabaseAndroidMalwares)
* [Drebin](http://user.informatik.uni-goettingen.de/~darp/drebin/)
* [Admire](http://admire.necst.it/)
* [MalGenome](http://www.malgenomeproject.org/policy.html) - contains 1260 malware samples categorized into 49 different malware families, free for research purpose.
* [VirusTotal Malware Intelligence Service](https://www.virustotal.com/en/about/contact/) - powered by VirusTotal,not free

## Reading material

1. [Android Security (and Not) Internals](http://www.zhauniarovich.com/pubs.html)
* [Android security related presentations](https://github.com/jacobsoo/AndroidSlides)
* [A good collection of static analysis papers](https://tthtlc.wordpress.com/2011/09/01/static-analysis-of-android-applications/)

## MARKET CRAWLERS

1. [Google play crawler (Java)](https://github.com/Akdeniz/google-play-crawler)
* [Google play crawler (Python)](https://github.com/egirault/googleplay-api)
* [Google play crawler (Node) ](https://github.com/dweinstein/node-google-play) - get app details and download apps from official Google Play Store.
* [Aptoide downloader (Node)](https://github.com/dweinstein/node-aptoide) - download apps from Aptoide third-party Android market
* [Appland downloader (Node)](https://github.com/dweinstein/node-appland) - download apps from Appland third-party Android market

## MISC TOOLS

1. [smalihook](http://androidcracking.blogspot.com/2011/03/original-smalihook-java-source.html)
* [APK-Downloader](http://codekiem.com/2012/02/24/apk-downloader/)
* [AXMLPrinter2](http://code.google.com/p/android4me/downloads/detail?name=AXMLPrinter2.jar) - to convert binary XML files to human-readable XML files
* [adb autocomplete](https://romannurik-code.googlecode.com/git/bash_completion/adb)
* [Dalvik opcodes](http://pallergabor.uw.hu/androidblog/dalvik_opcodes.html)
* [Opcodes table for quick reference](http://www.xchg.info/corkami/opcodes_tables.pdf)
* [ExploitMe Android Labs](http://securitycompass.github.io/AndroidLabs/setup.html) - for practice
* [GoatDroid](https://github.com/jackMannino/OWASP-GoatDroid-Project) - for practice
* [mitmproxy](https://github.com/mitmproxy/mitmproxy)
* [dockerfile/androguard](https://github.com/dweinstein/dockerfile-androguard)
* [Android Vulnerability Test Suite](https://github.com/nowsecure/android-vts) - android-vts scans a device for set of vulnerabilities

## Good Tutorials
1. [Android Reverse Engineering 101 by Daniele Altomare](http://www.fasteque.com/android-reverse-engineering-101-part-1/)

# Other Awesome Lists
Other amazingly awesome lists can be found in the
[awesome-awesomeness](https://github.com/bayandin/awesome-awesomeness) list.

# Contributing
Your contributions are always welcome!
