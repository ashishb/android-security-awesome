android-security-awesome [![Awesome](https://cdn.rawgit.com/sindresorhus/awesome/d7305f38d29fed78fa85652e3a63e154dd8e8829/media/badge.svg)](https://github.com/sindresorhus/awesome)
========================

A collection of Android security related resources.

A lot of work is happening in academia and industry on tools to perform dynamic analysis, static analysis and reverse engineering of Android apps.

## APP REPACKAGING DETECTORS

* [FSquaDRA](https://github.com/zyrikby/FSquaDRA) - a tool for detection of repackaged Android applications based on app resources hash comparison.

## APP VULNERABILITY SCANNERS

* [AndroBugs](https://github.com/AndroBugs/AndroBugs_Framework)
* [Nogotofail](https://github.com/google/nogotofail)
* [QARK](https://github.com/linkedin/qark/) - QARK by LinkedIn is for app developers to scan app for security issues

## DYNAMIC ANALYSIS TOOLS

* [Android DBI frameowork](http://www.mulliner.org/blog/blosxom.cgi/security/androiddbiv02.html)
* [Android Hooker](https://github.com/AndroidHooker/hooker) - API Hooking of java methods triggered by any Android application (requires the Substrate Framework)
* [Android Linux Kernel modules](https://github.com/strazzere/android-lkms)
* [Android Malware Analysis Toolkit](http://www.mobilemalware.com.br/amat/download.html) - (linux distro) Earlier it use to be an [online analyzer](http://dunkelheit.com.br/amat/analysis/index_en.html)
* [Android Reverse Engineering](https://redmine.honeynet.org/projects/are/wiki) – ARE (android reverse engineering) not under active development anymore
* [Android Security Evaluation Framework](https://code.google.com/p/asef/) - not under active development anymore
* [Android Tamer](https://androidtamer.com/) - Virtual / Live Platform for Android Security Professionals
* [Appie](https://manifestsecurity.com/appie/) - Appie is a software package that has been pre-configured to function as an Android Pentesting Environment.It is completely portable and can be carried on USB stick or smartphone.This is a one stop answer for all the tools needed in Android Application Security Assessment and an awesome alternative to existing virtual machines
* [AppUse](https://appsec-labs.com/AppUse/) – custom build for pentesting
* [AuditdAndroid](https://github.com/nwhusted/AuditdAndroid) – android port of auditd, not under active development anymore
* [Aurasium](https://github.com/xurubin/aurasium) – Practical security policy enforcement for Android apps via bytecode rewriting and in-place reference monitor
* [Cobradroid](https://thecobraden.com/projects/cobradroid/) – custom image for malware analysis
* [Crowdroid](http://www.ida.liu.se/labs/rtslab/publications/2011/spsm11-burguera.pdf) – unable to find the actual tool
* [CuckooDroid](https://github.com/idanr1986/cuckoo-droid) - Android extension for Cuckoo sandbox
* [DroidAnalytics](https://github.com/zhengmin1989/DroidAnalytics) - incomplete
* [Droidbox](https://github.com/pjlantz/droidbox)
* [Droidscope](https://code.google.com/p/decaf-platform/wiki/DroidScope) - custom image for dynamic analysis
* [Drozer](https://labs.mwrinfosecurity.com/tools/drozer/)
* [Mem](https://github.com/MobileForensicsResearch/mem) - Memory analysis of Android (root required)
* [Mercury](http://labs.mwrinfosecurity.com/tools/2012/03/16/mercury/)
* [StaDynA](https://github.com/zyrikby/StaDynA) - a system supporting security app analysis in the presence of dynamic code update features (dynamic class loading and reflection). This tool combines static and dynamic analysis of Android applications in order to reveal the hidden/updated behavior and extend static analysis results with this information
* [Taintdroid](https://appanalysis.org/download.html) - requires AOSP compilation
* [Vezir Project](https://github.com/oguzhantopgul/Vezir-Project) - Virtual Machine for Mobile Application Pentesting and Mobile Malware Analysis
* [ViaLab Community Edition](https://www.nowsecure.com/blog/2014/09/10/introducing-vialab-community-edition/)
* [Xposed](https://forum.xda-developers.com/showthread.php?t=1574401) - equivalent of doing Stub based code injection but without any modifications to the binary

## EXPLOITABLE VULNERABILITIES

* [Root Exploits (from Drozer issue #56)](https://github.com/mwrlabs/drozer/issues/56)
* [Vulnerability Google
   doc](https://docs.google.com/spreadsheet/pub?key=0Am5hHW4ATym7dGhFU1A4X2lqbUJtRm1QSWNRc3E0UlE&single=true&gid=0&output=html)

## FUZZ TESTING

* [Android port of the melkor ELF fuzzer](https://github.com/anestisb/melkor-android)
* [Honggfuzz](https://github.com/google/honggfuzz)
* [IntentFuzzer](https://www.nccgroup.trust/us/about-us/resources/intent-fuzzer/)
* [Media Fuzzing Framework for Android](https://github.com/fuzzing/MFFA)
* [Radamsa Fuzzer](https://github.com/anestisb/radamsa-android)

## MARKET CRAWLERS

* [Appland downloader (Node)](https://github.com/dweinstein/node-appland) - download apps from Appland third-party Android market
* [Aptoide downloader (Node)](https://github.com/dweinstein/node-aptoide) - download apps from Aptoide third-party Android market
* [Google Play Crawler (Java)](https://github.com/Akdeniz/google-play-crawler)
* [Google Play Crawler (Node) ](https://github.com/dweinstein/node-google-play) - get app details and download apps from official Google Play Store.
* [Google Play Crawler (Python)](https://github.com/egirault/googleplay-api)

## ONLINE ANALYZERS

* [AndroTotal](http://andrototal.org/)
* ~~[Android Sandbox](http://www.androidsandbox.net/)~~
* ~~[Anubis](http://anubis.iseclab.org/)~~
* [AVC UnDroid](http://www.av-comparatives.org/avc-analyzer/)
* ~~[Comdroid](http://www.comdroid.org/)~~
* [CopperDroid](http://copperdroid.isg.rhul.ac.uk/copperdroid/)
* [Dexter](https://dexter.dexlabs.org/)
* [Fireeye](https://fireeye.ijinshan.com/)- max 60MB 15/day
* ~~[Foresafe](http://www.foresafe.com/scan)~~
* [Fraunhofer App-Ray](https://www.app-ray.com) - not free
* [Habo](https://habo.qq.com/) 10/day
* [IBM Security AppScan Mobile Analyzer](https://appscan.bluemix.net/mobileAnalyzer) - not free
* ~~[Ijiami](http://safe.ijiami.cn/)~~
* ~~[Mobile App Insight](http://www.mobile-app-insight.org)~~
* [Mobile Malware Sandbox](http://www.mobilemalware.com.br/analysis/index_en.php)
* ~~[Mobile-Sandbox](http://mobile-sandbox.com)~~
* [MobiSec Eacus](http://www.mobiseclab.org/eacus.jsp)
* [NVISO ApkScan](https://apkscan.nviso.be/)
* [SandDroid](http://sanddroid.xjtu.edu.cn/)
* ~~[Stowaway](http://www.android-permissions.org/)~~
* [Tracedroid](http://tracedroid.few.vu.nl/)
* [Virustotal](https://www.virustotal.com/)-max 128MB
* [Visual Threat](http://www.visualthreat.com/)

## REVERSE ENGINEERING

* [AndBug](https://github.com/swdunlop/AndBug)
* [Androguard](https://github.com/androguard/androguard) – powerful, integrates well with other tools
* [Android Framework for Exploitation](https://github.com/appknox/AFE)
* [Android OpenDebug](https://github.com/iSECPartners/Android-OpenDebug) – make any application on device debuggable (using cydia substrate)
* [Apktool](https://ibotpeaches.github.io/Apktool/) – really useful for compilation/decompilation (uses smali)
* [Bypass signature and permission checks for IPCs](https://github.com/iSECPartners/Android-KillPermAndSigChecks)
* [Bytecode viewer](https://github.com/Konloch/bytecode-viewer)
* [CFR](http://www.benf.org/other/cfr/) - Java decompiler
* [Dare](http://siis.cse.psu.edu/dare/index.html) – .dex to .class converter
* [Dedexer](http://dedexer.sourceforge.net)
* [Dex2Jar](https://github.com/pxb1988/dex2jar) - dex to jar converter
* [Emacs syntax coloring for Smali files](https://github.com/strazzere/Emacs-Smali)
* [Enjarify](https://github.com/google/enjarify) - dex to jar converter from Google
* [FernFlower](https://github.com/fesh0r/fernflower) - Java decompiler
* [Fino](https://github.com/sysdream/fino)
* [Indroid](https://bitbucket.org/aseemjakhar/indroid) – thread injection kit
* [IntentSniffer](https://www.nccgroup.trust/us/about-us/resources/intent-sniffer/)
* [Introspy](https://github.com/iSECPartners/Introspy-Android)
* [Jad]( http://varaneckas.com/jad/) - Java decompiler
* [JD-GUI](https://github.com/java-decompiler/jd-gui) - Java decompiler
* [Krakatau](https://github.com/Storyyeller/Krakatau) - Java decompiler
* [Procyon](https://bitbucket.org/mstrobel/procyon/wiki/Java%20Decompiler) - Java decompiler
* [Radare2](https://github.com/radare/radare2)
* [Redexer](https://github.com/plum-umd/redexer) – apk manipulation
* [Simplify Android deobfuscator](https://github.com/CalebFenton/simplify)
* [Smali/Baksmali](https://github.com/JesusFreke/smali) – apk decompilation
* [Smali viewer](http://blog.avlyun.com/wp-content/uploads/2014/04/SmaliViewer.zip)
* [Vim syntax coloring for Smali files](http://codetastrophe.com/smali.vim)
* [ZjDroid](https://github.com/BaiduSecurityLabs/ZjDroid) (no longer available), [fork/mirror](https://github.com/yangbean9/ZjDroid)

## SAMPLE SOURCES

* [Admire](http://admire.necst.it/)
* [Android Malware - Github repo](https://github.com/ashishb/android-malware)
* [Contagio Mini Dump](http://contagiominidump.blogspot.com)
* [Drebin](http://user.informatik.uni-goettingen.de/~darp/drebin/)
* [MalGenome](http://www.malgenomeproject.org/policy.html) - contains 1260 malware samples categorized into 49 different malware families, free for research purpose.
* [Open Source database](https://code.google.com/p/androguard/wiki/DatabaseAndroidMalwares)
* [VirusTotal Malware Intelligence Service](https://www.virustotal.com/en/about/contact/) - powered by VirusTotal - not free

## STATIC ANALYSIS TOOLS

* [Amandroid](http://amandroid.sireum.org/)
* [Android Decompiler](https://www.pnfsoftware.com/) – not free
* [Androwarn](https://github.com/maaaaz/androwarn/) - detect and warn the user about potential malicious behaviours developped by an Android application.
* [ApkAnalyser](https://github.com/sonyxperiadev/ApkAnalyser)
* [APKInspector](https://github.com/honeynet/apkinspector/)
* [CFGScanDroid](https://github.com/douggard/CFGScanDroid) - Scans and compares CFG against CFG of malicious applications
* [ConDroid](https://github.com/JulianSchuette/ConDroid) - Performs a combination of symoblic + concrete execution of the app
* [Droid Intent Data Flow Analysis for Information Leakage](https://www.cert.org/secure-coding/tools/didfail.cfm)
* [FlowDroid](https://blogs.uni-paderborn.de/sse/tools/flowdroid/)
* [Madrolyzer](https://github.com/maldroid/maldrolyzer) - extracts actionable data like C&C, phone number etc.
* [PSCout](http://pscout.csl.toronto.edu/) - A tool that extracts the permission specification from the Android OS source code using static analysis
* [Several tools from PSU](http://siis.cse.psu.edu/tools.html)
* [Smali CFG generator](https://github.com/EugenioDelfa/Smali-CFGs)
* [SmaliSCA](https://github.com/dorneanu/smalisca) - Smali Static Code Analysis
* [SPARTA](http://www.cs.washington.edu/sparta) - verifies (proves) that an app satisfies an information-flow security policy; built on the [Checker Framework](http://types.cs.washington.edu/checker-framework/)

## READING MATERIAL

* [Android Security (and Not) Internals](http://www.zhauniarovich.com/pubs.html)
* [Android security related presentations](https://github.com/jacobsoo/AndroidSlides)
* [A good collection of static analysis papers](https://tthtlc.wordpress.com/2011/09/01/static-analysis-of-android-applications/)

## MISC TOOLS

* [ADB AutoComplete](https://romannurik-code.googlecode.com/git/bash_completion/adb)
* [Android Vulnerability Test Suite](https://github.com/nowsecure/android-vts) - android-vts scans a device for set of vulnerabilities
* [APK-Downloader](http://codekiem.com/2012/02/24/apk-downloader/)
* [AXMLPrinter2](http://code.google.com/p/android4me/downloads/detail?name=AXMLPrinter2.jar) - to convert binary XML files to human-readable XML files
* [Dalvik opcodes](http://pallergabor.uw.hu/androidblog/dalvik_opcodes.html)
* [dockerfile/androguard](https://github.com/dweinstein/dockerfile-androguard)
* [ExploitMe Android Labs](http://securitycompass.github.io/AndroidLabs/setup.html) - for practice
* [GoatDroid](https://github.com/jackMannino/OWASP-GoatDroid-Project) - for practice
* [Opcodes table for quick reference](http://www.xchg.info/corkami/opcodes_tables.pdf)
* [mitmproxy](https://github.com/mitmproxy/mitmproxy)
* [Smalihook](http://androidcracking.blogspot.com/2011/03/original-smalihook-java-source.html)

## TUTORIALS
* [Android Reverse Engineering 101 by Daniele Altomare](http://www.fasteque.com/android-reverse-engineering-101-part-1/)

# Other Awesome Lists
Other amazingly awesome lists can be found in the
[awesome-awesomeness](https://github.com/bayandin/awesome-awesomeness) list.

# Contributing
Your contributions are always welcome!
