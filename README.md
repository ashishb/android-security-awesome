# android-security-awesome ![Awesome](https://cdn.rawgit.com/sindresorhus/awesome/d7305f38d29fed78fa85652e3a63e154dd8e8829/media/badge.svg) <a href="https://travis-ci.org/ashishb/android-security-awesome"><img src="https://img.shields.io/travis/ashishb/android-security-awesome/master.svg?label=URL%20Check" alt="URL Check"></a>

A collection of android security related resources.

1. [Tools](#tools)
2. [Academic/Research/Publications/Books](#academic)
3. [Exploits/Vulnerabilities/Bugs](#exploits)

## <a name="tools"></a>Tools

### Online Analyzers

1. [AndroTotal](http://andrototal.org/)
5. [Appknox](https://www.appknox.com/) - not free
8. [AVC UnDroid](http://undroid.av-comparatives.info/)
10. [Virustotal](https://www.virustotal.com/) - max 128MB
11. [Fraunhofer App-ray](http://app-ray.co/) - not free
12. [AppCritique](https://appcritique.boozallen.com) - Upload your Android APKs and receive comprehensive free security assessments.
13. [NowSecure Lab Automated](https://www.nowsecure.com/blog/2016/09/19/announcing-nowsecure-lab-automated/) - Enterprise tool for mobile app security testing both Android and iOS mobile apps. Lab Automated features dynamic and static analysis on real devices in the cloud to return results in minutes. Not free
14. [AMAaaS](https://amaaas.com) - Free Android Malware Analysis Service. A baremetal service features static and dynamic analysis for Android applications. A product of [MalwarePot](https://malwarepot.com/index.php/AMAaaS).
15. ~~[NVISO ApkScan](https://apkscan.nviso.be/) - sunsetting on Oct 31, 2019~~
4. ~~[Mobile Malware Sandbox](http://www.mobilemalware.com.br/analysis/index_en.php)~~
6. ~~[IBM Security AppScan Mobile Analyzer](https://appscan.bluemix.net/mobileAnalyzer) - not free~~
15. ~~[Visual Threat](https://www.visualthreat.com/) - no longer an Android app analyzer~~
15. ~~[Tracedroid](http://tracedroid.few.vu.nl/)~~
15. ~~[habo](https://habo.qq.com/) - 10/day~~
16. ~~[CopperDroid](http://copperdroid.isg.rhul.ac.uk/copperdroid/)~~
17. ~~[SandDroid](http://sanddroid.xjtu.edu.cn/)~~
18. ~~[Stowaway](http://www.android-permissions.org/)~~
19. ~~[Anubis](http://anubis.iseclab.org/)~~
20. ~~[Mobile app insight](http://www.mobile-app-insight.org)~~
21. ~~[Mobile-Sandbox](http://mobile-sandbox.com)~~
22. ~~[Ijiami](http://safe.ijiami.cn/)~~
23. ~~[Comdroid](http://www.comdroid.org/)~~
24. ~~[Android Sandbox](http://www.androidsandbox.net/)~~
25. ~~[Foresafe](http://www.foresafe.com/scan)~~
26. ~~[Dexter](https://dexter.dexlabs.org/)~~
27. ~~[MobiSec Eacus](http://www.mobiseclab.org/eacus.jsp)~~
28. ~~[Fireeye](https://fireeye.ijinshan.com/)- max 60MB 15/day~~

### Static Analysis Tools

1. [Androwarn](https://github.com/maaaaz/androwarn/) - detect and warn the user about potential malicious behaviours developed by an Android application.
2. [ApkAnalyser](https://github.com/sonyxperiadev/ApkAnalyser)
3. [APKInspector](https://github.com/honeynet/apkinspector/)
4. [Droid Intent Data Flow Analysis for Information Leakage](https://www.cert.org/secure-coding/tools/didfail.cfm)
5. [DroidLegacy](https://bitbucket.org/srl/droidlegacy)
7. [Smali CFG generator](https://github.com/EugenioDelfa/Smali-CFGs)
8. [FlowDroid](https://blogs.uni-paderborn.de/sse/tools/flowdroid/)
9. [Android Decompiler](https://www.pnfsoftware.com/) – not free
10. [PSCout](http://pscout.csl.toronto.edu/) - A tool that extracts the permission specification from the Android OS source code using static analysis
11. [Amandroid](http://amandroid.sireum.org/)
12. [SmaliSCA](https://github.com/dorneanu/smalisca) - Smali Static Code Analysis
13. [CFGScanDroid](https://github.com/douggard/CFGScanDroid) - Scans and compares CFG against CFG of malicious applications
14. [Madrolyzer](https://github.com/maldroid/maldrolyzer) - extracts actionable data like C&C, phone number etc.
15. [SPARTA](https://www.cs.washington.edu/sparta) - verifies (proves) that an app satisfies an information-flow security policy; built on the [Checker Framework](https://types.cs.washington.edu/checker-framework/)
16. [ConDroid](https://github.com/JulianSchuette/ConDroid) - Performs a combination of symbolic + concrete execution of the app
17. [DroidRA](https://github.com/serval-snt-uni-lu/DroidRA)
18. [RiskInDroid](https://github.com/ClaudiuGeorgiu/RiskInDroid) - A tool for calculating the risk of Android apps based on their permissions, with online demo available.
19. [SUPER](https://github.com/SUPERAndroidAnalyzer/super) - Secure, Unified, Powerful and Extensible Rust Android Analyzer
20. [ClassyShark](https://github.com/google/android-classyshark) - Standalone binary inspection tool which can browse any Android executable and show important infos.
21. [StaCoAn](https://github.com/vincentcox/StaCoAn) - Crossplatform tool which aids developers, bugbounty hunters and ethical hackers performing static code analysis on mobile applications. This tool was created with a big focus on usability and graphical guidance in the user interface.
22. [JAADAS](https://github.com/flankerhqd/JAADAS) - Joint intraprocedure and interprocedure program analysis tool to find vulnerabilities in Android apps, built on Soot and Scala
23. ~~[Several tools from PSU](http://siis.cse.psu.edu/tools.html)~~
24. [Quark-Engine](https://github.com/quark-engine/quark-engine) - An Obfuscation-Neglect Android Malware Scoring System

### App Vulnerability Scanners

1. [QARK](https://github.com/linkedin/qark/) - QARK by LinkedIn is for app developers to scan app for security issues
2. [AndroBugs](https://github.com/AndroBugs/AndroBugs_Framework)
3. [Nogotofail](https://github.com/google/nogotofail)
4. ~~[Devknox](https://devknox.io/) - IDE plugin to build secure Android apps. Not maintained anymore.~~

### Dynamic Analysis Tools

1. [Android DBI frameowork](http://www.mulliner.org/blog/blosxom.cgi/security/androiddbiv02.html)
2. [Androl4b](https://github.com/sh4hin/Androl4b)- A Virtual Machine For Assessing Android applications, Reverse Engineering and Malware Analysis
4. [Mobile-Security-Framework MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF) - Mobile Security Framework is an intelligent, all-in-one open source mobile application (Android/iOS) automated pen-testing framework capable of performing static, dynamic analysis and web API testing.
5. [AppUse](https://appsec-labs.com/AppUse/) – custom build for pentesting
6. [Cobradroid](https://thecobraden.com/projects/cobradroid/) – custom image for malware analysis
7. [Droidbox](https://github.com/pjlantz/droidbox)
10. [Drozer](https://github.com/mwrlabs/drozer)
11. [Xposed](https://forum.xda-developers.com/xposed/xposed-installer-versions-changelog-t2714053) - equivalent of doing Stub based code injection but without any modifications to the binary
12. [Inspeckage](https://github.com/ac-pm/Inspeckage) - Android Package Inspector - dynamic analysis with api hooks, start unexported activities and more. (Xposed Module)
13. [Android Hooker](https://github.com/AndroidHooker/hooker) - Dynamic Java code instrumentation (requires the Substrate Framework)
14. [ProbeDroid](https://github.com/ZSShen/ProbeDroid) - Dynamic Java code instrumentation
15. [Android Tamer](https://androidtamer.com/) - Virtual / Live Platform for Android Security Professionals
16. [DECAF](https://github.com/sycurelab/DECAF) - Dynamic Executable Code Analysis Framework based on QEMU (DroidScope is now an extension to DECAF)
17. [CuckooDroid](https://github.com/idanr1986/cuckoo-droid) - Android extension for Cuckoo sandbox
18. [Mem](https://github.com/MobileForensicsResearch/mem) - Memory analysis of Android (root required)
19. [Crowdroid](http://www.ida.liu.se/labs/rtslab/publications/2011/spsm11-burguera.pdf) – unable to find the actual tool
20. [AuditdAndroid](https://github.com/nwhusted/AuditdAndroid) – android port of auditd, not under active development anymore
21. [Android Security Evaluation Framework](https://code.google.com/p/asef/) - not under active development anymore
23. [Aurasium](https://github.com/xurubin/aurasium) – Practical security policy enforcement for Android apps via bytecode rewriting and in-place reference monitor.
24. [Android Linux Kernel modules](https://github.com/strazzere/android-lkms)
25. [Appie](https://manifestsecurity.com/appie/) - Appie is a software package that has been pre-configured to function as an Android Pentesting Environment. It is completely portable and can be carried on USB stick or smartphone. This is a one stop answer for all the tools needed in Android Application Security Assessment and an awesome alternative to existing virtual machines.
26. [StaDynA](https://github.com/zyrikby/StaDynA) - a system supporting security app analysis in the presence of dynamic code update features (dynamic class loading and reflection). This tool combines static and dynamic analysis of Android applications in order to reveal the hidden/updated behavior and extend static analysis results with this information.
27. [DroidAnalytics](https://github.com/zhengmin1989/DroidAnalytics) - incomplete
28. [Vezir Project](https://github.com/oguzhantopgul/Vezir-Project) - Virtual Machine for Mobile Application Pentesting and Mobile Malware Analysis
29. [MARA](https://github.com/xtiankisutsa/MARA_Framework) - Mobile Application Reverse engineering and Analysis Framework
30. [Taintdroid](http://appanalysis.org) - requires AOSP compilation
31. [ARTist](https://artist.cispa.saarland) - a flexible open source instrumentation and hybrid analysis framework for Android apps and Android's java middleware. It is based on the Android Runtime's (ART) compiler and modifies code during on-device compilation.
32. [Android Malware Sandbox](https://github.com/Areizen/Android-Malware-Sandbox)
3. ~~[Android Malware Analysis Toolkit](http://www.mobilemalware.com.br/amat/download.html) - (linux distro) Earlier it use to be an [online analyzer](http://dunkelheit.com.br/amat/analysis/index_en.php)~~
31. ~~[Android Reverse Engineering](https://redmine.honeynet.org/projects/are/wiki) – ARE (android reverse engineering) not under active development anymore~~
31. ~~[ViaLab Community Edition](https://www.nowsecure.com/blog/2014/09/09/introducing-vialab-community-edition/)~~
32. ~~[Mercury](https://labs.mwrinfosecurity.com/tools/2012/03/16/mercury/)~~

### Reverse Engineering

1. [Smali/Baksmali](https://github.com/JesusFreke/smali) – apk decompilation
2. [emacs syntax coloring for smali files](https://github.com/strazzere/Emacs-Smali)
3. [vim syntax coloring for smali files](http://codetastrophe.com/smali.vim)
4. [AndBug](https://github.com/swdunlop/AndBug)
5. [Androguard](https://github.com/androguard/androguard) – powerful, integrates well with other tools
6. [Apktool](https://ibotpeaches.github.io/Apktool/) – really useful for compilation/decompilation (uses smali)
7. [Android Framework for Exploitation](https://github.com/appknox/AFE)
8. [Bypass signature and permission checks for IPCs](https://github.com/iSECPartners/Android-KillPermAndSigChecks)
9. [Android OpenDebug](https://github.com/iSECPartners/Android-OpenDebug) – make any application on device debuggable (using cydia substrate).
11. [Dex2Jar](https://github.com/pxb1988/dex2jar) - dex to jar converter
12. [Enjarify](https://github.com/google/enjarify) - dex to jar converter from Google
13. [Dedexer](https://sourceforge.net/projects/dedexer/)
14. [Fino](https://github.com/sysdream/fino)
15. [Frida](https://www.frida.re/) - inject javascript to explore applications and a [GUI tool](https://github.com/antojoseph/diff-gui) for it
16. [Indroid](https://bitbucket.org/aseemjakhar/indroid) – thread injection kit
17. [IntentSniffer](https://www.nccgroup.trust/us/about-us/resources/intent-sniffer/)
18. [Introspy](https://github.com/iSECPartners/Introspy-Android)
19. [Jad]( https://varaneckas.com/jad/) - Java decompiler
20. [JD-GUI](https://github.com/java-decompiler/jd-gui) - Java decompiler
21. [CFR](http://www.benf.org/other/cfr/) - Java decompiler
22. [Krakatau](https://github.com/Storyyeller/Krakatau) - Java decompiler
23. [Procyon](https://bitbucket.org/mstrobel/procyon/wiki/Java%20Decompiler) - Java decompiler
24. [FernFlower](https://github.com/fesh0r/fernflower) - Java decompiler
25. [Redexer](https://github.com/plum-umd/redexer) – apk manipulation
26. [Simplify Android deobfuscator](https://github.com/CalebFenton/simplify)
29. [Bytecode viewer](https://github.com/Konloch/bytecode-viewer)
30. [Radare2](https://github.com/radare/radare2)
31. [Jadx](https://github.com/skylot/jadx)
32. [Dwarf](https://github.com/iGio90/Dwarf) - GUI for reverse engineering
33. [Andromeda](https://github.com/secrary/Andromeda) - Another basic command-line reverse engineering tool
34. [apk-mitm](https://github.com/shroudedcode/apk-mitm) - A CLI application that prepares Android APK files for HTTPS inspection
34. ~~[Smali viewer](http://blog.avlyun.com/wp-content/uploads/2014/04/SmaliViewer.zip)~~
35. ~~[ZjDroid](https://github.com/BaiduSecurityLabs/ZjDroid)~~, ~~[fork/mirror](https://github.com/yangbean9/ZjDroid)~~
36. ~~[Dare](http://siis.cse.psu.edu/dare/index.html) – .dex to .class converter~~

### Fuzz Testing

1. [IntentFuzzer](https://www.nccgroup.trust/us/about-us/resources/intent-fuzzer/)
2. [Radamsa Fuzzer](https://github.com/anestisb/radamsa-android)
3. [Honggfuzz](https://github.com/google/honggfuzz)
4. [An Android port of the melkor ELF fuzzer](https://github.com/anestisb/melkor-android)
5. [Media Fuzzing Framework for Android](https://github.com/fuzzing/MFFA)
6. [AndroFuzz](https://github.com/jonmetz/AndroFuzz)

### App Repackaging Detectors

1. [FSquaDRA](https://github.com/zyrikby/FSquaDRA) - a tool for detection of repackaged Android applications based on app resources hash comparison.

### Market Crawlers

1. [Google play crawler (Java)](https://github.com/Akdeniz/google-play-crawler)
2. [Google play crawler (Python)](https://github.com/egirault/googleplay-api)
3. [Google play crawler (Node)](https://github.com/dweinstein/node-google-play) - get app details and download apps from official Google Play Store.
4. [Aptoide downloader (Node)](https://github.com/dweinstein/node-aptoide) - download apps from Aptoide third-party Android market
5. [Appland downloader (Node)](https://github.com/dweinstein/node-appland) - download apps from Appland third-party Android market
6. [Apkpure](https://apkpure.com/) - Online apk downloader. Provides also an own app for downloading.

### Misc Tools

1. [smalihook](http://androidcracking.blogspot.com/2011/03/original-smalihook-java-source.html)
3. [AXMLPrinter2](http://code.google.com/p/android4me/downloads/detail?name=AXMLPrinter2.jar) - to convert binary XML files to human-readable XML files
4. [adb autocomplete](https://github.com/mbrubeck/android-completion)
5. [Dalvik opcodes](http://pallergabor.uw.hu/androidblog/dalvik_opcodes.html)
7. [ExploitMe Android Labs](http://securitycompass.github.io/AndroidLabs/setup.html) - for practice
8. [GoatDroid](https://github.com/jackMannino/OWASP-GoatDroid-Project) - for practice
9. [Android InsecureBank](https://github.com/dineshshetty/Android-InsecureBankv2) - for practice
10. [mitmproxy](https://github.com/mitmproxy/mitmproxy)
11. [dockerfile/androguard](https://github.com/dweinstein/dockerfile-androguard)
12. [Android Vulnerability Test Suite](https://github.com/AndroidVTS/android-vts) - android-vts scans a device for set of vulnerabilities
13. [AppMon](https://github.com/dpnishant/appmon)- AppMon is an automated framework for monitoring and tampering system API calls of native macOS, iOS and android apps. It is based on Frida.
14. [Internal Blue](https://github.com/seemoo-lab/internalblue) - Bluetooth experimentation framework based on Reverse Engineering of Broadcom Bluetooth Controllers
15. ~~[Opcodes table for quick reference](http://ww38.xchg.info/corkami/opcodes_tables.pdf)~~
15. ~~[APK-Downloader](http://codekiem.com/2012/02/24/apk-downloader/)~~ - seems dead now

## <a name="academic"></a>Academic/Research/Publications/Books

### Research Papers

1. [Exploit Database](https://www.exploit-db.com/papers/)
2. [Android security related presentations](https://github.com/jacobsoo/AndroidSlides)
3. [A good collection of static analysis papers](https://tthtlc.wordpress.com/2011/09/01/static-analysis-of-android-applications/)

### Books

1. [SEI CERT Android Secure Coding Standard](https://www.securecoding.cert.org/confluence/display/android/Android+Secure+Coding+Standard)

### Others

1. [OWASP Mobile Security Testing Guide Manual](https://github.com/OWASP/owasp-mstg)
2. [doridori/Android-Security-Reference](https://github.com/doridori/Android-Security-Reference)
3. [android app security checklist](https://github.com/b-mueller/android_app_security_checklist)
4. [Mobile App Pentest Cheat Sheet](https://github.com/tanprathan/MobileApp-Pentest-Cheatsheet)
5. ~~[Mobile Security Reading Room](https://mobile-security.zeef.com) - A reading room which contains well categorised technical reading material about mobile penetration testing, mobile malware, mobile forensics and all kind of mobile security related topics~~
6. ~~[Android Reverse Engineering 101 by Daniele Altomare](http://www.fasteque.com/android-reverse-engineering-101-part-1/)~~

## <a name="exploits"/></a>Exploits/Vulnerabilities/Bugs

### List

1. [Android Security Bulletins](https://source.android.com/security/bulletin/)
2. [Android's reported security vulnerabilities](https://www.cvedetails.com/vulnerability-list/vendor_id-1224/product_id-19997/Google-Android.html)
3. [Android Devices Security Patch Status](https://kb.androidtamer.com/Device_Security_Patch_tracker/)
4. [AOSP - Issue tracker](https://code.google.com/p/android/issues/list?can=2&q=priority=Critical&sort=-opened)
5. [OWASP Mobile Top 10 2016](https://www.owasp.org/index.php/Mobile_Top_10_2016-Top_10)
6. [Exploit Database](https://www.exploit-db.com/search/?action=search&q=android) - click search
7. [Vulnerability Google Doc](https://docs.google.com/spreadsheet/pub?key=0Am5hHW4ATym7dGhFU1A4X2lqbUJtRm1QSWNRc3E0UlE&single=true&gid=0&output=html)
8. [Google Android Security Team’s Classifications for Potentially Harmful Applications (Malware)](https://source.android.com/security/reports/Google_Android_Security_PHA_classifications.pdf)

### Malware

1. [androguard - Database Android Malwares wiki](https://code.google.com/p/androguard/wiki/DatabaseAndroidMalwares)
2. [Android Malware Github repo](https://github.com/ashishb/android-malware)
3. [Android Malware Genome Project](http://www.malgenomeproject.org/policy.html) - contains 1260 malware samples categorized into 49 different malware families, free for research purpose.
4. [Contagio Mobile Malware Mini Dump](http://contagiominidump.blogspot.com)
5. [VirusTotal Malware Intelligence Service](https://www.virustotal.com/en/about/contact/) - powered by VirusTotal, not free
6. [Drebin](https://www.sec.cs.tu-bs.de/~danarp/drebin/)
7. ~~[Admire](http://admire.necst.it/)~~

### Bounty Programs

1. [Android Security Reward Program](https://www.google.com/about/appsecurity/android-rewards/)

### How to report Security issues

1. [Android - reporting security issues](https://source.android.com/security/overview/updates-resources.html#report-issues)
2. [Android Reports and Resources](https://github.com/B3nac/Android-Reports-and-Resources) - List of Android Hackerone disclosed reports and other resources

## Contributing

Your contributions are always welcome!
