# android-security-awesome ![Awesome](https://cdn.rawgit.com/sindresorhus/awesome/d7305f38d29fed78fa85652e3a63e154dd8e8829/media/badge.svg)

[![Link Liveness Checker](https://github.com/ashishb/android-security-awesome/actions/workflows/validate-links.yml/badge.svg)](https://github.com/ashishb/android-security-awesome/actions/workflows/validate-links.yml)

[![Lint Shell scripts](https://github.com/ashishb/android-security-awesome/actions/workflows/lint-shell-script.yaml/badge.svg)](https://github.com/ashishb/android-security-awesome/actions/workflows/lint-shell-script.yaml)
[![Lint Markdown](https://github.com/ashishb/android-security-awesome/actions/workflows/lint-markdown.yaml/badge.svg)](https://github.com/ashishb/android-security-awesome/actions/workflows/lint-markdown.yaml)
[![Lint YAML](https://github.com/ashishb/android-security-awesome/actions/workflows/lint-yaml.yaml/badge.svg)](https://github.com/ashishb/android-security-awesome/actions/workflows/lint-yaml.yaml)
[![Lint GitHub Actions](https://github.com/ashishb/android-security-awesome/actions/workflows/lint-github-actions.yaml/badge.svg)](https://github.com/ashishb/android-security-awesome/actions/workflows/lint-github-actions.yaml)
![GitHub contributors](https://img.shields.io/github/contributors/ashishb/android-security-awesome)

A collection of Android security-related resources.

1. [Tools](#tools)
1. [Academic/Research/Publications/Books](#academic)
1. [Exploits/Vulnerabilities/Bugs](#exploits)

## Tools

### Online Analyzers

1. [AndroTotal](http://andrototal.org/)
1. [Appknox](https://www.appknox.com/) - not free
1. [Virustotal](https://www.virustotal.com/) - max 128MB
1. [Fraunhofer App-ray](http://app-ray.co/) - not free
1. [NowSecure Lab Automated](https://www.nowsecure.com/blog/2016/09/19/announcing-nowsecure-lab-automated/) - Enterprise tool for mobile app security testing both Android and iOS mobile apps. Lab Automated features dynamic and static analysis on real devices in the cloud to return results in minutes. Not free
1. [App Detonator](https://appdetonator.run/) - Detonate APK binary to provide source code level details, including app author, signature, build, and manifest information. 3 Analysis/day free quota.
1. [Pithus](https://beta.pithus.org/) - Open-Source APK analyzer. Still in Beta and limited to static analysis for the moment. It is possible to hunt malware with Yara rules. More [here](https://beta.pithus.org/about/).
1. [Oversecured](https://oversecured.com/) - Enterprise vulnerability scanner for Android and iOS apps; it offers app owners and developers the ability to secure each new version of a mobile app by integrating Oversecured into the development process. Not free.
1. [AppSweep by Guardsquare](https://appsweep.guardsquare.com/) - Free, fast Android application security testing for developers
1. [Koodous](https://koodous.com) - Performs static/dynamic malware analysis over a vast repository of Android samples and checks them against public and private Yara rules.
1. [Immuniweb](https://www.immuniweb.com/mobile/). Does an "OWASP Mobile Top 10 Test", "Mobile App Privacy Check", and an application permissions test. The free tier is 4 tests per day, including report after registration
1. ~~[BitBaan](https://malab.bitbaan.com/)~~
1. ~~[AVC UnDroid](http://undroid.av-comparatives.info/)~~
1. ~~[AMAaaS](https://amaaas.com) - Free Android Malware Analysis Service. A bare-metal service features static and dynamic analysis for Android applications. A product of [MalwarePot](https://malwarepot.com/index.php/AMAaaS)~~.
1. ~~[AppCritique](https://appcritique.boozallen.com) - Upload your Android APKs and receive comprehensive free security assessments~~
1. ~~[NVISO ApkScan](https://apkscan.nviso.be/) - sunsetting on Oct 31, 2019~~
1. ~~[Mobile Malware Sandbox](http://www.mobilemalware.com.br/analysis/index_en.php)~~
1. ~~[IBM Security AppScan Mobile Analyzer](https://appscan.bluemix.net/mobileAnalyzer) - not free~~
1. ~~[Visual Threat](https://www.visualthreat.com/) - no longer an Android app analyzer~~
1. ~~[Tracedroid](http://tracedroid.few.vu.nl/)~~
1. ~~[habo](https://habo.qq.com/) - 10/day~~
1. ~~[CopperDroid](http://copperdroid.isg.rhul.ac.uk/copperdroid/)~~
1. ~~[SandDroid](http://sanddroid.xjtu.edu.cn/)~~
1. ~~[Stowaway](http://www.android-permissions.org/)~~
1. ~~[Anubis](http://anubis.iseclab.org/)~~
1. ~~[Mobile app insight](http://www.mobile-app-insight.org)~~
1. ~~[Mobile-Sandbox](http://mobile-sandbox.com)~~
1. ~~[Ijiami](http://safe.ijiami.cn/)~~
1. ~~[Comdroid](http://www.comdroid.org/)~~
1. ~~[Android Sandbox](http://www.androidsandbox.net/)~~
1. ~~[Foresafe](http://www.foresafe.com/scan)~~
1. ~~[Dexter](https://dexter.dexlabs.org/)~~
1. ~~[MobiSec Eacus](http://www.mobiseclab.org/eacus.jsp)~~
1. ~~[Fireeye](https://fireeye.ijinshan.com/)- max 60MB 15/day~~
1. ~~[approver](https://approver.talos-sec.com/) - Approver  is a fully automated security analysis and risk assessment platform for Android and iOS apps. Not free.~~

### Static Analysis Tools

1. [Androwarn](https://github.com/maaaaz/androwarn/) - detect and warn the user about potential malicious behaviors developed by an Android application.
1. [ApkAnalyser](https://github.com/sonyxperiadev/ApkAnalyser)
1. [APKInspector](https://github.com/honeynet/apkinspector/)
1. [Droid Intent Data Flow Analysis for Information Leakage](https://insights.sei.cmu.edu/library/didfail/)
1. [DroidLegacy](https://bitbucket.org/srl/droidlegacy)
1. [FlowDroid](https://blogs.uni-paderborn.de/sse/tools/flowdroid/)
1. [Android Decompiler](https://www.pnfsoftware.com/) – not free
1. [PSCout](https://security.csl.toronto.edu/pscout/) - A tool that extracts the permission specification from the Android OS source code using static analysis
1. [Amandroid](http://amandroid.sireum.org/)
1. [SmaliSCA](https://github.com/dorneanu/smalisca) - Smali Static Code Analysis
1. [CFGScanDroid](https://github.com/douggard/CFGScanDroid) - Scans and compares the CFG against the CFG of malicious applications
1. [Madrolyzer](https://github.com/maldroid/maldrolyzer) - extracts actionable data like C&C, phone number etc.
1. [ConDroid](https://github.com/JulianSchuette/ConDroid) - Performs a combination of symbolic + concrete execution of the app
1. [DroidRA](https://github.com/serval-snt-uni-lu/DroidRA)
1. [RiskInDroid](https://github.com/ClaudiuGeorgiu/RiskInDroid) - A tool for calculating the risk of Android apps based on their permissions, with an online demo available.
1. [SUPER](https://github.com/SUPERAndroidAnalyzer/super) - Secure, Unified, Powerful, and Extensible Rust Android Analyzer
1. [ClassyShark](https://github.com/google/android-classyshark) - A Standalone binary inspection tool that can browse any Android executable and show important info.
1. [StaCoAn](https://github.com/vincentcox/StaCoAn) - Cross-platform tool that aids developers, bug-bounty hunters, and ethical hackers in performing static code analysis on mobile applications. This tool was created with a big focus on usability and graphical guidance in the user interface.
1. [JAADAS](https://github.com/flankerhqd/JAADAS) - Joint intraprocedural and interprocedural program analysis tool to find vulnerabilities in Android apps, built on Soot and Scala
1. [Quark-Engine](https://github.com/quark-engine/quark-engine) - An Obfuscation-Neglect Android Malware Scoring System
1. [One Step Decompiler](https://github.com/b-mueller/apkx) - Android APK Decompilation for the Lazy
1. [APKLeaks](https://github.com/dwisiswant0/apkleaks) - Scanning APK file for URIs, endpoints & secrets.
1. [Mobile Audit](https://github.com/mpast/mobileAudit) - Web application for performing Static Analysis and detecting malware in Android APKs.
1. ~~[Smali CFG generator](https://github.com/EugenioDelfa/Smali-CFGs)~~
1. ~~[Several tools from PSU](http://siis.cse.psu.edu/tools.html)~~
1. ~~[SPARTA](https://www.cs.washington.edu/sparta) - verifies (proves) that an app satisfies an information-flow security policy; built on the [Checker Framework](https://types.cs.washington.edu/checker-framework/)~~

### App Vulnerability Scanners

1. [QARK](https://github.com/linkedin/qark/) - QARK by LinkedIn is for app developers to scan apps for security issues
1. [AndroBugs](https://github.com/AndroBugs/AndroBugs_Framework)
1. [Nogotofail](https://github.com/google/nogotofail)
1. ~~[Devknox](https://devknox.io/) - IDE plugin to build secure Android apps. Not maintained anymore.~~

### Dynamic Analysis Tools

1. [Android DBI frameowork](http://www.mulliner.org/blog/blosxom.cgi/security/androiddbiv02.html)
1. [Androl4b](https://github.com/sh4hin/Androl4b)- A Virtual Machine For Assessing Android applications, Reverse Engineering and Malware Analysis
1. [House](https://github.com/nccgroup/house)- House: A runtime mobile application analysis toolkit with a Web GUI, powered by Frida, written in Python.
1. [Mobile-Security-Framework MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF) - Mobile Security Framework is an intelligent, all-in-one open-source mobile application (Android/iOS) automated pen-testing framework capable of performing static, dynamic analysis and web API testing.
1. [AppUse](https://appsec-labs.com/AppUse/) – custom build for penetration testing
1. [Droidbox](https://github.com/pjlantz/droidbox)
1. [Drozer](https://github.com/mwrlabs/drozer)
1. [Xposed](https://forum.xda-developers.com/xposed/xposed-installer-versions-changelog-t2714053) - equivalent of doing Stub-based code injection but without any modifications to the binary
1. [Inspeckage](https://github.com/ac-pm/Inspeckage) - Android Package Inspector - dynamic analysis with API hooks, start unexported activities, and more. (Xposed Module)
1. [Android Hooker](https://github.com/AndroidHooker/hooker) - Dynamic Java code instrumentation (requires the Substrate Framework)
1. [ProbeDroid](https://github.com/ZSShen/ProbeDroid) - Dynamic Java code instrumentation
1. [DECAF](https://github.com/sycurelab/DECAF) - Dynamic Executable Code Analysis Framework based on QEMU (DroidScope is now an extension to DECAF)
1. [CuckooDroid](https://github.com/idanr1986/cuckoo-droid) - Android extension for Cuckoo sandbox
1. [Mem](https://github.com/MobileForensicsResearch/mem) - Memory analysis of Android (root required)
1. [Crowdroid](http://www.ida.liu.se/labs/rtslab/publications/2011/spsm11-burguera.pdf) – unable to find the actual tool
1. [AuditdAndroid](https://github.com/nwhusted/AuditdAndroid) – Android port of auditd, not under active development anymore
1. [Android Security Evaluation Framework](https://code.google.com/p/asef/) - not under active development anymore
1. [Aurasium](https://github.com/xurubin/aurasium) – Practical security policy enforcement for Android apps via bytecode rewriting and in-place reference monitoring.
1. [Android Linux Kernel modules](https://github.com/strazzere/android-lkms)
1. [StaDynA](https://github.com/zyrikby/StaDynA) - a system supporting security app analysis in the presence of dynamic code update features (dynamic class loading and reflection). This tool combines static and dynamic analysis of Android applications in order to reveal the hidden/updated behavior and extend static analysis results with this information.
1. [DroidAnalytics](https://github.com/zhengmin1989/DroidAnalytics) - incomplete
1. [Vezir Project](https://github.com/oguzhantopgul/Vezir-Project) - Virtual Machine for Mobile Application Pentesting and Mobile Malware Analysis
1. [MARA](https://github.com/xtiankisutsa/MARA_Framework) - Mobile Application Reverse Engineering and Analysis Framework
1. [Taintdroid](http://appanalysis.org) - requires AOSP compilation
1. [ARTist](https://artist.cispa.saarland) - a flexible open-source instrumentation and hybrid analysis framework for Android apps and Android's Java middleware. It is based on the Android Runtime's (ART) compiler and modifies code during on-device compilation.
1. [Android Malware Sandbox](https://github.com/Areizen/Android-Malware-Sandbox)
1. [AndroPyTool](https://github.com/alexMyG/AndroPyTool) - a tool for extracting static and dynamic features from Android APKs. It combines different well-known Android app analysis tools such as DroidBox, FlowDroid, Strace, AndroGuard, or VirusTotal analysis.
1. [Runtime Mobile Security (RMS)](https://github.com/m0bilesecurity/RMS-Runtime-Mobile-Security) - is a powerful web interface that helps you to manipulate Android and iOS Apps at Runtime
1. [PAPIMonitor](https://github.com/Dado1513/PAPIMonitor) – PAPIMonitor (Python API Monitor for Android apps) is a Python tool based on Frida for monitoring user-select APIs during the app execution.
1. [Android_application_analyzer](https://github.com/NotSoSecure/android_application_analyzer) - The tool is used to analyze the content of the Android application in local storage.
1. [Decompiler.com](https://www.decompiler.com/) - Online APK and Java decompiler
1. [friTap](https://github.com/fkie-cad/friTap)- Intercept SSL/TLS connections with Frida; Allows TLS key extraction and decryption of TLS payload as PCAP on Android in real-time.
1. [HacknDroid](https://github.com/RaffaDNDM/HacknDroid) - A tool designed to automate various Mobile Application Penetration Testing (MAPT) tasks and facilitate interaction with Android devices.
1. [adbsploit](https://github.com/mesquidar/adbsploit) - tools for exploiting device via ADB
1. ~~[Appie](https://manifestsecurity.com/appie/) - Appie is a software package that has been pre-configured to function as an Android Pentesting Environment. It is completely portable and can be carried on a USB stick or smartphone. This is a one-stop answer for all the tools needed in Android Application Security Assessment and an awesome alternative to existing virtual machines.~~
1. ~~[Android Tamer](https://androidtamer.com/) - Virtual / Live Platform for Android Security Professionals~~
1. ~~[Android Malware Analysis Toolkit](http://www.mobilemalware.com.br/amat/download.html) - (Linux distro) Earlier, it used to be an [online analyzer](http://dunkelheit.com.br/amat/analysis/index_en.php)~~
1. ~~[Android Reverse Engineering](https://redmine.honeynet.org/projects/are/wiki) – ARE (android reverse engineering) is not under active development anymore~~
1. ~~[ViaLab Community Edition](https://www.nowsecure.com/blog/2014/09/09/introducing-vialab-community-edition/)~~
1. ~~[Mercury](https://labs.mwrinfosecurity.com/tools/2012/03/16/mercury/)~~
1. ~~[Cobradroid](https://thecobraden.com/projects/cobradroid/) – custom image for malware analysis~~

### Reverse Engineering

1. [Smali/Baksmali](https://github.com/JesusFreke/smali) – apk decompilation
1. [emacs syntax coloring for smali files](https://github.com/strazzere/Emacs-Smali)
1. [vim syntax coloring for smali files](http://codetastrophe.com/smali.vim)
1. [AndBug](https://github.com/swdunlop/AndBug)
1. [Androguard](https://github.com/androguard/androguard) – powerful, integrates well with other tools
1. [Apktool](https://ibotpeaches.github.io/Apktool/) – really useful for compilation/decompilation (uses smali)
1. [Android Framework for Exploitation](https://github.com/appknox/AFE)
1. [Bypass signature and permission checks for IPCs](https://github.com/iSECPartners/Android-KillPermAndSigChecks)
1. [Android OpenDebug](https://github.com/iSECPartners/Android-OpenDebug) – make any application on the device debuggable (using cydia substrate).
1. [Dex2Jar](https://github.com/pxb1988/dex2jar) - dex to jar converter
1. [Enjarify](https://github.com/google/enjarify) - dex to jar converter from Google
1. [Dedexer](https://sourceforge.net/projects/dedexer/)
1. [Fino](https://github.com/sysdream/fino)
1. [Frida](https://www.frida.re/) - inject JavaScript to explore applications and a [GUI tool](https://github.com/antojoseph/diff-gui) for it
1. [Indroid](https://bitbucket.org/aseemjakhar/indroid) – thread injection kit
1. [IntentSniffer](https://www.nccgroup.com/us/our-research/intent-sniffer/)
1. [Introspy](https://github.com/iSECPartners/Introspy-Android)
1. [Jad]( https://varaneckas.com/jad/) - Java decompiler
1. [JD-GUI](https://github.com/java-decompiler/jd-gui) - Java decompiler
1. [CFR](http://www.benf.org/other/cfr/) - Java decompiler
1. [Krakatau](https://github.com/Storyyeller/Krakatau) - Java decompiler
1. [FernFlower](https://github.com/fesh0r/fernflower) - Java decompiler
1. [Redexer](https://github.com/plum-umd/redexer) – apk manipulation
1. [Simplify Android deobfuscator](https://github.com/CalebFenton/simplify)
1. [Bytecode viewer](https://github.com/Konloch/bytecode-viewer)
1. [Radare2](https://github.com/radare/radare2)
1. [Jadx](https://github.com/skylot/jadx)
1. [Dwarf](https://github.com/iGio90/Dwarf) - GUI for reverse engineering
1. [Andromeda](https://github.com/secrary/Andromeda) - Another basic command-line reverse engineering tool
1. [apk-mitm](https://github.com/shroudedcode/apk-mitm) - A CLI application that prepares Android APK files for HTTPS inspection
1. [Noia](https://github.com/0x742/noia) - Simple Android application sandbox file browser tool
1. [Obfuscapk](https://github.com/ClaudiuGeorgiu/Obfuscapk) — Obfuscapk is a modular Python tool for obfuscating Android apps without requiring their source code.
1. [ARMANDroid](https://github.com/Mobile-IoT-Security-Lab/ARMANDroid) - ARMAND (Anti-Repackaging through Multi-pattern, Anti-tampering based on Native Detection) is a novel anti-tampering protection scheme that embeds logic bombs and AT detection nodes directly in the apk file without needing their source code.
1. [MVT (Mobile Verification Toolkit)](https://github.com/mvt-project/mvt) - a collection of utilities to simplify and automate the process of gathering forensic traces helpful to identify a potential compromise of Android and iOS devices
1. [Dexmod](https://github.com/google/dexmod) - a tool to exemplify patching Dalvik bytecode in a DEX (Dalvik Executable) file and assist in the static analysis of Android applications.
1. [odex-patcher](https://github.com/giacomoferretti/odex-patcher) - Run arbitrary code by patching OAT files
1. [PhoneSpolit-Pro](https://github.com/AzeemIdrisi/PhoneSploit-Pro) - An all-in-one hacking tool to remotely exploit Android devices using ADB and Metasploit Framework to get a Meterpreter session.
1. ~~[Procyon](https://bitbucket.org/mstrobel/procyon/wiki/Java%20Decompiler) - Java decompiler~~
1. ~~[Smali viewer](http://blog.avlyun.com/wp-content/uploads/2014/04/SmaliViewer.zip)~~
1. ~~[ZjDroid](https://github.com/BaiduSecurityLabs/ZjDroid)~~, ~~[fork/mirror](https://github.com/yangbean9/ZjDroid)~~
1. ~~[Dare](http://siis.cse.psu.edu/dare/index.html) – .dex to .class converter~~

### Fuzz Testing

1. [Radamsa Fuzzer](https://github.com/anestisb/radamsa-android)
1. [Honggfuzz](https://github.com/google/honggfuzz)
1. [An Android port of the Melkor ELF fuzzer](https://github.com/anestisb/melkor-android)
1. [Media Fuzzing Framework for Android](https://github.com/fuzzing/MFFA)
1. [AndroFuzz](https://github.com/jonmetz/AndroFuzz)
1. [QuarksLab's Android Fuzzing](https://github.com/quarkslab/android-fuzzing)
1. ~~[IntentFuzzer](https://www.nccgroup.trust/us/about-us/resources/intent-fuzzer/)~~

### App Repackaging Detectors

1. [FSquaDRA](https://github.com/zyrikby/FSquaDRA) - a tool for detecting repackaged Android applications based on app resources hash comparison.

### Market Crawlers

1. [Google Play crawler (Java)](https://github.com/Akdeniz/google-play-crawler)
1. [Google Play crawler (Python)](https://github.com/egirault/googleplay-api)
1. [Google Play crawler (Node)](https://github.com/dweinstein/node-google-play) - get app details and download apps from the official Google Play Store.
1. [Aptoide downloader (Node)](https://github.com/dweinstein/node-aptoide) - download apps from Aptoide third-party Android market
1. [Appland downloader (Node)](https://github.com/dweinstein/node-appland) - download apps from Appland third-party Android market
1. [PlaystoreDownloader](https://github.com/ClaudiuGeorgiu/PlaystoreDownloader) - PlaystoreDownloader is a tool for downloading Android applications directly from the Google Play Store. After an initial (one-time) configuration, applications can be downloaded by specifying their package name.
1. [APK Downloader](https://apkcombo.com/apk-downloader/) Online Service to download APK from the Play Store for a specific Android Device Configuration
1. ~~[Apkpure](https://apkpure.com/) - Online apk downloader. Also, it provides its own app for downloading.~~

### Misc Tools

1. [smalihook](http://androidcracking.blogspot.com/2011/03/original-smalihook-java-source.html)
1. [AXMLPrinter2](http://code.google.com/p/android4me/downloads/detail?name=AXMLPrinter2.jar) - to convert binary XML files to human-readable XML files
1. [adb autocomplete](https://github.com/mbrubeck/android-completion)
1. [mitmproxy](https://github.com/mitmproxy/mitmproxy)
1. [dockerfile/androguard](https://github.com/dweinstein/dockerfile-androguard)
1. [Android Vulnerability Test Suite](https://github.com/AndroidVTS/android-vts) - android-vts scans a device for set of vulnerabilities
1. [AppMon](https://github.com/dpnishant/appmon)- AppMon is an automated framework for monitoring and tampering with system API calls of native macOS, iOS, and Android apps. It is based on Frida.
1. [Internal Blue](https://github.com/seemoo-lab/internalblue) - Bluetooth experimentation framework based on the Reverse Engineering of Broadcom Bluetooth Controllers
1. [Android Mobile Device Hardening](https://github.com/SecTheTech/AMDH) - AMDH scans and hardens the device's settings and lists harmful installed Apps based on permissions.
1. [Firmware Extractor](https://github.com/AndroidDumps/Firmware_extractor) - Extract given archive to images
1. [ARMv7 payload that provides arbitrary code execution on MediaTek bootloaders](https://github.com/R0rt1z2/kaeru)  
1. ~~[Android Device Security Database](https://www.android-device-security.org/client/datatable) - Database of security features of Android devices~~
1. ~~[Opcodes table for quick reference](http://ww38.xchg.info/corkami/opcodes_tables.pdf)~~
1. ~~[APK-Downloader](http://codekiem.com/2012/02/24/apk-downloader/)~~ - seems dead now
1. ~~[Dalvik opcodes](http://pallergabor.uw.hu/androidblog/dalvik_opcodes.html)~~

### Vulnerable Applications for practice

1. [Damn Insecure Vulnerable Application (DIVA)](https://github.com/payatu/diva-android)
1. [Vuldroid](https://github.com/jaiswalakshansh/Vuldroid)
1. [ExploitMe Android Labs](http://securitycompass.github.io/AndroidLabs/setup.html)
1. [GoatDroid](https://github.com/jackMannino/OWASP-GoatDroid-Project)
1. [Android InsecureBank](https://github.com/dineshshetty/Android-InsecureBankv2)
1. [Insecureshop](https://github.com/optiv/insecureshop)
1. [Oversecured Vulnerable Android App (OVAA)](https://github.com/oversecured/ovaa)

## Academic/Research/Publications/Books

### Research Papers

1. [Exploit Database](https://www.exploit-db.com/papers/)
1. [Android security-related presentations](https://github.com/jacobsoo/AndroidSlides)
1. [A good collection of static analysis papers](https://tthtlc.wordpress.com/2011/09/01/static-analysis-of-android-applications/)

### Books

1. [SEI CERT Android Secure Coding Standard](https://wiki.sei.cmu.edu/confluence/display/android/Android+Secure+Coding+Standard)

### Others

1. [OWASP Mobile Security Testing Guide Manual](https://github.com/OWASP/owasp-mstg)
1. [doridori/Android-Security-Reference](https://github.com/doridori/Android-Security-Reference)
1. [android app security checklist](https://github.com/b-mueller/android_app_security_checklist)
1. [Mobile App Pentest Cheat Sheet](https://github.com/tanprathan/MobileApp-Pentest-Cheatsheet)
1. [Android Reverse Engineering 101 by Daniele Altomare (Web Archive link)](https://web.archive.org/web/20180721134044/http://www.fasteque.com:80/android-reverse-engineering-101-part-1/)
1. ~~[Mobile Security Reading Room](https://mobile-security.zeef.com) - A reading room that contains well-categorized technical reading material about mobile penetration testing, mobile malware, mobile forensics, and all kinds of mobile security-related topics~~

## Exploits/Vulnerabilities/Bugs

### List

1. [Android Security Bulletins](https://source.android.com/security/bulletin/)
1. [Android's reported security vulnerabilities](https://www.cvedetails.com/vulnerability-list/vendor_id-1224/product_id-19997/Google-Android.html)
1. [OWASP Mobile Top 10 2016](https://www.owasp.org/index.php/Mobile_Top_10_2016-Top_10)
1. [Exploit Database](https://www.exploit-db.com/search/?action=search&q=android) - click search
1. [Vulnerability Google Doc](https://docs.google.com/spreadsheet/pub?key=0Am5hHW4ATym7dGhFU1A4X2lqbUJtRm1QSWNRc3E0UlE&single=true&gid=0&output=html)
1. [Google Android Security Team’s Classifications for Potentially Harmful Applications (Malware)](https://source.android.com/security/reports/Google_Android_Security_PHA_classifications.pdf)
1. ~~[Android Devices Security Patch Status](https://kb.androidtamer.com/Device_Security_Patch_tracker/)~~

### Malware

1. [androguard - Database Android Malware wiki](https://code.google.com/p/androguard/wiki/DatabaseAndroidMalwares)
1. [Android Malware Github repo](https://github.com/ashishb/android-malware)
1. [Android Malware Genome Project](http://www.malgenomeproject.org/) - contains 1260 malware samples categorized into 49 different malware families, free for research purposes.
1. [Contagio Mobile Malware Mini Dump](http://contagiominidump.blogspot.com)
1. [Drebin](https://www.sec.tu-bs.de/~danarp/drebin/)
1. [Hudson Rock](https://www.hudsonrock.com/threat-intelligence-cybercrime-tools) - A Free cybercrime intelligence toolset that can indicate if a specific APK package was compromised in an Infostealer malware attack.
1. [Kharon Malware Dataset](http://kharon.gforge.inria.fr/dataset/) - 7 malware which have been reverse-engineered and documented
1. [Android Adware and General Malware Dataset](https://www.unb.ca/cic/datasets/android-adware.html)
1. [AndroZoo](https://androzoo.uni.lu/) - AndroZoo is a growing Android application collection from several sources, including the official Google Play app market.
1. ~~[Android PRAGuard Dataset](http://pralab.diee.unica.it/en/AndroidPRAGuardDataset) - The dataset contains 10479 samples, obtained by obfuscating the MalGenome and the Contagio Minidump datasets with seven different obfuscation techniques.~~
1. ~~[Admire](http://admire.necst.it/)~~

### Bounty Programs

1. [Android Security Reward Program](https://www.google.com/about/appsecurity/android-rewards/)

### How to report Security issues

1. [Android - reporting security issues](https://source.android.com/security/overview/updates-resources.html#report-issues)
1. [Android Reports and Resources](https://github.com/B3nac/Android-Reports-and-Resources) - List of Android Hackerone disclosed reports and other resources

## Contributing

Your contributions are always welcome!
