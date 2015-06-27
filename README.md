android-security-awesome
========================

A collection of android security related resources.

A lot of work is happening in academia and industry on tools to perform dynamic analysis, static analysis and reverse engineering of android apps.


## ONLINE ANALYZERS

1. [AndroTotal](http://andrototal.org/)
2. [Anubis](http://anubis.iseclab.org/)
3. [App 360 scan](http://www.app360scan.com/)
4. [CopperDroid](http://copperdroid.isg.rhul.ac.uk/copperdroid/)
6. [Dexter](https://dexter.bluebox.com/)
7. [Foresafe](http://www.foresafe.com/scan)
8. [Mobile app insight](http://www.mobile-app-insight.org)
9. [Mobile-Sandbox](http://mobile-sandbox.com)
10. [Sandroid](http://sanddroid.xjtu.edu.cn/)
11. [Tracedroid](http://tracedroid.few.vu.nl/)
12. [Visual Threat](http://www.visualthreat.com/)
13. [Android Sandbox](http://www.androidsandbox.net/)
14. [Mobile Malware Sandbox](http://www.mobilemalware.com.br/analysis/index_en.php)
15. [MobiSec Eacus](http://www.mobiseclab.org/eacus.jsp)
15. [IBM Security AppScan Mobile Analyzer](https://appscan.bluemix.net/mobileAnalyzer) - not free
16. [NVISO ApkScan](http://apkscan.nviso.be/)
17. [AVC UnDroid](http://www.av-comparatives.org/avc-analyzer/)
14. [Stowaway](http://www.android-permissions.org/) – seems to be dead now
15. [Comdroid](http://www.comdroid.org/) - seems to be dead now

## STATIC ANALYSIS TOOLS

2. [Androwarn](https://github.com/maaaaz/androwarn/)
3. [ApkAnalyser](https://github.com/sonyxperiadev/ApkAnalyser)
4. [APKInspector](https://github.com/honeynet/apkinspector/)
5. [Droid Intent Data Flow Analysis for Information Leakage](https://www.cert.org/secure-coding/tools/didfail.cfm)
6. [Several tools from PSU](http://siis.cse.psu.edu/tools.html)
7. [Smali CFG generator](http://code.google.com/p/smali-cfgs/)
8. [FlowDroid](http://sseblog.ec-spride.de/tools/flowdroid/)
9. [Android Decompiler](http://www.android-decompiler.com/) – not free
10. [PSCout](http://pscout.csl.toronto.edu/) - A tool that extracts the permission specification from the Android OS source code using static analysis
11. [Amandroid](http://amandroid.sireum.org/)
12. [SmaliSCA](https://github.com/dorneanu/smalisca) - Smali Static Code Analysis
13. [CFGScanDroid](https://github.com/douggard/CFGScanDroid) - Scans and compares CFG against CFG of malicious applications
14. [Madrolyzer](https://github.com/maldroid/maldrolyzer) - extracts actionable data like C&C, phone number etc.

## DYNAMIC ANALYSIS TOOLS

1. [Android DBI frameowork](http://www.mulliner.org/blog/blosxom.cgi/security/androiddbiv02.html)
2. [Android Malware Analysis Toolkit](http://www.mobilemalware.com.br/amat/download.html) - (linux distro) Earlier it use to be an [online analyzer](http://dunkelheit.com.br/amat/analysis/index_en.html)
5. [AppUse](https://appsec-labs.com/AppUse) – custom build for pentesting
7. [Cobradroid](http://thecobraden.com/projects/cobradroid/) – custom image for malware analysis
8. [ViaLab Community Edition](https://viaforensics.com/product-updates/introducing-vialab-community-edition.html)
9. [Droidbox](http://code.google.com/p/droidbox/)
10. [Mercury](http://labs.mwrinfosecurity.com/tools/2012/03/16/mercury/)
11. [Drozer](https://labs.mwrinfosecurity.com/tools/drozer/)
12. [Taintdroid](http://appanalysis.org/download.html) - requires AOSP compilation
13. [Xposed](http://forum.xda-developers.com/showthread.php?t=1574401) - equivalent of doing Stub based code injection but without any modifications to the binary
15. [Android Hooker](https://github.com/AndroidHooker/hooker) - API Hooking of java methods triggered by any Android application (requires the Substrate Framework)
16. [Android tamer](https://androidtamer.com/) - custom image
17. [Droidscope](https://code.google.com/p/decaf-platform/wiki/DroidScope) - custom image for dynamic analysis
16. [Crowdroid](http://www.ida.liu.se/labs/rtslab/publications/2011/spsm11-burguera.pdf) – unable to find the actual tool
16. [AuditdAndroid](https://github.com/nwhusted/AuditdAndroid) – android port of auditd, not under active development anymore
16. [Android Security Evaluation Framework](https://code.google.com/p/asef/) - not under active development anymore
18. [Android Reverse Engineering](https://redmine.honeynet.org/projects/are/wiki) – ARE (android reverse engineering) not under active development anymore
19. [Ijiami (Chinese)](http://safe.ijiami.cn/) - seems dead now
16. [Aurasium](http://www.aurasium.com/) – rewrites the android app to add security policy, seems dead now
17. [Android Linux Kernel modules](https://github.com/strazzere/android-lkms)
18. [Appie](http://manifestsecurity.com/appie/) - Appie is a software package that has been pre-configured to function as an Android Pentesting Environment.It is completely portable and can be carried on USB stick or smartphone.This is a one stop answer for all the tools needed in Android Application Security Assessment and an awesome alternative to existing virtual machines.
19. [StaDynA](https://github.com/zyrikby/StaDynA) - a system supporting security app analysis in the presence of dynamic code update features (dynamic class loading and reflection). This tool combines static and dynamic analysis of Android applications in order to reveal the hidden/updated behavior and extend static analysis results with this information.
20. [DroidAnalytics](https://github.com/zhengmin1989/DroidAnalytics) - incomplete

## REVERSE ENGINEERING

1. [Smali/Baksmali](http://code.google.com/p/smali/) – apk decompilation
3. [emacs syntax coloring for smali files](https://github.com/strazzere/Emacs-Smali)
4. [vim syntax coloring for smali files](http://codetastrophe.com/smali.vim)
5. [AndBug](https://github.com/swdunlop/AndBug)
6. [Androguard](https://github.com/androguard/androguard) – powerful, integrates well with other tools
7. [Apktool](http://code.google.com/p/android-apktool/) – really useful for compilation/decompilation (uses smali)
8. [Android Framework for Exploitation](https://github.com/xysec/AFE)
9. [Bypass signature and permission checks for IPCs](https://github.com/iSECPartners/Android-KillPermAndSigChecks)
10. [Android OpenDebug](https://github.com/iSECPartners/Android-OpenDebug) – make any application on device debuggable (using cydia substrate).
11. [Dare](http://siis.cse.psu.edu/dare/index.html) – .dex to .class converter
12. [Dex2Jar](http://code.google.com/p/dex2jar/) - dex to jar converter
13. [Enjarify](https://github.com/google/enjarify) - dex to jar converter from Google
13. [Dedexer](http://dedexer.sourceforge.net)
14. [Fino](https://github.com/sysdream/fino)
15. [Indroid](https://bitbucket.org/aseemjakhar/indroid) – thread injection kit
16. [IntentFuzzer](https://www.isecpartners.com/tools/mobile-security/intent-fuzzer.aspx)
17. [IntentSniffer](https://www.isecpartners.com/tools/mobile-security/intent-sniffer.aspx)
18. [Introspy](https://github.com/iSECPartners/Introspy-Android)
19. [Jad]( http://www.varaneckas.com/jad) - Java decompiler
20. [JD-GUI](http://java.decompiler.free.fr/?q=jdgui) - Java decompiler
21. [CFR](http://www.benf.org/other/cfr/) - Java decompiler
22. [Krakatau](https://github.com/Storyyeller/Krakatau) - Java decompiler
23. [Procyon](https://bitbucket.org/mstrobel/procyon/wiki/Java%20Decompiler) - Java decompiler
24. [FernFlower](https://github.com/fesh0r/fernflower) - Java decompiler
21. [Redexer](https://github.com/plum-umd/redexer) – apk manipulation
22. [Smali viewer](http://blog.avlyun.com/wp-content/uploads/2014/04/SmaliViewer.zip)
23. [ZjDroid](https://github.com/BaiduSecurityLabs/ZjDroid) (no longer available), [fork/mirror](https://github.com/yangbean9/ZjDroid)
24. [Simplify Android deobfuscator](https://github.com/CalebFenton/simplify)
25. [Bytecode viewer](https://github.com/Konloch/bytecode-viewer)
26. [Krakatau](https://github.com/Storyyeller/Krakatau)

##APP REPACKAGING DETECTORS

1. [FSquaDRA](https://github.com/zyrikby/FSquaDRA) - a tool for detection of repackaged Android applications based on app resources hash comparison.

## Exploitable Vulnerabilties

1. [Vulnerability Google
   doc](https://docs.google.com/spreadsheet/pub?key=0Am5hHW4ATym7dGhFU1A4X2lqbUJtRm1QSWNRc3E0UlE&single=true&gid=0&output=html)
2. [Root Exploits (from Drozer issue
   #56)](https://github.com/mwrlabs/drozer/issues/56)

## SAMPLE SOURCES

1. [contagio mini dump](http://contagiominidump.blogspot.com)
2. [Open Source database](http://code.google.com/p/androguard/wiki/DatabaseAndroidMalwares)
3. [Drebin](http://user.informatik.uni-goettingen.de/~darp/drebin/)

## BOOKS

1. [Android Security (and Not) Internals](http://www.zhauniarovich.com/pubs.html)

## MISC TOOLS/READINGS

1. [smalihook](http://androidcracking.blogspot.com/2011/03/original-smalihook-java-source.html)
2. [APK-Downloader](http://codekiem.com/2012/02/24/apk-downloader/)
3. [AXMLPrinter2](http://code.google.com/p/android4me/downloads/detail?name=AXMLPrinter2.jar) - to convert binary XML files to human-readable XML files
4. [An Android port of the melkor ELF fuzzer](https://github.com/anestisb/melkor-android)
5. [adb autocomplete](https://romannurik-code.googlecode.com/git/bash_completion/adb)
6. [Dalvik opcodes](http://pallergabor.uw.hu/androidblog/dalvik_opcodes.html)
7. [Opcodes table for quick reference](http://xchg.info/corkami/opcodes_tables.pdf)
8. [A good collection of static analysis papers](http://tthtlc.wordpress.com/2011/09/01/static-analysis-of-android-applications/)
9. [ExploitMe](http://securitycompass.github.io/AndroidLabs/setup.html) - for practice
10. [GoatDroid](https://github.com/jackMannino/OWASP-GoatDroid-Project) - for practice
11. [Android Labs](http://securitycompass.github.io/AndroidLabs/setup.html) - for practice
12. [mitmproxy](https://github.com/mitmproxy/mitmproxy)
13. [dockerfile/androguard](https://github.com/dweinstein/dockerfile-androguard)

# Other Awesome Lists
Other amazingly awesome lists can be found in the
[awesome-awesomeness](https://github.com/bayandin/awesome-awesomeness) list.

# Contributing
Your contributions are always welcome!
 
