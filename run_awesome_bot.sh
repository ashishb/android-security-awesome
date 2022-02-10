#!/usr/bin/env bash
set -euxo pipefail


DEAD_URLS='opencollective.com','http://copperdroid.isg.rhul.ac.uk/copperdroid/',\
'http://sanddroid.xjtu.edu.cn/','http://www.foresafe.com/scan',\
'https://github.com/BaiduSecurityLabs/ZjDroid','https://github.com/yangbean9/ZjDroid',\
'https://appanalysis.org/download.html','https://labs.mwrinfosecurity.com/tools/2012/03/16/mercury/',\
'https://dexter.dexlabs.org/','http://www.mobiseclab.org/eacus.jsp','https://fireeye.ijinshan.com/',\
'http://www.comdroid.org/','http://www.androidsandbox.net/','http://andrototal.org',\
'http://www.mobile-app-insight.org','http://anubis.iseclab.org/',\
'http://blog.avlyun.com/wp-content/uploads/2014/04/SmaliViewer.zip',\
'habo.qq.com','http://admire.necst.it/','tracedroid.few.vu.nl',\
'http://appanalysis.org','http://dunkelheit.com.br','https://mobile-security.zeef.com',\
'https://redmine.honeynet.org/projects/are/wiki','https://www.visualthreat.com/',\
'http://www.mobilemalware.com.br','https://appscan.bluemix.net',\
'http://siis.cse.psu.edu/tools.html','http://siis.cse.psu.edu/dare/index.html',\
'http://codekiem.com/2012/02/24/apk-downloader/','https://apkscan.nviso.be',\
'http://ww38.xchg.info','https://thecobraden.com/projects/cobradroid',\
'https://bitbucket.org/mstrobel/procyon/wiki/',\
'https://code.google.com/p/androguard/wiki/DatabaseAndroidMalwares',\
'https://github.com/ashishb/android-security-awesome/actions',\
'https://pscout.csl.toronto.edu',\
'https://appcritique.boozallen.com',\
'https://amaaas.com',\
'https://malwarepot.com/index.php/AMAaaS'

FLAKY_URLS='http://safe.ijiami.cn/',\
'https://apkcombo.com/apk-downloader/'

SRC_FILE=README.md
# Run `gem install awesome_bot` to install awesome_bot
awesome_bot \
  --allow-redirect \
  --allow-ssl \
  --skip-save-results \
  --request-delay 1 \
  --white-list ${DEAD_URLS},${FLAKY_URLS} \
  --files ${SRC_FILE}
