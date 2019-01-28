#!/usr/bin/env bash
set -euxo pipefail


DEAD_URLS='opencollective.com','http://copperdroid.isg.rhul.ac.uk/copperdroid/','http://sanddroid.xjtu.edu.cn/','http://www.foresafe.com/scan','https://github.com/BaiduSecurityLabs/ZjDroid','https://github.com/yangbean9/ZjDroid','https://appanalysis.org/download.html','https://labs.mwrinfosecurity.com/tools/2012/03/16/mercury/','https://dexter.dexlabs.org/','http://www.mobiseclab.org/eacus.jsp','https://fireeye.ijinshan.com/','http://www.comdroid.org/','http://www.androidsandbox.net/','http://andrototal.org','http://www.mobile-app-insight.org','http://anubis.iseclab.org/','http://blog.avlyun.com/wp-content/uploads/2014/04/SmaliViewer.zip','habo.qq.com','www.fasteque.com','http://admire.necst.it/','tracedroid.few.vu.nl','appanalysis.org' \
FLAKY_URLS='http://safe.ijiami.cn/'
SRC_FILE=README.md
# Run `gem install awesome_bot` to install awesome_bot
awesome_bot \
  --allow-redirect \
  --allow-ssl \
  --skip-save-results \
  --white-list ${DEAD_URLS},${FLAKY_URLS} \
  --files ${SRC_FILE}
