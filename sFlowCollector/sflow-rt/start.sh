#!/bin/sh

HOME=`dirname $0`
cd $HOME

RTMEM="${RTMEM:-200M}"
RTMEMLIMITS="${RTMEMLIMITS:--Xms${RTMEM} -Xmx${RTMEM}}"
RTGC="${RTGC:--XX:+UseG1GC -XX:+UseStringDeduplication -XX:MaxGCPauseMillis=100}"

JAR="./lib/sflowrt.jar"

exec /usr/lib/jvm/java-11-openjdk-amd64/bin/java ${RTMEMLIMITS} ${RTGC} ${RTAPP} ${RTPROP} $@ -jar ${JAR}

