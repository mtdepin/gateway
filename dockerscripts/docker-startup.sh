#!/bin/sh
runningApp="minio"
#cd $(dirname $0)
BIN_DIR=$(pwd)
#cd ..
export ROCKETMQ_GO_LOG_LEVEL=error
SERVER_HOME="/opt/mtoss/minio"
echo "nohup $SERVER_HOME/$runningApp  > $SERVER_HOME/logs/stdout.out & "
nohup ./bin/minio gateway mtstorage --json > ./logs/stdout.out 2>&1 < /dev/null