FROM harbor.mty.wang/gobase/ubuntu:20.04
RUN   mkdir -p /opt/mtoss/minio /opt/mtoss/minio/logs /opt/mtoss/minio/bin
ENV WORK_HOME  /opt/mtoss/minio
COPY  minio /opt/mtoss/minio/bin/
COPY  ./conf  /opt/mtoss/minio/conf
COPY  ./dockerscripts/docker-startup.sh  /opt/mtoss/minio
RUN chmod +x $WORK_HOME/docker-startup.sh
WORKDIR $WORK_HOME
EXPOSE     9000
EXPOSE     9001
ENTRYPOINT ["./docker-startup.sh"]

#CMD ["/opt/mtoss/minio", "gateway", "mtstorage"]