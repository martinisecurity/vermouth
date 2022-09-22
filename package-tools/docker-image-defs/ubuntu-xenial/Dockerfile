FROM ubuntu:xenial

MAINTAINER IPiFony
LABEL maintainer="IPiFony"

# Yum
#RUN yum -y update && \
#    yum -y install rpmdevtools mock rpmlint git wget curl kernel-devel rpmdevtools rpmlint rpm-build sudo gcc-c++ make automake autoconf expect

RUN apt-get -y update && \
	apt-get -y install apt gnupg pbuilder ubuntu-dev-tools apt-file

USER root

WORKDIR /root

