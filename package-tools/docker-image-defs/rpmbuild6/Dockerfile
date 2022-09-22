FROM amazonlinux:1

MAINTAINER IPiFony
LABEL maintainer="IPiFony"

# Yum
RUN yum -y update && \
    yum -y install rpmdevtools mock rpmlint git wget curl kernel-devel rpmdevtools rpmlint rpm-build sudo gcc-c++ make automake autoconf expect

# build files
ADD bin/build-spec /bin/
ADD bin/build-all /bin/
#ADD opt/go1.17.2.linux-amd64.tar.gz /usr/local/

# Sudo
ADD etc/sudoers.d/wheel /etc/sudoers.d/
RUN chown root:root /etc/sudoers.d/*

# Remove requiretty from sudoers main file
RUN sed -i '/Defaults    requiretty/c\#Defaults    requiretty' /etc/sudoers

# Rpm User
RUN adduser -G wheel rpmbuilder \
    && mkdir -p /home/rpmbuilder/rpmbuild/{BUILD,SPECS,SOURCES,BUILDROOT,RPMS,SRPMS,tmp} \
    && chmod -R 777 /home/rpmbuilder/rpmbuild

# Add another user and group with 1000 so that rpm won't complain about bad owner/group when building on default el7 boxes
RUN groupadd -g 1000 el7 \
    && useradd -u 1000 -g el7 -G wheel el7

#RUN mkdir -p /root
#RUN echo 'export GOROOT=/usr/local/go' >> /root/.bash_profile
#RUN echo 'export PATH=/usr/local/go/bin:$PATH' >> /root/.bash_profile


ADD .rpmmacros /home/rpmbuilder/

# ENV PATH /usr/local/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

USER rpmbuilder

WORKDIR /home/rpmbuilder
