#!/bin/bash
set -xeu
. /usr/lib/os-release
dn=$(cd $(dirname $0) && pwd)
case $ID in
  centos|rhel) dnf config-manager --set-enabled crb;;
  fedora) dnf -y install dnf-utils 'dnf5-command(builddep)';;
esac
dnf -y builddep ${dn}/../contrib/packaging/bootc.spec
# Extra dependencies
dnf -y install git-core
