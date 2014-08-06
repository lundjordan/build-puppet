#!/bin/bash
set -e

BUILD=$PWD/build
ROOT=$BUILD/installroot
OUT=dmg

REALNAME=unzip
VER=6.0
PACKAGE_FULLNAME=$REALNAME-$VER
PACKAGE_SHORTNAME=${REALNAME}60
TAR=$PACKAGE_SHORTNAME.tar.gz
URL=http://tcpdiag.dl.sourceforge.net/project/infozip/UnZip%206.x%20%28latest%29/UnZip%206.0/$TAR

# Clean build dir
if [ -d $BUILD ]; then
    rm -rf $BUILD
fi
mkdir $BUILD
cd $BUILD

# Download collectd tar.gz
curl -LO $URL

# unpack
tar -zxvf $TAR

# compile source
cd $PACKAGE_SHORTNAME
cp unix/Makefile .
mkdir -p $ROOT/usr/local
make generic

# install
make prefix=$ROOT/usr/local install
cd ..

# Make package
mkdir -p $OUT
PKG=$OUT/$PACKAGE_FULLNAME.pkg
DMG=$PACKAGE_FULLNAME.dmg
pkgbuild --root $ROOT --identifier org.$REALNAME.$REALNAME --install-location / $PKG

# make dmg
hdiutil makehybrid -hfs -hfs-volume-name "${PACKAGE_FULLNAME}" -o ./$DMG $OUT
echo "Result:"
echo $PWD/$DMG
