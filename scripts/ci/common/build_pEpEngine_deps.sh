#!/usr/bin/env sh
set -exo

### Test Deps
git clone https://github.com/google/gtest-parallel.git $BUILDROOT/gtest-parallel

### sequoia
echo SEQUOIA_VERSION=${SEQUOIA_VERSION}
git clone --depth=1 https://gitea.pep.foundation/pEp.foundation/pEpEngineSequoiaBackend -b ${SEQUOIA_VERSION} $BUILDROOT/pEpEngineSequoiaBackend
cd $BUILDROOT/pEpEngineSequoiaBackend
make build
make install

### YML2
cd $INSTPREFIX
curl -O "https://gitea.pep.foundation/fdik/yml2/archive/${YML2_VERSION}.tar.gz"
tar -xf "${YML2_VERSION}.tar.gz"
rm -f ${YML2_VERSION}.tar*


### libetpan
git clone https://gitea.pep.foundation/pEp.foundation/libetpan $BUILDROOT/libetpan
cd $BUILDROOT/libetpan
test -f configure || NOCONFIGURE=absolutely ./autogen.sh
./configure --prefix=${INSTPREFIX}/libetpan \
    --without-openssl --without-gnutls --without-sasl \
    --without-curl --without-expat --without-zlib \
    --disable-dependency-tracking
make -j$(nproc)
make install
echo "${libetpan_ver}">${INSTPREFIX}/libetpan.ver


### ASN1c
git clone https://github.com/vlm/asn1c.git $BUILDROOT/asn1c
cd $BUILDROOT/asn1c
git checkout tags/v0.9.28 -b pep-engine
test -f configure || autoreconf -iv
./configure --prefix=${INSTPREFIX}/asn1c
make -j$(nproc) && make install
echo "${asn1c_ver}">${INSTPREFIX}/asn1c.ver

### libpEpTransport
git clone https://gitea.pep.foundation/pEp.foundation/libpEpTransport.git $BUILDROOT/libpEpTransport
cd $BUILDROOT/libpEpTransport
git checkout "${PEPTRANSPORT_VERSION}"
cat >local.conf <<__LOCAL__
PREFIX=${INSTPREFIX}
YML2_PATH=${INSTPREFIX}/yml2
__LOCAL__
make src
make install
