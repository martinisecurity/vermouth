#!/bin/sh
SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
cd "${SCRIPT_DIR}"
source ./getversion.sh
rm -rf work
mkdir -p work
cd ..
export RPM_BUILD_ROOT="${SCRIPT_DIR}/work/target"
mkdir -p "${RPM_BUILD_ROOT}"
export GOOS=linux
export GOARCH=amd64
make compile
make install
cd "${SCRIPT_DIR}"
mkdir -p "${SCRIPT_DIR}/rpm-sources"
rm -rf "${SCRIPT_DIR}/rpm-sources/vermouth"
cp "${SCRIPT_DIR}/work/target/usr/bin/vermouth" "${SCRIPT_DIR}/rpm-sources/vermouth"
rm -rf "${SCRIPT_DIR}/work/target"
rm -rf "${SCRIPT_DIR}/work/RPMS"
mkdir -p "${SCRIPT_DIR}/work/RPMS"
rm -rf "${SCRIPT_DIR}/work/rpm-specs"
mkdir -p "${SCRIPT_DIR}/work/rpm-specs"
sed -e "s/VERSION_STRING/$VERSION/g" "${SCRIPT_DIR}/rpm-specs/vermouth.spec" > "${SCRIPT_DIR}/work/rpm-specs/vermouth.spec"
rm -rf "${SCRIPT_DIR}/built-rpms"
mkdir -p "${SCRIPT_DIR}/built-rpms"
rm -rf "${SCRIPT_DIR}/work/debian-tree"
mkdir -p "${SCRIPT_DIR}/work/debian-tree"
cp -R "${SCRIPT_DIR}/deb-sources/DEBIAN" "${SCRIPT_DIR}/work/debian-tree"
cp -R "${SCRIPT_DIR}/deb-sources/etc" "${SCRIPT_DIR}/work/debian-tree"
cp -R "${SCRIPT_DIR}/deb-sources/lib" "${SCRIPT_DIR}/work/debian-tree"
sed -e "s/VERSION_STRING/$VERSION/g" "${SCRIPT_DIR}/deb-sources/DEBIAN/control" > "${SCRIPT_DIR}/work/debian-tree/DEBIAN/control"
mkdir -p "${SCRIPT_DIR}/work/debian-tree/usr/bin"
cp "${SCRIPT_DIR}/rpm-sources/vermouth" "${SCRIPT_DIR}/work/debian-tree/usr/bin/vermouth"
chmod a+rx "${SCRIPT_DIR}/work/debian-tree/usr/bin/vermouth"
mkdir -p "${SCRIPT_DIR}/work/debian-tree/var/lib/vermouth/cache"
mkdir -p "${SCRIPT_DIR}/work/debian-tree/var/lib/vermouth/certs/sti_pa"
chmod og-rwx "${SCRIPT_DIR}/work/debian-tree/var/lib/vermouth/cache"
chmod og-rwx "${SCRIPT_DIR}/work/debian-tree/var/lib/vermouth/certs"
rm -rf "${SCRIPT_DIR}/work/debian-return"
mkdir -p "${SCRIPT_DIR}/work/debian-return"
rm -rf "${SCRIPT_DIR}/ubuntu-deb"
mkdir -p "${SCRIPT_DIR}/ubuntu-deb"
#rm -f "${SCRIPT_DIR}/rpm-sources/STI-PA_CRL_SIGNER.pem"
rm -f "${SCRIPT_DIR}/rpm-sources/STI-PA_ROOT.pem"
#rm -f "${SCRIPT_DIR}/rpm-sources/STI-PA_STAGING_CRL_SIGNER.pem"
rm -f "${SCRIPT_DIR}/rpm-sources/STI-PA_STAGING_ROOT.pem"
#cp "${SCRIPT_DIR}/../certs/sti_pa/STI-PA_CRL_SIGNER.pem" "${SCRIPT_DIR}/rpm-sources/STI-PA_CRL_SIGNER.pem"
cp "${SCRIPT_DIR}/../certs/sti_pa/STI-PA_ROOT.pem" "${SCRIPT_DIR}/rpm-sources/STI-PA_ROOT.pem"
#cp "${SCRIPT_DIR}/../certs/sti_pa/STI-PA_STAGING_CRL_SIGNER.pem" "${SCRIPT_DIR}/rpm-sources/STI-PA_STAGING_CRL_SIGNER.pem"
cp "${SCRIPT_DIR}/../certs/sti_pa/STI-PA_STAGING_ROOT.pem" "${SCRIPT_DIR}/rpm-sources/STI-PA_STAGING_ROOT.pem"
#cp "${SCRIPT_DIR}/../certs/sti_pa/STI-PA_CRL_SIGNER.pem" "${SCRIPT_DIR}/work/debian-tree/var/lib/vermouth/certs/sti_pa/STI-PA_CRL_SIGNER.pem"
cp "${SCRIPT_DIR}/../certs/sti_pa/STI-PA_ROOT.pem" "${SCRIPT_DIR}/work/debian-tree/var/lib/vermouth/certs/sti_pa/STI-PA_ROOT.pem"
#cp "${SCRIPT_DIR}/../certs/sti_pa/STI-PA_STAGING_CRL_SIGNER.pem" "${SCRIPT_DIR}/work/debian-tree/var/lib/vermouth/certs/sti_pa/STI-PA_STAGING_CRL_SIGNER.pem"
cp "${SCRIPT_DIR}/../certs/sti_pa/STI-PA_STAGING_ROOT.pem" "${SCRIPT_DIR}/work/debian-tree/var/lib/vermouth/certs/sti_pa/STI-PA_STAGING_ROOT.pem"

# call docker runs to build
docker run -it -v "${SCRIPT_DIR}/work/RPMS":"/home/rpmbuilder/rpmbuild/RPMS" -v "${SCRIPT_DIR}/work/rpm-specs":"/home/rpmbuilder/rpmbuild/SPECS" -v "${SCRIPT_DIR}/rpm-sources":"/home/rpmbuilder/rpmbuild/SOURCES" --rm=true vermouth/rpmbuild6 /usr/bin/rpmbuild -bb rpmbuild/SPECS/vermouth.spec
cp "${SCRIPT_DIR}/work/RPMS/x86_64/"*.rpm "${SCRIPT_DIR}/built-rpms"
rm -rf "${SCRIPT_DIR}/work/RPMS"
mkdir -p "${SCRIPT_DIR}/work/RPMS"
docker run -it -v "${SCRIPT_DIR}/work/RPMS":"/home/rpmbuilder/rpmbuild/RPMS" -v "${SCRIPT_DIR}/work/rpm-specs":"/home/rpmbuilder/rpmbuild/SPECS" -v "${SCRIPT_DIR}/rpm-sources":"/home/rpmbuilder/rpmbuild/SOURCES" --rm=true vermouth/rpmbuild7 /usr/bin/rpmbuild -bb rpmbuild/SPECS/vermouth.spec
docker run -it -v "${SCRIPT_DIR}/work/debian-tree":"/root/vermouth" -v "${SCRIPT_DIR}/work/debian-return":"/root/deb-out" --rm=true vermouth/debpkg /usr/bin/dpkg-deb --build vermouth deb-out/vermouth.deb
cp "${SCRIPT_DIR}/work/RPMS/x86_64/"*.rpm "${SCRIPT_DIR}/built-rpms"
rm -rf "${SCRIPT_DIR}/work/debian-tree"
rm -f "${SCRIPT_DIR}/ubuntu-deb/*.deb"
cp "${SCRIPT_DIR}/work/debian-return/vermouth.deb" "${SCRIPT_DIR}/ubuntu-deb/vermouth-${VERSION}-1.deb"
rm -rf "${SCRIPT_DIR}/work/debian-return"
rm -rf "${SCRIPT_DIR}/work/RPMS"
rm -rf "${SCRIPT_DIR}/work/rpm-specs"
rm -f "${SCRIPT_DIR}/rpm-sources/vermouth"
rm -f "${SCRIPT_DIR}/rpm-sources/"*.pem

