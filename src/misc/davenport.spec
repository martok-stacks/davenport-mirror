Summary: A Java servlet-based WebDAV gateway to a CIFS (SMB) network.
Group: System Environment/Daemons
License: LGPL

Name: davenport
Version: @VERSION@
Release: @RELEASE@

# Really, we *do* require J2RE.  But Sun's J2SDK RPM provides "j2sdk", not
# "j2re"; so if the user has the J2SDK installed, it will fail the dependency
# (unless they also go out and install the J2RE separately).  We could require
# "j2sdk", but we don't really need a compiler (as there aren't any JSPs
# involved).
#Requires: j2re
BuildRequires: j2sdk, ant

Source: http://umn.dl.sourceforge.net/sourceforge/davenport/davenport-@VERSION@-src.tgz
Prefix: /opt
BuildRoot: /var/tmp/%{name}-buildroot

%description
Davenport is a Java servlet-based WebDAV gateway to a CIFS network. This allows you to access Windows/Samba shares using any web browser. WebDAV clients (such as Windows Web Folders, Konqueror, etc.) can upload and download from the shares as if they were local folders.

%prep
%setup -q

%build
ant bin-distrib

%install
ant -DRPM_BUILD_ROOT="$RPM_BUILD_ROOT" rpm-install

%clean
ant -DRPM_BUILD_ROOT="$RPM_BUILD_ROOT" rpm-clean

%files -f rpm-files.txt
%doc license.txt CHANGES.txt
%doc /opt/davenport/doc
%config /opt/davenport/webapps/root/WEB-INF/web.xml
%config /opt/davenport/etc/admin.xml
%config /opt/davenport/etc/jetty.xml

