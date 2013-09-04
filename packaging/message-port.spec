Name:       message-port
Summary:    Message Port library
Version: 	1.2.2.0
Release:    1
Group:		Application Framework/Libraries
License:    Apache-2.0
Source0:    %{name}-%{version}.tar.gz
Source1001: 	message-port.manifest
BuildRequires:  cmake
BuildRequires:  pkgconfig(dlog)
BuildRequires:  pkgconfig(bundle)
BuildRequires:  pkgconfig(glib-2.0)
BuildRequires:  pkgconfig(chromium)
BuildRequires:  pkgconfig(aul)

# runtime requires
Requires: chromium

Requires(post): /sbin/ldconfig  
Requires(post): coreutils
Requires(postun): /sbin/ldconfig

Provides:   libmessage-port.so.1

%description
Message Port library

%package devel
Summary:  Message Port library (Development)
Group:    Application Framework/Development
Requires: %{name} = %{version}-%{release}

%description devel
Message Port library (DEV)


%prep
%setup -q
cp %{SOURCE1001} .

%build
MAJORVER=`echo %{version} | awk 'BEGIN {FS="."}{print $1}'`
%cmake . -DFULLVER=%{version} -DMAJORVER=${MAJORVER}

# Call make instruction with smp support
make %{?jobs:-j%jobs}

%install
rm -rf %{buildroot}

%make_install
mkdir -p %{buildroot}/usr/share/license
install -m 0644 LICENSE.APLv2  %{buildroot}/usr/share/license/%{name}

%make_install

%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig


%files
%manifest %{name}.manifest
%{_libdir}/libmessage-port.so.*
%manifest message-port.manifest
%license /usr/share/license/%{name}

%files devel
%manifest %{name}.manifest
%{_includedir}/appfw/*.h
%{_libdir}/pkgconfig/*.pc
%{_libdir}/libmessage-port.so
