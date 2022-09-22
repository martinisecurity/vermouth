Name:           vermouth
Version:        VERSION_STRING
Release:        1%{?dist}
Summary:        STIR/SHAKEN processing server for STI-AS, STI-VS, STI-CR (cache) functions

Group:          System Environment/Daemons
License:        Proprietary
URL:            https://martinisecurity.com
Source0:        %{name}
Source1:        %{name}.sysconfig
Source2:        %{name}.service
Source3:        %{name}.init
Source4:	%{name}.config
Source6:	STI-PA_ROOT.pem
Source8:	STI-PA_STAGING_ROOT.pem
Source9:	%{name}.logrotate6
Source10:	%{name}.logrotate7

%if 0%{?amzn} >= 2
BuildRequires:  systemd-units
Requires:       systemd
%endif

%description
STIR/SHAKEN processing server for STI-AS, STI-VS, STI-CR (cache) functions

%install
mkdir -p %{buildroot}/usr/bin
cp %{SOURCE0} %{buildroot}/usr/bin/%{name}
mkdir -p %{buildroot}/%{_sysconfdir}/sysconfig
cp %{SOURCE1} %{buildroot}/%{_sysconfdir}/sysconfig/%{name}
cp %{SOURCE4} %{buildroot}/%{_sysconfdir}/%{name}
mkdir -p %{buildroot}/%{_sysconfdir}/logrotate.d
%if 0%{?amzn} >= 2
cp %{SOURCE10} %{buildroot}/%{_sysconfdir}/logrotate.d/%{name}
%else
cp %{SOURCE9} %{buildroot}/%{_sysconfdir}/logrotate.d/%{name}
%endif
mkdir -p %{buildroot}/%{_sharedstatedir}/%{name}/certs/sti_pa
mkdir -p %{buildroot}/%{_sharedstatedir}/%{name}/cache
cp %{SOURCE6} %{buildroot}/%{_sharedstatedir}/%{name}/certs/sti_pa/STI-PA_ROOT.pem
cp %{SOURCE8} %{buildroot}/%{_sharedstatedir}/%{name}/certs/sti_pa/STI-PA_STAGING_ROOT.pem


%if 0%{?amzn} >= 2
mkdir -p %{buildroot}/%{_unitdir}
cp %{SOURCE2} %{buildroot}/%{_unitdir}/
%else
mkdir -p %{buildroot}/%{_initrddir}
cp %{SOURCE3} %{buildroot}/%{_initrddir}/%{name}
%endif

%if 0%{?amzn} >= 2
%post
%systemd_post %{name}.service

%preun
%systemd_preun %{name}.service

%postun
%systemd_postun_with_restart %{name}.service
%else
%post
/sbin/chkconfig --add %{name}

%preun
if [ "$1" = 0 ] ; then
    /sbin/service %{name} stop >/dev/null 2>&1
    /sbin/chkconfig --del %{name}
fi
%endif

%clean
rm -rf %{buildroot}


%files
%defattr(-,root,root,-)
%{_sysconfdir}/sysconfig/%{name}
%config(noreplace) %{_sysconfdir}/%{name}
%config(noreplace) %{_sysconfdir}/logrotate.d/%{name}
%config %{_sharedstatedir}/%{name}/certs/sti_pa/STI-PA_ROOT.pem
%config %{_sharedstatedir}/%{name}/certs/sti_pa/STI-PA_STAGING_ROOT.pem
# %{_sharedstatedir}/%{name}
%if 0%{?amzn} >= 2
%{_unitdir}/%{name}.service
%else
%{_initrddir}/%{name}
%endif
%attr(755, root, root) /usr/bin/%{name}

%doc



%changelog
