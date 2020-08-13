pam_smbsync
===========

PAM module to update Samba password in sync with UNIX password change.

The only thing it does is invoke `smbpasswd` to do the job.

There used to be `pam_smbpasswd` module, but it's long gone and `pam_exec`
doesn't support password changes. It is possible to have a SSO setup with
LDAP and `pam_ldap` + `passdb backend = ldapsam` in Samba, but it's probably
overkill for a small local setup.

The module supports changing password by a normal user and changing password
for any user by root without knowing old password.

This module has no configuration options of its own, but accepts those
that modify `pam_get_authtok (3)` behavior.

Build it while specifying `PAM_MODULE_DIR`. Install and add in your PAM
configuration after `password pam_unix.so ...` line the following:

```
password optional pam_smbsync.so use_authtok
```

WARNING
-------

I have no idea if this is secure at all, launching other executables from
SUID binaries is scary, I hope I dropped privileges correctly.
Could be the reason why pam_smbpasswd was dropped.
