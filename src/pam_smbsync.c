// Copyright Pavel A. Lebedev 2020
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE.md or copy at http://boost.org/LICENSE_1_0.txt)
// SPDX-License-Identifier: BSL-1.0

#define _GNU_SOURCE

#include <security/pam_ext.h>
#include <security/pam_modules.h>
#include <security/pam_modutil.h>

#include <grp.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <syslog.h>
#include <unistd.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>

int pam_sm_chauthtok(pam_handle_t* pamh,int flags,int argc,const char* argv[])
{
    uid_t id = getuid();
    if(flags&PAM_PRELIM_CHECK)
        // TODO: check smbpasswd is executable?
        // TODO: if(id) check connectivity to samba server?
        return PAM_SUCCESS;
    const char* user;
    int ret = pam_get_user(pamh,&user,NULL);
    if(ret!=PAM_SUCCESS){
        pam_syslog(pamh,LOG_ERR,"pam_get_user: %s",pam_strerror(pamh,ret));
        return ret;
    }
    if(!*user){
        pam_syslog(pamh,LOG_ERR,"username not known");
        return PAM_USER_UNKNOWN;
    }
    const char* old_password = "";
    // We need the old password only if we're not invoced as root.
    if(id){
        ret = pam_get_authtok(pamh,PAM_OLDAUTHTOK,&old_password,NULL);
        if(ret!=PAM_SUCCESS){
            pam_syslog(pamh,LOG_ERR,"pam_get_authtok(old): %s",pam_strerror(pamh,ret));
            return ret;
        }
    }
    const char* password;
    ret = pam_get_authtok(pamh,PAM_AUTHTOK,&password,NULL);
    if(ret!=PAM_SUCCESS){
        pam_syslog(pamh,LOG_ERR,"pam_get_authtok(new): %s",pam_strerror(pamh,ret));
        return ret;
    }
    int p[2];
    if(pipe(p)){
        pam_syslog(pamh,LOG_ERR,"pipe: %s",strerror(errno));
        return PAM_AUTHTOK_ERR;
    }
    ret = PAM_AUTHTOK_ERR;
    pid_t cp = fork();
    if(cp==-1){
        pam_syslog(pamh,LOG_ERR,"fork: %s",strerror(errno));
    }else{
        if(!cp){
            int e;
            if(dup2(p[0],STDIN_FILENO)!=STDIN_FILENO){
                pam_syslog(pamh,LOG_ERR,"dup2: %s",strerror(e=errno));
                exit(e);
            }
            if(pam_modutil_sanitize_helper_fds(pamh,PAM_MODUTIL_IGNORE_FD,
                    PAM_MODUTIL_NULL_FD,PAM_MODUTIL_NULL_FD))
                exit(1);
            // If we are really not running as root, not effectively through
            // suid passwd binary, drop privileges.
            if(id){
                if(setgroups(0,NULL)){
                    pam_syslog(pamh,LOG_ERR,"setgroups: %s",strerror(e=errno));
                    exit(e);
                }
                uid_t gid = getgid();
                if(setresgid(gid,gid,gid)){
                    pam_syslog(pamh,LOG_ERR,"setresgid: %s",strerror(e=errno));
                    exit(e);
                }
                if(setresuid(id,id,id)){
                    pam_syslog(pamh,LOG_ERR,"setresuid: %s",strerror(e=errno));
                    exit(e);
                }
                // Passing username through -u option sets user name in
                // unprivileged mode that talks to samba server.
                execlp("smbpasswd","smbpasswd","-s","-u",user,NULL);
            }else
                // User name as last parameter invoces root mode that
                // directly modives the database without the need for
                // the old password.
                execlp("smbpasswd","smbpasswd","-s",user,NULL);
            pam_syslog(pamh,LOG_ERR,"execlp: %s",strerror(e=errno));
            exit(e);
        }
        const char nl = '\n';
        size_t ol = strlen(old_password),l = strlen(password);
        struct iovec pv[] = {
            {(void*)old_password,ol},
            {(void*)&nl,1},
            {(void*)password,l},
            {(void*)&nl,1},
            {(void*)password,l},
            {(void*)&nl,1}
        };
        ssize_t expected_len = 2*(l+1),written;
        int ok = 1;
        if(id){
            written = writev(p[1],&pv[0],6);
            expected_len += ol+1;
        }else
            written = writev(p[1],&pv[2],4);
        if(written!=expected_len){
            pam_syslog(pamh,LOG_ERR,"writev: %s",strerror(errno));
            kill(cp,SIGTERM);
            ok = 0;
        }
        int ws;
        if(waitpid(cp,&ws,0)!=cp){
            pam_syslog(pamh,LOG_ERR,"waitpid: %s",strerror(errno));
            ok = 0;
        }
        if(!WIFEXITED(ws)||WEXITSTATUS(ws)){
            pam_syslog(pamh,LOG_ERR,"child failed: %d",ws);
            ok = 0;
        }
        if(ok){
            ret = PAM_SUCCESS;
            pam_syslog(pamh,LOG_NOTICE,"password synchronized");
        }
    }
    close(p[0]);
    close(p[1]);
    return ret;
}

