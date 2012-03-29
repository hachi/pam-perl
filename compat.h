#ifndef _PAM_PERL_COMPAT
#define _PAM_PERL_COMPAT

#ifdef PERL_DARWIN
void pam_syslog(pam_handle_t *pamh, int level, const char *msg, ...) { }
#else
#include <security/pam_ext.h>
#endif

#endif
