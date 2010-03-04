#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "ppport.h"

#include <security/pam_misc.h>
#include "const-c.inc"

#include "xs_object_magic.h"

MODULE = PAM    PACKAGE = PAM::Constants

INCLUDE: const-xs.inc

MODULE = PAM    PACKAGE = PAM::Handle    PREFIX = pam_

PROTOTYPES: DISABLE

SV*
get_user(pam_handle, ...)
    pam_handle_t* pam_handle
    PREINIT:
        const char* user;
        const char* prompt = NULL;
        int rv;
    CODE:
        if (items > 1)
            prompt = (char *)SvPV_nolen(ST(1));
        if (pam_handle == NULL)
            croak("pam_handle not defined\n");
        rv = pam_get_user(pam_handle, &user, prompt);
        RETVAL = newSVpv(user, 0);
    OUTPUT:
        RETVAL

SV*
get_item(pam_handle, item_type)
    pam_handle_t* pam_handle
    int item_type
    PREINIT:
        const void* item;
        int rv;
    CODE:
        switch (item_type)
        {
            case PAM_SERVICE :
            case PAM_USER :
            case PAM_USER_PROMPT :
            case PAM_TTY :
            case PAM_RUSER :
            case PAM_RHOST :
            case PAM_AUTHTOK :
            case PAM_OLDAUTHTOK :
            case PAM_XDISPLAY : // Linux specific
                rv = pam_get_item(pam_handle, item_type, &item);
                if (rv == PAM_SUCCESS)
                    RETVAL = newSVpv((char*)item, 0);
                else
                    RETVAL = &PL_sv_undef;
            break;

            case PAM_CONV :
            case PAM_FAIL_DELAY :   // Linux specific
            case PAM_XAUTHDATA :    // Linux specific
            case PAM_AUTHTOK_TYPE : // Linux specific
            default :
                RETVAL = &PL_sv_undef;
            break;
        }
    OUTPUT:
        RETVAL

void
set_item(pam_handle, item_type, item_sv)
    pam_handle_t* pam_handle
    int item_type
    SV* item_sv
    PREINIT:
        const void* item;
        int rv;
    CODE:
        switch (item_type)
        {
            case PAM_SERVICE :
            case PAM_USER :
            case PAM_USER_PROMPT :
            case PAM_TTY :
            case PAM_RUSER :
            case PAM_RHOST :
            case PAM_AUTHTOK :
            case PAM_OLDAUTHTOK :
            case PAM_XDISPLAY : // Linux specific
                item = SvPV_nolen(item_sv);
                rv = pam_set_item(pam_handle, item_type, item);
            break;

            case PAM_CONV :
            case PAM_FAIL_DELAY :   // Linux specific
            case PAM_XAUTHDATA :    // Linux specific
            case PAM_AUTHTOK_TYPE : // Linux specific
            default :
            break;
        }

SV*
get_data(pam_handle, name)
    pam_handle_t* pam_handle
    const char* name
    PREINIT:
        void* data;
        int rv;
    CODE:
        rv = pam_get_data(pam_handle, name, &data);
        if (rv == PAM_SUCCESS)
            RETVAL = newSVpv((char*)data, 0);
        else
            RETVAL = &PL_sv_undef;
    OUTPUT:
        RETVAL

void
set_data(pam_handle, name, data_sv)
    pam_handle_t* pam_handle
    const char* name
    SV* data_sv
    PREINIT:
        const void* data;
        int rv;
    CODE:
        data = SvPV_nolen(data_sv);
        rv = pam_set_data(pam_handle, name, data);

void
getenvlist(pam_handle)
    pam_handle_t* pam_handle
    PREINIT:
        char** env;
        char** env_orig;
    PPCODE:
        env = pam_getenvlist(pam_handle);
        env_orig = env;
        while (env != NULL) {
            XPUSHs(sv_2mortal(newSVpv(*env, 0)));
            env++;
        }
        free(env_orig);

SV*
getenv(pam_handle, name)
    pam_handle_t* pam_handle
    const char* name
    PREINIT:
        const char* value;
    CODE:
        value = pam_getenv(pam_handle, name);
        RETVAL = newSVpv(value, 0);
    OUTPUT:
        RETVAL

void
putenv(pam_handle, name_value_sv)
    pam_handle_t* pam_handle
    SV* name_value_sv
    const void* name_value = NO_INIT
    int rv           = NO_INIT
    CODE:
        name_value = SvPV_nolen(name_value_sv);
        rv = pam_putenv(pam_handle, name_value);

SV*
strerror(pam_handle, errnum)
    pam_handle_t* pam_handle
    int           errnum
    PREINIT:
        const char* errstr;
    CODE:
        errstr = pam_strerror(pam_handle, errnum);
        RETVAL = newSVpv(errstr, 0);
    OUTPUT:
        RETVAL
