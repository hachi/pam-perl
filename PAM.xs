#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "ppport.h"

#include <security/pam_misc.h>
#include "const-c.inc"

#include "xs_object_magic.h"

//pam_set_item
//pam_strerror
//pam_set_data
//pam_get_data
//pam_putenv
//pam_getenv
//pam_getenvlist

MODULE = PAM    PACKAGE = PAM::Constants

INCLUDE: const-xs.inc

MODULE = PAM    PACKAGE = PAM::Handle    PREFIX = pam_

PROTOTYPES: DISABLE

const char*
get_user(pam_handle, ...)
    const pam_handle_t* pam_handle
    const char* user   = NO_INIT
    const char* prompt = NO_INIT
    int rv             = NO_INIT
    PREINIT:
        prompt = NULL;
        user = "";
    CODE:
        if (items > 1)
            prompt = (char *)SvPV_nolen(ST(1));
        if (pam_handle == NULL)
            croak("pam_handle not defined\n");
        rv = pam_get_user(pam_handle, &user, prompt);
        RETVAL = user;
    OUTPUT:
        RETVAL

const char*
get_item(pam_handle, item_type)
    const pam_handle_t* pam_handle
    int item_type
    const void* item = NO_INIT
    int rv            = NO_INIT
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
                RETVAL = (char*)item;
            break;

            case PAM_CONV :
            case PAM_FAIL_DELAY :   // Linux specific
            case PAM_XAUTHDATA :    // Linux specific
            case PAM_AUTHTOK_TYPE : // Linux specific
            default :
                RETVAL = NULL;
            break;
        }
    OUTPUT:
        RETVAL
