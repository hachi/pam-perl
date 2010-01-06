#include <EXTERN.h>
#include <perl.h>

#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT
#define PAM_SM_SESSION
#define PAM_SM_PASSWORD

#include <security/pam_modules.h>
#include <security/_pam_macros.h>

EXTERN_C void boot_DynaLoader (pTHX_ CV* cv);

int invoke(const char *phase, pam_handle_t *pamh, int flags, int argc, const char **argv);
static void xs_init (pTHX);

EXTERN_C void
xs_init(pTHX)
{
    char *file = __FILE__;
    dXSUB_SYS;
    newXS("DynaLoader::boot_DynaLoader", boot_DynaLoader, file);
}

int
invoke(const char *phase, pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    static PerlInterpreter* my_perl = NULL;

    int my_argc = 3;
    char *my_argv[] = { "", "-T", "-e1", NULL }; // POSIX says it must be NULL terminated, even though we have argc

    PerlInterpreter* original_interpreter = PERL_GET_INTERP;

    if (my_perl == NULL) {
        if (original_interpreter == NULL) {
            PERL_SYS_INIT(&my_argc, (char***)&my_argv);
        }

        my_perl = perl_alloc();
        perl_construct(my_perl);
        perl_parse(my_perl, xs_init, my_argc, my_argv, (char **)NULL);
    }
    else {
        PERL_SET_INTERP(my_perl);
    }

    if (argc != 1 || argv[0] == NULL) {
        D(("Wrong number of args passed"));
        return PAM_MODULE_UNKNOWN;
    }

    SV* module_name = newSVpv(argv[0], 0);
    HV* stash = gv_stashsv(module_name, GV_ADD);

    newCONSTSUB(stash, "PAM_SUCCESS", newSViv(PAM_SUCCESS));
    newCONSTSUB(stash, "PAM_OPEN_ERR", newSViv(PAM_OPEN_ERR));
    newCONSTSUB(stash, "PAM_SYMBOL_ERR", newSViv(PAM_SYMBOL_ERR));
    newCONSTSUB(stash, "PAM_SERVICE_ERR", newSViv(PAM_SERVICE_ERR));
    newCONSTSUB(stash, "PAM_SYSTEM_ERR", newSViv(PAM_SYSTEM_ERR));
    newCONSTSUB(stash, "PAM_BUF_ERR", newSViv(PAM_BUF_ERR));
    newCONSTSUB(stash, "PAM_PERM_DENIED", newSViv(PAM_PERM_DENIED));
    newCONSTSUB(stash, "PAM_AUTH_ERR", newSViv(PAM_AUTH_ERR));
    newCONSTSUB(stash, "PAM_CRED_INSUFFICIENT", newSViv(PAM_CRED_INSUFFICIENT));
    newCONSTSUB(stash, "PAM_AUTHINFO_UNAVAIL", newSViv(PAM_AUTHINFO_UNAVAIL));
    newCONSTSUB(stash, "PAM_USER_UNKNOWN", newSViv(PAM_USER_UNKNOWN));
    newCONSTSUB(stash, "PAM_MAXTRIES", newSViv(PAM_MAXTRIES));
    newCONSTSUB(stash, "PAM_NEW_AUTHTOK_REQD", newSViv(PAM_NEW_AUTHTOK_REQD));
    newCONSTSUB(stash, "PAM_ACCT_EXPIRED", newSViv(PAM_ACCT_EXPIRED));
    newCONSTSUB(stash, "PAM_SESSION_ERR", newSViv(PAM_SESSION_ERR));
    newCONSTSUB(stash, "PAM_CRED_UNAVAIL", newSViv(PAM_CRED_UNAVAIL));
    newCONSTSUB(stash, "PAM_CRED_EXPIRED", newSViv(PAM_CRED_EXPIRED));
    newCONSTSUB(stash, "PAM_CRED_ERR", newSViv(PAM_CRED_ERR));
    newCONSTSUB(stash, "PAM_NO_MODULE_DATA", newSViv(PAM_NO_MODULE_DATA));
    newCONSTSUB(stash, "PAM_CONV_ERR", newSViv(PAM_CONV_ERR));
    newCONSTSUB(stash, "PAM_AUTHTOK_ERR", newSViv(PAM_AUTHTOK_ERR));
    newCONSTSUB(stash, "PAM_AUTHTOK_RECOVERY_ERR", newSViv(PAM_AUTHTOK_RECOVERY_ERR));
    newCONSTSUB(stash, "PAM_AUTHTOK_LOCK_BUSY", newSViv(PAM_AUTHTOK_LOCK_BUSY));
    newCONSTSUB(stash, "PAM_AUTHTOK_DISABLE_AGING", newSViv(PAM_AUTHTOK_DISABLE_AGING));
    newCONSTSUB(stash, "PAM_TRY_AGAIN", newSViv(PAM_TRY_AGAIN));
    newCONSTSUB(stash, "PAM_IGNORE", newSViv(PAM_IGNORE));
    newCONSTSUB(stash, "PAM_ABORT", newSViv(PAM_ABORT));
    newCONSTSUB(stash, "PAM_AUTHTOK_EXPIRED", newSViv(PAM_AUTHTOK_EXPIRED));
    newCONSTSUB(stash, "PAM_MODULE_UNKNOWN", newSViv(PAM_MODULE_UNKNOWN));
    newCONSTSUB(stash, "PAM_BAD_ITEM", newSViv(PAM_BAD_ITEM));
    newCONSTSUB(stash, "PAM_CONV_AGAIN", newSViv(PAM_CONV_AGAIN));
    newCONSTSUB(stash, "PAM_INCOMPLETE", newSViv(PAM_INCOMPLETE));

    load_module(0, newSVsv(module_name), NULL, NULL);

    dSP;
    ENTER;
    SAVETMPS;
    PUSHMARK(SP);
    XPUSHs(sv_2mortal(module_name));
    PUTBACK;
    call_method(phase, G_DISCARD);
    FREETMPS;
    LEAVE;

    // TODO get the return value from the subroutine and turn it into a PAM status.

    if (0) {
        perl_destruct(my_perl);
        perl_free(my_perl);
        my_perl = NULL;
    }

    if (original_interpreter != NULL) {
        PERL_SET_INTERP(original_interpreter);
    }

/*  Can't use this cause we might not be the last perl interpreter. Really only perl(1) can call this.
    else {
        PERL_SYS_TERM();
    }
*/

    return 0;
}

PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    invoke("authenticate", pamh, flags, argc, argv);
    return PAM_SUCCESS;
}

PAM_EXTERN int
pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    invoke("setcred", pamh, flags, argc, argv);
    return PAM_SUCCESS;
}

PAM_EXTERN int
pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    invoke("acct_mgmt", pamh, flags, argc, argv);
    return PAM_SUCCESS;
}

PAM_EXTERN int
pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    invoke("chauthtok", pamh, flags, argc, argv);
    return PAM_SUCCESS;
}

PAM_EXTERN int
pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    invoke("open_session", pamh, flags, argc, argv);
    return PAM_SUCCESS;
}

PAM_EXTERN int
pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    invoke("close_session", pamh, flags, argc, argv);
    return PAM_SUCCESS;
}

#ifdef PAM_STATIC

struct pam_module _pam_perl_modstruct = {
    "pam_perl",
    pam_sm_authenticate,
    pam_sm_setcred,
    pam_sm_acct_mgmt,
    pam_sm_open_session,
    pam_sm_close_session,
    pam_sm_chauthtok
};

#endif
