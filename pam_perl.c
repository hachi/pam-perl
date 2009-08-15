#include <EXTERN.h>
#include <perl.h>

#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT
#define PAM_SM_SESSION
#define PAM_SM_PASSWORD

#include <security/pam_modules.h>
#include <security/_pam_macros.h>

int invoke(const char *phase, pam_handle_t *pamh, int flags, int argc, const char **argv);

int
invoke(const char *phase, pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    int my_argc = 3;
    char *my_argv[] = { "", "-T", "-e1", NULL }; // POSIX says it must be NULL terminated, even though we have argc
    PerlInterpreter* original_interpreter = PL_curinterp;

    if (original_interpreter == NULL) {
        PERL_SYS_INIT(&my_argc, (char***)&my_argv);
    }

    PerlInterpreter* my_perl = perl_alloc();
    perl_construct(my_perl);
    perl_parse(my_perl, NULL, my_argc, my_argv, (char **)NULL);

    SV* name = newSVpvn("Hachi::Test", 11);

    load_module(0, newSVsv(name), NULL, NULL);

    dSP;
    ENTER;
    SAVETMPS;
    PUSHMARK(SP);
    XPUSHs(sv_2mortal(name));
    PUTBACK;
    call_method("pam_module", G_DISCARD);
    SPAGAIN;
    PUTBACK;
    FREETMPS;
    LEAVE;

    perl_destruct(my_perl);
    perl_free(my_perl);

    if (original_interpreter == NULL) {
        PERL_SYS_TERM();
    }
    else {
        PL_curinterp = original_interpreter;
    }

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
