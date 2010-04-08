#include <EXTERN.h>
#include <perl.h>

#include <security/pam_modules.h>

#include <xs_object_magic.h>

#include <assert.h>

EXTERN_C void xs_init (pTHX);

int invoke(const char *phase, pam_handle_t *pamh, int flags, int argc, const char **argv);

int
invoke(const char *phase, pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    static PerlInterpreter* my_perl = NULL;
    int rv = PAM_SYSTEM_ERR;

    int my_argc = 3;
    char *my_argv[] = { "", "-T", "-e1", NULL }; // POSIX says it must be NULL terminated, even though we have argc

    int i;

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

    if (argc < 1 || argv[0] == NULL) {
        return PAM_MODULE_UNKNOWN;
    }

    SV* module_name = newSVpv(argv[0], 0);

    load_module(0, newSVsv(module_name), NULL, NULL);

    SV* other_module_name = newSVpv("XS::Object::Magic", 0);
    load_module(0, newSVsv(other_module_name), NULL, NULL);
    SV *pamh_sv = xs_object_magic_create(aTHX_ pamh, gv_stashpv("PAM::Handle", GV_ADD));

    dSP;
    ENTER;
    SAVETMPS;
    PUSHMARK(SP);
    EXTEND(SP, 3 + argc);
    XPUSHs(sv_2mortal(module_name));
    XPUSHs(sv_2mortal(pamh_sv));
    XPUSHs(sv_2mortal(newSViv(flags)));
    for (i = 0; i < argc; i++)
        XPUSHs(sv_2mortal(newSVpv(argv[i], 0)));
    PUTBACK;
    call_method(phase, G_SCALAR);
    SPAGAIN;
    rv = POPi;
    PUTBACK;
    FREETMPS;
    LEAVE;

    // TODO, should I destroy and shutdown the interpreter to save memory, or keep it up so that module writers can have persistency.
    // Suppose could also add a way to pass data between invocations.
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

    return rv;
}
