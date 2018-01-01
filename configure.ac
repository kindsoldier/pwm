AC_INIT(pwm.pl,0.01)
AM_INIT_AUTOMAKE
AC_PREFIX_DEFAULT(/usr/local)

PACKAGE=pwm

AC_CHECK_PROG(HAVE_PERL, perl, true, false, /usr/local/bin /usr/bin)
if test "x$HAVE_PERL" = "xfalse"; then
	AC_MSG_ERROR([Requested program perl not found])
fi
AC_PATH_PROG([perl],[perl])
dnl AC_SUBST(perl, perl)

AC_PROG_INSTALL

AC_CANONICAL_HOST

case $host_os in
    *freebsd* )
	AC_SUBST(ROOT_GROUP, "wheel")
	AM_CONDITIONAL(FREEBSD_OS, true)
	AM_CONDITIONAL(LINUX_OS, false)
	OSNAME=freebsd
	ROOT_GROUP=wheel
        ;;
    *linux* )
	AC_SUBST(ROOT_GROUP, "root")
	AM_CONDITIONAL(FREEBSD_OS, false)
	AM_CONDITIONAL(LINUX_OS, true)
	OSNAME=linux
	ROOT_GROUP=root
        ;;
esac

test "x$prefix" == "xNONE" && prefix=$ac_default_prefix

dnl --------------------------------------------------------------------------------------
AC_DEFUN([AC_PERL_MODULES],[
ac_perl_modules="$1"
for ac_perl_module in $ac_perl_modules; do
AC_MSG_CHECKING(for perl module $ac_perl_module)
perl "-M$ac_perl_module" -e exit > /dev/null 2>&1
if test $? -ne 0; then
    AC_MSG_RESULT(no);
    AC_MSG_ERROR(You must install perl module $ac_perl_module)
  else
    AC_MSG_RESULT(ok);
fi
done])

AC_PERL_MODULES([
POSIX
])

AC_OUTPUT([
Makefile
pwm:pwm.pl
])

dnl EOF


