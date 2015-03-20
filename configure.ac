#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([smaug], [0.8.0], [eosterweil@verisign.com])
AM_INIT_AUTOMAKE
AC_CONFIG_SRCDIR([src/smg_id.cc])
AC_CONFIG_HEADERS([src/config.h])
# Release 0.8.0, libsmaug 0:0:0
AC_SUBST(libsmaug_la_version_info, 0:0:0)
LT_INIT

AC_ARG_ENABLE([getdns],
              [  --enable-getdns   Build with getdns API (default is no)],
              [case "$enableval" in
                 yes) getdns=true;;
                 no) getdns=false;;
                 *) AC_MSG_ERROR([bad value ${enableval} for --enable-getdns]) ;;
               esac],[getdns=false])
AC_ARG_WITH(getdns_dir,
            AC_HELP_STRING(
                           [--with-getdns-dir[=DIR])],
                           [getdns API library directory]),
            [getdns_dir=$withval])
AM_CONDITIONAL([SMG_GETDNS], [test "x$getdns" = "xtrue" || test "x$getdns_dir" != "x"])


AC_ARG_ENABLE([openldap],
              [  --enable-openldap   Build with OpenLDAP support (default is no)],
              [case "$enableval" in
                 yes) openldap=true;;
                 no) openldap=false;;
                 *) AC_MSG_ERROR([bad value ${enableval} for --enable-openldap]) ;;
               esac],[openldap=false])
AC_ARG_WITH(openldap_dir,
            AC_HELP_STRING(
                           [--with-openldap[=DIR]],
                           [OPENLDAP library directory]),
            [openldap_dir=$withval])
AM_CONDITIONAL([SMG_LDAP], [test "x$openldap" = "xtrue" || test "x$openldap_dir" != "x"])

AC_ARG_WITH(openssl-lib-dir,
            AC_HELP_STRING(
                           [--with-openssl-lib-dir[=DIR]],
                           [OPENSSL library directory]),
            [openssl_lib_dir=$withval])

AC_CHECK_LIB(ssl, OpenSSL_add_all_algorithms, OPENSSL_LIB=" ", OPENSSL_LIB= )
AC_CHECK_LIB(crypto, EVP_PKEY_new, CRYPTO_LIB=" ", CRYPTO_LIB= )

LDFLAGS="$LDFLAGS $OPENSSL_LIB $CRYPTO_LIB $LDAP_LIB"

if test "x$openssl_lib_dir" != "x"; then
  AC_CHECK_LIB(ssl, OpenSSL_add_all_algorithms, OPENSSL_LIB=" ", OPENSSL_LIB= )
  # hunt through several directories trying to find the libraries
  if test "x$OPENSSL_LIB" = "x"; then
    old_LDFLAGS="$LDFLAGS"
    for try in $openssl_lib_dir /usr/lib /usr/local/lib /opt/local/lib; do
      LDFLAGS=$"old_LDFLAGS"
      unset ac_cv_OpenSSL_add_all_algorithms
      AC_CHECK_LIB(ssl, OpenSSL_add_all_algorithms, OPENSSL_LIB="-L$try", OPENSSL_LIB=)
      if test "x$OPENSSL_LIB" != "x"; then
        break;
      fi
    done
    LDFLAGS="$old_LDFLAGS $OPENSSL_LIB"
  fi
  if test "x$OPENSSL_LIB" = "x"; then
    AC_MSG_ERROR([OPENSSL_LIB not found.])
  fi
fi


if test "x$getdns_dir" != "x"; then
  AC_CHECK_LIB(getdns, getdns_context_create, GETDNS_LIB=" ", GETDNS_LIB= )
  # hunt through several directories trying to find the libraries
  if test "x$GETDNS_LIB" = "x"; then
    old_LDFLAGS="$LDFLAGS"
    for try in /usr/lib /usr/local/lib /opt/local/lib; do
      LDFLAGS=$"old_LDFLAGS"
      unset ac_cv_getdns_context_create
      AC_CHECK_LIB(getdns, getdns_context_create, GETDNS_LIB="-L$try", GETDNS_LIB=)
      if test "x$GETDNS_LIB" != "x"; then
        break;
      fi
    done
    LDFLAGS="$old_LDFLAGS $GETDNS_LIB"
  fi
  if test "x$GETDNS_LIB" = "x"; then
    AC_MSG_ERROR([GETDNS_LIB libraries not found.])
  fi
else
  AC_CHECK_LIB(unbound, ub_ctx_create, LIBUNBOUND=" ", LIBUNBOUND=)
  # hunt through several directories trying to find the libraries
  if test "x$LIBUNBOUND" = "x"; then
    old_LDFLAGS="$LDFLAGS"
    for try in /usr/lib /usr/local/lib /opt/local/lib; do
      LDFLAGS=$"old_LDFLAGS"
      unset ac_cv_ub_ctx_create
      AC_CHECK_LIB(unbound, ub_ctx_create, LIBUNBOUND="-L$try", LIBUNBOUND=)
      if test "x$LIBUNBOUND" != "x"; then
        break;
      fi
    done
    LDFLAGS="$old_LDFLAGS $LIBUNBOUND"
  fi
  if test "x$LIBUNBOUND" = "x"; then
    AC_MSG_ERROR([LIBUNBOUND not found.])
  fi
fi

if test "x$openldap" = "xtrue"; then
  AC_CHECK_LIB(ldap, ldap_initialize, LDAP_LIB=" ", LDAP_LIB= )
  # hunt through several directories trying to find the libraries
  if test "x$LDAP_LIB" = "x"; then
    old_LDFLAGS="$LDFLAGS"
    for try in $openldap_dir /usr/lib /usr/local/lib /opt/local/lib; do
      LDFLAGS=$"old_LDFLAGS"
      unset ac_cv_ldap_initialize
      AC_CHECK_LIB(ldap, ldap_initialize, LDAP_LIB="-L$try ", LDAP_LIB=)
      if test "x$LDAP_LIB" != "x"; then
        break;
      fi
    done
    LDFLAGS="$old_LDFLAGS $LDAP_LIB"
  fi
  if test "x$LDAP_LIB" = "x"; then
    AC_MSG_ERROR([LDAP_LIB not found.])
  fi
fi

# Checks for programs.
AC_PROG_CXX
AC_PROG_CC

# Checks for libraries.

# Checks for header files.
AC_CHECK_HEADERS([string.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL
AC_TYPE_SIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_CHECK_FUNCS([memset])

# AC_CONFIG_FILES([src/Makefile])
AC_OUTPUT(Makefile src/Makefile)

