dnl configure.ac

dnl outline
dnl 1. AC_INIT
dnl 2. options (AC_ARG_ENABLE)
dnl 3. programs (AC_CHECK_PROG)
dnl 4. libraries
dnl 5. header files
dnl 6. typedefs, structs
dnl 7. functions
dnl 8. AC_OUTPUT

###
### 1. AC_INIT
###

AC_INIT([pspacer],[ ],[takano-ryousei@aist.go.jp])
PACKAGE_VERSION=`cat $srcdir/VERSION | awk '{print $1}'`
PACKAGE_STRING="$PACKAGE_NAME-$PACKAGE_VERSION"

AC_SUBST(RELEASE_DATE)
RELEASE_DATE=`cat $srcdir/VERSION | awk '{print $2}'`

dnl check tc version
dnl If the version of iproute2 is older then ss040831, TC_COMPAT is set to yes.

AC_SUBST(TC_COMPAT)
TC_COMPAT=no

if test -f /sbin/tc; then
    TC=/sbin/tc
elif test -f /usr/sbin/tc; then
    TC=/usr/sbin/tc
else
    echo "Can not find tc(8)."
    exit 1
fi

curver=`$TC -V | sed -s 's/.*iproute2-ss\([[0-9]]*\)/\1/'`
compatver="040831"
tmp=`echo -e "$curver\n$compatver" | sort -n | head -1`
if test "$tmp" != "$compatver" ; then
    echo "Use compat mode."
    TC_COMPAT=yes
fi

arch=`uname -i`
if test "$arch" == "x86_64" ; then
    tclib_dir="/usr/lib64/tc"
else
    tclib_dir="/usr/lib/tc"
fi

function fullpath {
    (cd `dirname $1`; pwd) \
    | tr -d "\n"; echo /`basename $1`
}

###
### 2. options (AC_ARG_ENABLE)
###

dnl CFLAGS

AC_SUBST(DEBUG_COPT)

AC_ARG_ENABLE(debug,
    AS_HELP_STRING([--enable-debug],[debugging mode]),
    [],enable_debug=no)
case "${enable_debug}" in
yes)
    DEBUG_COPT="-DDEBUG=1"
    ;;
*) ;;
esac

dnl iproute2

AC_SUBST(IPROUTE_INC)
AC_SUBST(TCLIB_DIR)

AC_ARG_WITH(iproute2_dir,
    AS_HELP_STRING([--with-iproute2-dir=DIR],
    [specify the iproute2 directory (default /opt/iproute2)]),
    [], [with_iproute2_dir=/opt/iproute2])

AC_ARG_WITH(tclib_dir,
    AS_HELP_STRING([--with-tclib-dir=DIR],
    [specify the tc lib directory (default /usr/lib/tc for i368, /usr/lib64/tc for x86_64)]),
     [], [with_tclib_dir=${tclib_dir}])

abs_iproute2_dir=""
case ${with_iproute2_dir} in
    /*) # absolute path
	abs_iproute2_dir=${with_iproute2_dir}
	;;
    *) # relative path
	abs_iproute2_dir=`fullpath ${with_iproute2_dir}`
	;;
esac

if test ! -d ${with_iproute2_dir}; then
    echo "${with_iproute2_dir} does not exist."
    exit 1
fi

IPROUTE_INC="-I ${abs_iproute2_dir}/include -I ${abs_iproute2_dir}/tc"

TCLIB_DIR=${with_tclib_dir}


dnl libnl

AC_SUBST(LIBNL)
AC_SUBST(LIBNL_DIR)

AC_ARG_WITH(libnl,
    AS_HELP_STRING([--with-libnl], [use the libnl library]), 
    [], [with_libnl=no])

AC_ARG_WITH(libnl_dir,
    AS_HELP_STRING([--with-libnl-dir=DIR],
    [specify the libnl directory (default /opt/linl)]), [with_libnl=yes],
    [with_libnl_dir=/opt/libnl])

AC_ARG_WITH(libnl_pkg,
    AS_HELP_STRING([--with-libnl-pkg=FILE],[use this libnl package]), 
    [with_libnl=yes], [with_libnl_pkg=no])

if test ${with_libnl_pkg} != "no"; then
    test -d libnl-* && echo "The libnl directory already exists." && exit 1
    test ! -f ${with_libnl_pkg} && echo "File is not found: ${with_libnl_pkg}" && exit 1

    echo "Uncompress $with_libnl_pkg"
    tar zxf ${with_libnl_pkg}

    with_libnl_dir=`basename ${with_libnl_pkg} | sed -e 's/\(.*\)\.tar\.gz/\1/'`

    echo "Apply patch to $with_libnl_dir"
    (cd ${with_libnl_dir}; patch -p1 < ../patch/${with_libnl_dir}.psp.patch)
fi

if test ${with_libnl} != "no"; then
    LIBNL=${with_libnl}
    case ${with_libnl_dir} in
	/*)
	    LIBNL_DIR=`dirname ${with_libnl_dir}`
	    ;;
	*)
	    LIBNL_DIR=`dirname ${PWD}/${with_libnl_dir}`
	    ;;
    esac
    LIBNL_DIR=${LIBNL_DIR}/`basename ${with_libnl_dir}`

    test -L libnl.temp && rm libnl.temp
    ln -s ${with_libnl_dir} libnl.temp
    AC_CONFIG_SUBDIRS(libnl.temp)	# this parameter must be literal.
fi

###
### 3. programs (AC_CHECK_PROG)
###

AC_PROG_CC
AC_PROG_INSTALL

###
### 4. libraries
###

###
### 5. header files
###

###
### 6. typedefs, structs
###

###
### 7. functions
###

###
### 8. AC_OUTPUT
###

echo ""
echo "Configuration"
(

echo "  --enable-debug                  ${enable_debug}"
echo "  --with-iproute2-dir             ${with_iproute2_dir}"
echo "  --with-tclib-dir                ${with_tclib_dir}"
echo "  --with-libnl                    ${with_libnl}"
echo "  --with-libnl-pkg                ${with_libnl_pkg}"
echo "  --with-libnl-dir                ${with_libnl_dir}"
) | tee config.options
echo ""

AC_CONFIG_FILES([Makefile
	pspacer.spec
	kernel/Makefile
	tc/Makefile
	pspd/Makefile
	doc/Makefile
	doc/README
	doc/usage.en.txt
	man/Makefile])
AC_OUTPUT

test -f doc/README && cp doc/README .
test -L libnl.temp && rm libnl.temp
