#!/bin/sh
_verbose=0
_package=pspacer-`cat ../VERSION | awk '{print $1}'`
_distfile=$_package.tar.gz

while [ -n "$1" ]; do
    case "$1" in
	-v)
	    _verbose=1; shift
	    ;;
	-o)
	    shift
	    _distfile=$1; shift
	    ;;
	*)
	    echo "$0 [-v] [-o filename] package"
	    exit 1
	    ;;
    esac
done

echo "make package: $_distfile"
if [ -e $_package ]; then
    rm -fR $_package
fi
mkdir $_package
find .. -name "CVS" -prune -o -name "$_package" -prune \
-o -type d -printf "%P\n" | xargs --replace mkdir -p $_package/{}
find .. -name "CVS" -prune -o -name "$_package" -prune \
-o -type f -printf "%P\n" | xargs --replace cp -p ../{} $_package/{}

for x in `cat pkg.rmlist.txt`; do
    if [ -f $_package/$x -o -d $_package/$x ]; then
	rm -fR $_package/$x
    else
	if [ $_verbose = 1 ]; then
	    echo "${PACKAGE}/$x does not exist"
	fi
    fi
done

tar zcf $_distfile $_package
rm -rf $_package
