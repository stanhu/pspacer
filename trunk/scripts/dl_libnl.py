#!/usr/bin/python
# A helper script to download a proper version package of the libnl.

import os, sys
from pkgutils import getPackage

rootURL = 'http://people.suug.ch/~tgr/libnl/files/'
defaultVersion = '1.0-pre6'

def main():
    try:
        if len(sys.argv) == 2:
            version = sys.argv[1]
        else:
            version = defaultVersion
        pkgName = 'libnl-' + version + '.tar.gz'
        url = rootURL + pkgName

        rc = getPackage(url)
    except:
        return 1
    else:
        if rc == 0:
            print "Success: " + pkgName
            return 0
        else:
            print "Error: " + pkgName
            return 1


if __name__ == '__main__':
    sys.exit(main())
