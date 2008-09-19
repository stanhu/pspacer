#!/usr/bin/python
# A helper script to download a proper version package of the iproute2.

import os, re, sys, urllib
from pkgutils import getPackage

rootURL = 'http://devresources.linux-foundation.org/dev/iproute2/download/'

# check the version of iproute2.
def getVersion():
    for cmd in ("/sbin/tc", "/usr/sbin/tc"):
        if os.path.isfile(cmd):
            f = os.popen(cmd + " -V")
            m = re.search('iproute2-(s*s*[0-9]+)', f.readline())
            if m is None:
                raise RuntimeError, "Unknown iproute2 version."
            return m.group(1)
    else:
        raise RuntimeError, "tc(8) dose not found."


def main():
    try:
        reg = re.compile('<a href="(\S+?)">(.+?)</a>')
        version = getVersion()

        for url in (rootURL, rootURL + "Old/"):
            try:
                f = urllib.urlopen(url)
            except IOError:
                print >>sys.stderr, url + " is unreachable."
                return 1

            for line in f:
                m = reg.search(line)
                if not m: continue
                fn = m.group(1)
                if fn.find(version) == -1: continue

                rc = getPackage(url + fn)
                if rc == 0:
                    print "Success: " + fn
                    return 0
            f.close()

    except RuntimeError, e:
        print >>sys.stderr, e
        return 1
    except:
        return 1

if __name__ == '__main__':
    sys.exit(main())
