import os

def getPackage(url):
    try:
        while 1:
            res = raw_input("Would you like to download " + url + " [y/n]: ")
            if res in ("y", "yes"):
                return os.system("wget" + " " + url)
            elif res in ("n", "no"):
                return 1
    except:
        raise # propagating.
