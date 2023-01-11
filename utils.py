def fuzzTime(stime, etime, fuzzFactor):

    stime = str(int(stime) - (fuzzFactor / 2))
    etime = str(int(etime) + (fuzzFactor / 2))

    return [stime, etime]


def makeEpoch(d):
    from datetime import datetime

    for n in d:
        n["_indextime"] = datetime.fromtimestamp(float(n["_indextime"])).strftime(
            "%d %b %y %H:%M:%S"
        )
    return d
