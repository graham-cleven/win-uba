def fuzzTime(stime, etime, fuzzFactor):

    stime = str(int(stime) - (fuzzFactor / 2))
    etime = str(int(etime) + (fuzzFactor / 2))

    return [stime, etime]
