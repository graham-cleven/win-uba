from splunk import Splunk
import matplotlib as mpl

mpl.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import datetime

data = Splunk().query("index=linux IP=* | table _indextime, IP")

dates = []
IPs = []

for dat in data:
    dates.append(dat["_indextime"])
    IPs.append(dat["IP"])

dates = [datetime.datetime.fromtimestamp(float(d)) for d in dates]

print(dates)

levels = np.tile([-5, 5, -3, 3, -1, 1], int(np.ceil(len(dates) / 6)))[: len(dates)]

fig, ax = plt.subplots(figsize=(8.8, 4))
ax.set(title="Access Failures")

markerline, stemline, baseline = ax.stem(
    dates, levels, linefmt="C3-", basefmt="k-", user_line_collection=True
)

plt.setup(markerline, mec="k", mfc="w", zorder=3)

markerline.set_ydata(np.zeros(len(dates)))

vert = np.array(["top", "bottom"])[(levels > 0).astype(int)]
for d, l, r, va in zip(dates, levels, names, vert):
    ax.annotate(
        r,
        xy=(d, 1),
        xytext=(-3, np.sign(1) * 3),
        textcoords="offset points",
        va=va,
        ha="right",
    )

ax.margins(y=0.1)
plt.save("/var/www/html/test")
