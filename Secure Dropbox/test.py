import time
a = "Tue, 23 Jul 2013 02:19:23 +0000"

format = '%a, %d %b %Y %H:%M:%S'

print time.mktime(time.strptime(a[:-6], format))
print time.time()