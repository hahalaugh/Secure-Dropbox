import os
import sys

filenames = os.listdir(os.getcwd())

for element in filenames:
    print element
    t = element.replace(' ', '_')
    os.rename(element,t)
    print t

