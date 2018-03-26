#!/usr/bin/env python
#-*- coding: utf-8 -*-
import sys
import numpy as np


arr = np.loadtxt(sys.stdin)
print("μ: {:.2e}\t σ: {:.4e}".format(arr.mean(), arr.std()))
