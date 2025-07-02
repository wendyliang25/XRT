#!/usr/bin/python3

#
# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2019-2021 Xilinx, Inc
#

import argparse
import os
import sys
import numpy

# Following found in PYTHONPATH setup by XRT
from xrt_binding import *
import pyxrt

sys.path.append('../')
#from utils_binding import *

def runKernel(args):
    print("simple device reset test")
    d = pyxrt.device(0)
    d.reset()
    print("simple device reset test done")

def main():
    parser = argparse.ArgumentParser(description="Parse xrt flow python test arguments.")
    parser.add_argument('--dev_index', type=int, help='AIE device index', default=0)
    args = parser.parse_args()
    runKernel(args)

if __name__ == '__main__':
    main()
