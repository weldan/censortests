#!/bin/sh
# Establish baseline using a known good site:
python testfilter.py --host python.org
python testfilter.py --host ubah.tv
python testfilter.py --host pru13.info
# Try hostname that is not available to check error
python testfilter.py --host entah.net
