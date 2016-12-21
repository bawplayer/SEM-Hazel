#!/usr/bin/env python3
__author__ = "bawplayer"

import typing
from contextlib import suppress
import sys
import os

def is_smu_related_instruction(s:str) -> bool:
	sargs = s.lower().split()
	with suppress(IndexError):
		return ("/smu/" in sargs[-1]) and (sargs[0] == "vcom")
	return False

def modify_vhdl_standand(filename, pred = None) :
	"""Replace VHDL compiler flag from standand 1993,
	to 2008, for SMU files only.
	"""
	if pred is None:
		# modify all
		act = lambda s: s.replace(" -93 ", " -2008 ", 1)
	else:
		act = lambda s: s if not pred(s) else \
			(s.replace(" -93 ", " -2008 ", 1).rstrip() + "\t# Modified by PYTHON" + os.linesep)
	with open(filename, 'r+') as f:
		lines = f.readlines() # read to buffer
		f.seek(0); f.truncate(None) # empty file
		f.writelines(map(act, lines)) # modify & write back
		

def main(*filenames):
	for fn in filenames:
		try:
			modify_vhdl_standand(fn, is_smu_related_instruction)
		except (FileNotFoundError, PermissionError, IsADirectoryError) as e:
			print(e, file=sys.stderr)


if __name__ == "__main__":
	main(*sys.argv[1:])
