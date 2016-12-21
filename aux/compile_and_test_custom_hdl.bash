#!/bin/bash
# Execute from /designs/leon3mp

OUTPUTLOG="testbench_output.log"


source /home/marcel/installs/Xilinx/13.4/ISE_DS/settings64.sh
make distclean
make xconfig # enable UART acceleration
make soft # rebuild ram.srec based on systest.c
make scripts # generate VHDL compiling recipes
../../../../aux/modify_flags.py "make.vsim"
make sim
vsim testbench -do "run -a; quit -f" -logfile ${OUTPUTLOG}
