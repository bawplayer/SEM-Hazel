onerror {resume}
quietly WaveActivateNextPane {} 0
add wave -noupdate -format Logic /testbench/clk
add wave -noupdate -format Logic /testbench/rst
add wave -noupdate -format Literal -radix hexadecimal /testbench/address
add wave -noupdate -format Literal -radix hexadecimal /testbench/data
add wave -noupdate -format Literal /testbench/sdcke
add wave -noupdate -format Literal /testbench/sdcsn
add wave -noupdate -format Logic /testbench/sdwen
add wave -noupdate -format Logic /testbench/sdrasn
add wave -noupdate -format Logic /testbench/sdcasn
add wave -noupdate -format Literal /testbench/sddqm
add wave -noupdate -format Logic /testbench/sdclk
add wave -noupdate -format Literal -radix hexadecimal /testbench/sa
add wave -noupdate -format Literal -radix hexadecimal /testbench/sd
add wave -noupdate -format Literal /testbench/ramsn
add wave -noupdate -format Literal /testbench/ramoen
add wave -noupdate -format Literal /testbench/rwen
add wave -noupdate -format Literal /testbench/romsn
add wave -noupdate -format Logic /testbench/iosn
add wave -noupdate -format Logic /testbench/oen
add wave -noupdate -format Logic /testbench/read
add wave -noupdate -format Logic /testbench/writen
add wave -noupdate -format Logic /testbench/brdyn
add wave -noupdate -format Logic /testbench/bexcn
add wave -noupdate -format Logic /testbench/dsuen
add wave -noupdate -format Logic /testbench/dsutx
add wave -noupdate -format Logic /testbench/dsurx
add wave -noupdate -format Logic /testbench/dsubre
add wave -noupdate -format Logic /testbench/dsuact
add wave -noupdate -format Logic /testbench/dsurst
add wave -noupdate -format Logic /testbench/error
add wave -noupdate -format Literal /testbench/gpio
add wave -noupdate -format Literal -radix hexadecimal /testbench/d3/apbi
add wave -noupdate -format Literal -radix hexadecimal /testbench/d3/apbo
add wave -noupdate -format Literal -radix hexadecimal /testbench/d3/ahbsi
add wave -noupdate -format Literal -radix hexadecimal /testbench/d3/ahbso
add wave -noupdate -format Literal -radix hexadecimal /testbench/d3/ahbmi
add wave -noupdate -format Literal -radix hexadecimal /testbench/d3/ahbmo
add wave -noupdate -format Literal -radix hexadecimal /testbench/d3/cpu__0/nosh/u0/p0/rfi
add wave -noupdate -format Literal -radix hexadecimal /testbench/d3/cpu__0/nosh/u0/p0/rfo
add wave -noupdate -format Literal -radix hexadecimal /testbench/d3/cpu__0/nosh/u0/p0/crami
add wave -noupdate -format Literal -radix hexadecimal /testbench/d3/cpu__0/nosh/u0/p0/cramo
add wave -noupdate -format Literal -radix hexadecimal /testbench/d3/cpu__0/nosh/u0/p0/ici
add wave -noupdate -format Literal -radix hexadecimal /testbench/d3/cpu__0/nosh/u0/p0/ico
add wave -noupdate -format Literal -radix hexadecimal /testbench/d3/cpu__0/nosh/u0/p0/dci
add wave -noupdate -format Literal -radix hexadecimal /testbench/d3/cpu__0/nosh/u0/p0/dco
add wave -noupdate -format Logic /testbench/d3/cpu__0/nosh/u0/p0/holdnx
add wave -noupdate -format Logic /testbench/etx_clk
add wave -noupdate -format Logic /testbench/erx_clk
add wave -noupdate -format Logic /testbench/erx_dv
add wave -noupdate -format Logic /testbench/erx_er
add wave -noupdate -format Logic /testbench/erx_col
add wave -noupdate -format Logic /testbench/eth_gtxclk
add wave -noupdate -format Logic /testbench/erx_crs
add wave -noupdate -format Logic /testbench/etx_en
add wave -noupdate -format Logic /testbench/etx_er
add wave -noupdate -format Logic /testbench/eth_macclk
add wave -noupdate -format Literal -radix hexadecimal /testbench/erxd
add wave -noupdate -format Literal -radix hexadecimal /testbench/etxd
add wave -noupdate -format Logic /testbench/emdc
add wave -noupdate -format Logic /testbench/emdio
add wave -noupdate -format Logic /testbench/emdintn
TreeUpdate [SetDefaultTree]
WaveRestoreCursors {{Cursor 1} {0 ps} 0}
configure wave -namecolwidth 150
configure wave -valuecolwidth 100
configure wave -justifyvalue left
configure wave -signalnamewidth 0
configure wave -snapdistance 10
configure wave -datasetprefix 0
configure wave -rowmargin 4
configure wave -childrowmargin 2
configure wave -gridoffset 0
configure wave -gridperiod 1
configure wave -griddelta 40
configure wave -timeline 0
update
WaveRestoreZoom {2177081115 ps} {2524606258 ps}
