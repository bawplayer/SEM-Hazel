setMode -bs
setCable -port auto
identify -inferir 
attachflash -position 1 -spi "W25Q64BV"
assignFile -p 1 -file "digilent-nexys3-xc6lx16.mcs"
assignfiletoattachedflash -position 1 -file "digilent-nexys3-xc6lx16.mcs"
program -p 1 -dataWidth 4 -spionly -e -v -loadfpga 
quit
