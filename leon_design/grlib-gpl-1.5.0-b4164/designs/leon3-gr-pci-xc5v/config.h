/*
 * Automatically generated C config: don't edit
 */
#define AUTOCONF_INCLUDED
#define CONFIG_HAS_SHARED_GRFPU 1
/*
 * Synthesis      
 */
#undef  CONFIG_SYN_INFERRED
#undef  CONFIG_SYN_STRATIX
#undef  CONFIG_SYN_STRATIXII
#undef  CONFIG_SYN_STRATIXIII
#undef  CONFIG_SYN_STRATIXIV
#undef  CONFIG_SYN_CYCLONEIII
#undef  CONFIG_SYN_ALTERA
#undef  CONFIG_SYN_AXCEL
#undef  CONFIG_SYN_AXDSP
#undef  CONFIG_SYN_PROASIC
#undef  CONFIG_SYN_PROASICPLUS
#undef  CONFIG_SYN_PROASIC3
#undef  CONFIG_SYN_PROASIC3E
#undef  CONFIG_SYN_PROASIC3L
#undef  CONFIG_SYN_IGLOO
#undef  CONFIG_SYN_IGLOO2
#undef  CONFIG_SYN_SF2
#undef  CONFIG_SYN_RTG4
#undef  CONFIG_SYN_FUSION
#undef  CONFIG_SYN_UT025CRH
#undef  CONFIG_SYN_UT130HBD
#undef  CONFIG_SYN_UT90NHBD
#undef  CONFIG_SYN_ATC18
#undef  CONFIG_SYN_ATC18RHA
#undef  CONFIG_SYN_CMOS9SF
#undef  CONFIG_SYN_CUSTOM1
#undef  CONFIG_SYN_IHP25
#undef  CONFIG_SYN_IHP25RH
#undef  CONFIG_SYN_LATTICE
#undef  CONFIG_SYN_ECLIPSE
#undef  CONFIG_SYN_RH_LIB18T
#undef  CONFIG_SYN_RHUMC
#undef  CONFIG_SYN_SAED32
#undef  CONFIG_SYN_DARE
#undef  CONFIG_SYN_RHS65
#undef  CONFIG_SYN_SMIC13
#undef  CONFIG_SYN_TM65GPLUS
#undef  CONFIG_SYN_TSMC90
#undef  CONFIG_SYN_UMC
#undef  CONFIG_SYN_ARTIX7
#undef  CONFIG_SYN_KINTEX7
#undef  CONFIG_SYN_SPARTAN3
#undef  CONFIG_SYN_SPARTAN3E
#undef  CONFIG_SYN_SPARTAN6
#undef  CONFIG_SYN_VIRTEX2
#undef  CONFIG_SYN_VIRTEX4
#define CONFIG_SYN_VIRTEX5 1
#undef  CONFIG_SYN_VIRTEX6
#undef  CONFIG_SYN_VIRTEX7
#undef  CONFIG_SYN_ZYNQ7000
#define CONFIG_TRANS_GTP0 1
#undef  CONFIG_TRANS_GTP1
#undef  CONFIG_TRANS_GTX0
#undef  CONFIG_TRANS_GTX1
#undef  CONFIG_TRANS_GTH0
#undef  CONFIG_TRANS_GTH1
#undef  CONFIG_SYN_INFER_RAM
#undef  CONFIG_SYN_INFER_PADS
#undef  CONFIG_SYN_NO_ASYNC
#undef  CONFIG_SYN_SCAN
#undef  CONFIG_FPGA_LX50
#undef  CONFIG_FPGA_LX85
#define CONFIG_FPGA_LX110 1
/*
 * Clock generation
 */
#undef  CONFIG_CLK_INFERRED
#undef  CONFIG_CLK_HCLKBUF
#undef  CONFIG_CLK_UT130HBD
#undef  CONFIG_CLK_ALTDLL
#undef  CONFIG_CLK_LATDLL
#undef  CONFIG_CLK_PRO3PLL
#undef  CONFIG_CLK_PRO3EPLL
#undef  CONFIG_CLK_PRO3LPLL
#undef  CONFIG_CLK_FUSPLL
#undef  CONFIG_CLK_LIB18T
#undef  CONFIG_CLK_RHUMC
#undef  CONFIG_CLK_DARE
#undef  CONFIG_CLK_SAED32
#undef  CONFIG_CLK_EASIC45
#undef  CONFIG_CLK_RHS65
#undef  CONFIG_CLK_CLKPLLE2
#undef  CONFIG_CLK_CLKDLL
#define CONFIG_CLK_DCM 1
#define CONFIG_CLK_MUL (7)
#define CONFIG_CLK_DIV (5)
#undef  CONFIG_PCI_CLKDLL
#undef  CONFIG_CLK_NOFB
#undef  CONFIG_PCI_SYSCLK
/*
 * Processor            
 */
#define CONFIG_LEON3 1
#undef  CONFIG_LEON4
#define CONFIG_PROC_NUM (2)
#undef  CONFIG_LEON_MIN
#undef  CONFIG_LEON_GP
#undef  CONFIG_LEON_HP
#define CONFIG_LEON_CUSTOM 1
/*
 * Integer unit                                           
 */
#define CONFIG_IU_NWINDOWS (8)
#define CONFIG_IU_V8MULDIV 1
#define CONFIG_IU_MUL_LATENCY_2 1
#undef  CONFIG_IU_MUL_LATENCY_4
#undef  CONFIG_IU_MUL_LATENCY_5
#define CONFIG_IU_MUL_INFERRED 1
#undef  CONFIG_IU_MUL_MODGEN
#undef  CONFIG_IU_MUL_TECHSPEC
#undef  CONFIG_IU_MUL_DW
#define CONFIG_IU_SVT 1
#define CONFIG_IU_LDELAY (1)
#define CONFIG_IU_WATCHPOINTS (2)
#define CONFIG_PWD 1
#define CONFIG_IU_RSTADDR 00000
#undef  CONFIG_NP_ASI
#undef  CONFIG_WRPSR
#undef  CONFIG_ALTWIN
#undef  CONFIG_REX
/*
 * Floating-point unit
 */
#undef  CONFIG_FPU_ENABLE
/*
 * Cache system
 */
#define CONFIG_ICACHE_ENABLE 1
#undef  CONFIG_ICACHE_ASSO1
#undef  CONFIG_ICACHE_ASSO2
#undef  CONFIG_ICACHE_ASSO3
#define CONFIG_ICACHE_ASSO4 1
#undef  CONFIG_ICACHE_SZ1
#undef  CONFIG_ICACHE_SZ2
#define CONFIG_ICACHE_SZ4 1
#undef  CONFIG_ICACHE_SZ8
#undef  CONFIG_ICACHE_SZ16
#undef  CONFIG_ICACHE_SZ32
#undef  CONFIG_ICACHE_SZ64
#undef  CONFIG_ICACHE_SZ128
#undef  CONFIG_ICACHE_SZ256
#undef  CONFIG_ICACHE_LZ16
#define CONFIG_ICACHE_LZ32 1
#undef  CONFIG_ICACHE_ALGORND
#define CONFIG_ICACHE_ALGOLRU 1
#undef  CONFIG_ICACHE_LOCK
#define CONFIG_DCACHE_ENABLE 1
#undef  CONFIG_DCACHE_ASSO1
#undef  CONFIG_DCACHE_ASSO2
#undef  CONFIG_DCACHE_ASSO3
#define CONFIG_DCACHE_ASSO4 1
#undef  CONFIG_DCACHE_SZ1
#undef  CONFIG_DCACHE_SZ2
#define CONFIG_DCACHE_SZ4 1
#undef  CONFIG_DCACHE_SZ8
#undef  CONFIG_DCACHE_SZ16
#undef  CONFIG_DCACHE_SZ32
#undef  CONFIG_DCACHE_SZ64
#undef  CONFIG_DCACHE_SZ128
#undef  CONFIG_DCACHE_SZ256
#define CONFIG_DCACHE_LZ16 1
#undef  CONFIG_DCACHE_LZ32
#undef  CONFIG_DCACHE_ALGORND
#define CONFIG_DCACHE_ALGOLRU 1
#undef  CONFIG_DCACHE_LOCK
#define CONFIG_DCACHE_SNOOP 1
#define CONFIG_DCACHE_SNOOP_SEPTAG 1
#undef  CONFIG_DCACHE_SNOOP_SP
#define CONFIG_CACHE_FIXED 0
/*
 * MMU
 */
#define CONFIG_MMU_ENABLE 1
#undef  CONFIG_MMU_COMBINED
#define CONFIG_MMU_SPLIT 1
#define CONFIG_MMU_REPARRAY 1
#undef  CONFIG_MMU_REPINCREMENT
#undef  CONFIG_MMU_I2
#undef  CONFIG_MMU_I4
#define CONFIG_MMU_I8 1
#undef  CONFIG_MMU_I16
#undef  CONFIG_MMU_I32
#undef  CONFIG_MMU_I64
#undef  CONFIG_MMU_D2
#undef  CONFIG_MMU_D4
#undef  CONFIG_MMU_D8
#define CONFIG_MMU_D16 1
#undef  CONFIG_MMU_D32
#undef  CONFIG_MMU_D64
#define CONFIG_MMU_FASTWB 1
/*
 * Debug Support Unit        
 */
#define CONFIG_DSU_ENABLE 1
#define CONFIG_DSU_ITRACE 1
#undef  CONFIG_DSU_ITRACESZ1
#define CONFIG_DSU_ITRACESZ2 1
#undef  CONFIG_DSU_ITRACESZ4
#undef  CONFIG_DSU_ITRACESZ8
#undef  CONFIG_DSU_ITRACESZ16
#undef  CONFIG_DSU_ITRACE_2P
#define CONFIG_DSU_ATRACE 1
#undef  CONFIG_DSU_ATRACESZ1
#define CONFIG_DSU_ATRACESZ2 1
#undef  CONFIG_DSU_ATRACESZ4
#undef  CONFIG_DSU_ATRACESZ8
#undef  CONFIG_DSU_ATRACESZ16
#undef  CONFIG_DSU_AFILT
#undef  CONFIG_DSU_ASTAT
#define CONFIG_DSU_AHBWP2 1
#undef  CONFIG_DSU_AHBWP1
#undef  CONFIG_DSU_AHBWP0
#undef  CONFIG_STAT_ENABLE
/*
 * Fault-tolerance  
 */
#define CONFIG_IUFT_NONE 1
#undef  CONFIG_IUFT_PAR
#undef  CONFIG_IUFT_DMR
#undef  CONFIG_IUFT_BCH
#undef  CONFIG_IUFT_TMR
#undef  CONFIG_RF_ERRINJ
#undef  CONFIG_CACHE_FT_EN
#define CONFIG_CACHE_ERRINJ (0)
/*
 * VHDL debug settings       
 */
#undef  CONFIG_IU_DISAS
#undef  CONFIG_DEBUG_PC32
/*
 * L2 Cache
 */
#undef  CONFIG_L2_ENABLE
#undef  CONFIG_L2_ASSO1
#define CONFIG_L2_ASSO2 1
#undef  CONFIG_L2_ASSO3
#undef  CONFIG_L2_ASSO4
#undef  CONFIG_L2_SZ1
#undef  CONFIG_L2_SZ2
#undef  CONFIG_L2_SZ4
#undef  CONFIG_L2_SZ8
#define CONFIG_L2_SZ16 1
#undef  CONFIG_L2_SZ32
#undef  CONFIG_L2_SZ64
#undef  CONFIG_L2_SZ128
#undef  CONFIG_L2_SZ256
#undef  CONFIG_L2_SZ512
#define CONFIG_L2_LINE32 1
#undef  CONFIG_L2_LINE64
#undef  CONFIG_L2_HPROT
#define CONFIG_L2_PEN 1
#undef  CONFIG_L2_WT
#undef  CONFIG_L2_RAN
#define CONFIG_L2_SHARE 1
#define CONFIG_L2_MAP 00F0
#define CONFIG_L2_MTRR (0)
#undef  CONFIG_L2_EDAC
/*
 * AMBA configuration
 */
#define CONFIG_AHB_DEFMST (0)
#define CONFIG_AHB_RROBIN 1
#undef  CONFIG_AHB_SPLIT
#undef  CONFIG_AHB_FPNPEN
#define CONFIG_AHB_IOADDR FFF
#define CONFIG_APB_HADDR 800
#undef  CONFIG_AHB_MON
#undef  CONFIG_AHB_MONERR
#undef  CONFIG_AHB_MONWAR
#undef  CONFIG_AHB_DTRACE
/*
 * Debug Link           
 */
#define CONFIG_DSU_UART 1
#define CONFIG_DSU_JTAG 1
#undef  CONFIG_GRUSB_DCL
#define CONFIG_GRUSB_DCL_ULPI 1
#undef  CONFIG_GRUSB_DCL_UTMI8
#undef  CONFIG_GRUSB_DCL_UTMI16
#define CONFIG_DSU_ETH 1
#undef  CONFIG_DSU_ETHSZ1
#define CONFIG_DSU_ETHSZ2 1
#undef  CONFIG_DSU_ETHSZ4
#undef  CONFIG_DSU_ETHSZ8
#undef  CONFIG_DSU_ETHSZ16
#define CONFIG_DSU_IPMSB C0A8
#define CONFIG_DSU_IPLSB 0033
#define CONFIG_DSU_ETHMSB 0200ee
#define CONFIG_DSU_ETHLSB 000007
#undef  CONFIG_DSU_ETH_PROG
/*
 * Memory controllers             
 */
/*
 * 8/32-bit PROM/SRAM controller 
 */
#define CONFIG_SRCTRL 1
#undef  CONFIG_SRCTRL_8BIT
#define CONFIG_SRCTRL_PROMWS (5)
#define CONFIG_SRCTRL_RAMWS (0)
#define CONFIG_SRCTRL_IOWS (0)
#undef  CONFIG_SRCTRL_RMW
#define CONFIG_SRCTRL_SRBANKS1 1
#undef  CONFIG_SRCTRL_SRBANKS2
#undef  CONFIG_SRCTRL_SRBANKS3
#undef  CONFIG_SRCTRL_SRBANKS4
#undef  CONFIG_SRCTRL_SRBANKS5
#undef  CONFIG_SRCTRL_BANKSZ0
#undef  CONFIG_SRCTRL_BANKSZ1
#undef  CONFIG_SRCTRL_BANKSZ2
#undef  CONFIG_SRCTRL_BANKSZ3
#undef  CONFIG_SRCTRL_BANKSZ4
#undef  CONFIG_SRCTRL_BANKSZ5
#undef  CONFIG_SRCTRL_BANKSZ6
#undef  CONFIG_SRCTRL_BANKSZ7
#undef  CONFIG_SRCTRL_BANKSZ8
#undef  CONFIG_SRCTRL_BANKSZ9
#undef  CONFIG_SRCTRL_BANKSZ10
#undef  CONFIG_SRCTRL_BANKSZ11
#undef  CONFIG_SRCTRL_BANKSZ12
#undef  CONFIG_SRCTRL_BANKSZ13
#define CONFIG_SRCTRL_ROMASEL (24)
/*
 * PC133 SDRAM controller             
 */
#define CONFIG_SDCTRL 1
#define CONFIG_SDCTRL_BUS64 1
#undef  CONFIG_SDCTRL_INVCLK
#undef  CONFIG_SDCTRL_PAGE
/*
 * Leon2 memory controller        
 */
#undef  CONFIG_MCTRL_LEON2
#undef  CONFIG_MCTRL_8BIT
#undef  CONFIG_MCTRL_16BIT
#undef  CONFIG_MCTRL_5CS
#undef  CONFIG_MCTRL_SDRAM
/*
 * PROM/SRAM/SDRAM Memory controller with EDAC       
 */
#undef  CONFIG_MCTRLFT
#undef  CONFIG_MCTRLFT_8BIT
#undef  CONFIG_MCTRLFT_16BIT
#undef  CONFIG_MCTRLFT_5CS
#define CONFIG_MCTRLFT_ROMASEL0 1
#undef  CONFIG_MCTRLFT_ROMASEL1
#undef  CONFIG_MCTRLFT_ROMASEL2
#undef  CONFIG_MCTRLFT_ROMASEL3
#undef  CONFIG_MCTRLFT_ROMASEL4
#undef  CONFIG_MCTRLFT_ROMASEL5
#undef  CONFIG_MCTRLFT_ROMASEL6
#undef  CONFIG_MCTRLFT_ROMASEL7
#undef  CONFIG_MCTRLFT_ROMASEL8
#undef  CONFIG_MCTRLFT_ROMASEL9
#undef  CONFIG_MCTRLFT_ROMASEL10
#undef  CONFIG_MCTRLFT_ROMASEL11
#undef  CONFIG_MCTRLFT_ROMASEL12
#undef  CONFIG_MCTRLFT_ROMASEL13
#undef  CONFIG_MCTRLFT_ROMASEL14
#undef  CONFIG_MCTRLFT_ROMASEL15
#undef  CONFIG_MCTRLFT_ROMASEL16
#undef  CONFIG_MCTRLFT_ROMASEL17
#undef  CONFIG_MCTRLFT_ROMASEL18
#undef  CONFIG_MCTRLFT_ROMASEL19
#undef  CONFIG_MCTRLFT_ROMASEL20
#undef  CONFIG_MCTRLFT_ROMASEL21
#undef  CONFIG_MCTRLFT_ROMASEL22
#undef  CONFIG_MCTRLFT_ROMASEL23
#undef  CONFIG_MCTRLFT_ROMASEL24
#undef  CONFIG_MCTRLFT_ROMASEL25
#undef  CONFIG_MCTRLFT_ROMASEL26
#undef  CONFIG_MCTRLFT_ROMASEL27
#undef  CONFIG_MCTRLFT_ROMASEL28
#undef  CONFIG_MCTRLFT_SDRAM
#undef  CONFIG_MCTRLFT_EDAC
#undef  CONFIG_MCTRLFT_WFB
#undef  CONFIG_MCTRLFT_NETLIST
#define CONFIG_AHBSTAT_ENABLE 1
#define CONFIG_AHBSTAT_NFTSLV (1)
/*
 * Peripherals             
 */
/*
 * On-chip RAM/ROM                 
 */
#undef  CONFIG_AHBRAM_ENABLE
#undef  CONFIG_AHBRAM_SZ1
#undef  CONFIG_AHBRAM_SZ2
#define CONFIG_AHBRAM_SZ4 1
#undef  CONFIG_AHBRAM_SZ8
#undef  CONFIG_AHBRAM_SZ16
#undef  CONFIG_AHBRAM_SZ32
#undef  CONFIG_AHBRAM_SZ64
#undef  CONFIG_AHBRAM_SZ128
#undef  CONFIG_AHBRAM_SZ256
#undef  CONFIG_AHBRAM_SZ512
#undef  CONFIG_AHBRAM_SZ1024
#undef  CONFIG_AHBRAM_SZ2048
#undef  CONFIG_AHBRAM_SZ4096
#define CONFIG_AHBRAM_START A00
#undef  CONFIG_AHBRAM_PIPE
/*
 * Ethernet             
 */
#define CONFIG_GRETH_ENABLE 1
#undef  CONFIG_GRETH_GIGA
#undef  CONFIG_GRETH_FIFO4
#undef  CONFIG_GRETH_FIFO8
#define CONFIG_GRETH_FIFO16 1
#undef  CONFIG_GRETH_FIFO32
#undef  CONFIG_GRETH_FIFO64
/*
 * CAN                     
 */
#undef  CONFIG_CAN_ENABLE
#define CONFIG_CAN_NUM (1)
#define CONFIG_CANIO C00
#define CONFIG_CANIRQ (13)
#undef  CONFIG_CANSEPIRQ
#undef  CONFIG_CAN_SYNCRST
#undef  CONFIG_CAN_FT
/*
 * Spacewire      
 */
#undef  CONFIG_SPW_ENABLE
#define CONFIG_SPW_NUM (1)
#undef  CONFIG_SPW_AHBFIFO4
#undef  CONFIG_SPW_AHBFIFO8
#define CONFIG_SPW_AHBFIFO16 1
#undef  CONFIG_SPW_AHBFIFO32
#define CONFIG_SPW_RXFIFO16 1
#undef  CONFIG_SPW_RXFIFO32
#undef  CONFIG_SPW_RXFIFO64
#undef  CONFIG_SPW_RMAP
#undef  CONFIG_SPW_RMAPCRC
#undef  CONFIG_SPW_RXUNAL
#undef  CONFIG_SPW_FT
#undef  CONFIG_SPW_NETLIST
#define CONFIG_SPW_PORTS (1)
#undef  CONFIG_SPW_GRSPW1
#define CONFIG_SPW_GRSPW2 1
#define CONFIG_SPW_DMACHAN (1)
#undef  CONFIG_SPW_RTSAME
#undef  CONFIG_SPW_RX_SDR
#define CONFIG_SPW_RX_DDR 1
#undef  CONFIG_SPW_RX_PAD
#undef  CONFIG_SPW_RX_XOR
#undef  CONFIG_SPW_RX_AFLEX
#define CONFIG_SPW_TX_SDR 1
#undef  CONFIG_SPW_TX_DDR
#undef  CONFIG_SPW_TX_AFLEX
/*
 * PCI              
 */
/*
 * GRPCI2         
 */
#define CONFIG_GRPCI2_MASTER 1
#define CONFIG_GRPCI2_TARGET 1
#undef  CONFIG_GRPCI2_DMA
#define CONFIG_GRPCI2_VENDORID 1AC8
#define CONFIG_GRPCI2_DEVICEID 0054
#define CONFIG_GRPCI2_CLASS 000000
#define CONFIG_GRPCI2_REVID 00
#define CONFIG_GRPCI2_CAPPOINT 40
#define CONFIG_GRPCI2_NEXTCAPPOINT 00
#define CONFIG_GRPCI2_BAR0 (26)
#define CONFIG_GRPCI2_BAR1 (0)
#define CONFIG_GRPCI2_BAR2 (0)
#define CONFIG_GRPCI2_BAR3 (0)
#define CONFIG_GRPCI2_BAR4 (0)
#define CONFIG_GRPCI2_BAR5 (0)
#define CONFIG_GRPCI2_FIFO8 1
#undef  CONFIG_GRPCI2_FIFO16
#undef  CONFIG_GRPCI2_FIFO32
#undef  CONFIG_GRPCI2_FIFO64
#undef  CONFIG_GRPCI2_FIFO128
#undef  CONFIG_GRPCI2_FIFOCNT1
#define CONFIG_GRPCI2_FIFOCNT2 1
#undef  CONFIG_GRPCI2_FIFOCNT3
#undef  CONFIG_GRPCI2_FIFOCNT4
#undef  CONFIG_GRPCI2_ENDIAN
#undef  CONFIG_GRPCI2_DINT
#define CONFIG_GRPCI2_DINTMASK 0
#undef  CONFIG_GRPCI2_HINT
#define CONFIG_GRPCI2_HINTMASK 0
#define CONFIG_GRPCI2_TRACE0 1
#undef  CONFIG_GRPCI2_TRACE256
#undef  CONFIG_GRPCI2_TRACE512
#undef  CONFIG_GRPCI2_TRACE1024
#undef  CONFIG_GRPCI2_TRACE2048
#undef  CONFIG_GRPCI2_TRACE4096
#undef  CONFIG_GRPCI2_TRACEAPB
#undef  CONFIG_GRPCI2_BYPASS
#define CONFIG_GRPCI2_EXTCFG (0)
#undef  CONFIG_PCI_ARBITER
#undef  CONFIG_PCI_ARBITER_APB
#define CONFIG_PCI_ARBITER_NREQ (4)
/*
 * USB 2.0 Host Controller      
 */
#undef  CONFIG_GRUSBHC_ENABLE
#undef  CONFIG_GRUSBHC_EHC
#undef  CONFIG_GRUSBHC_UHC
#define CONFIG_GRUSBHC_NPORTS (1)
#define CONFIG_GRUSBHC_ULPI 1
#undef  CONFIG_GRUSBHC_UTMI16
#undef  CONFIG_GRUSBHC_UTMI8
#define CONFIG_GRUSBHC_VBUSEXT 1
#undef  CONFIG_GRUSBHC_VBUSINT
#define CONFIG_GRUSBHC_FAULTL 1
#undef  CONFIG_GRUSBHC_FAULTH
#undef  CONFIG_GRUSBHC_FAULTN
/*
 * Memory interface
 */
#undef  CONFIG_GRUSBHC_BEREGS
#undef  CONFIG_GRUSBHC_BEDESC
#define CONFIG_GRUSBHC_BWRD (16)
/*
 * Port routing
 */
#undef  CONFIG_GRUSBHC_PRR
#define CONFIG_GRUSBHC_NPCC (1)
/*
 * USB 2.0 Device Controller      
 */
#undef  CONFIG_GRUSBDC_ENABLE
#undef  CONFIG_GRUSBDC_AIFACE
#define CONFIG_GRUSBDC_ULPI 1
#undef  CONFIG_GRUSBDC_UTMI8
#undef  CONFIG_GRUSBDC_UTMI16
#define CONFIG_GRUSBDC_NEPI (1)
#define CONFIG_GRUSBDC_NEPO (1)
#define CONFIG_GRUSBDC_I0 (1024)
#define CONFIG_GRUSBDC_I1 (1024)
#define CONFIG_GRUSBDC_I2 (1024)
#define CONFIG_GRUSBDC_I3 (1024)
#define CONFIG_GRUSBDC_I4 (1024)
#define CONFIG_GRUSBDC_I5 (1024)
#define CONFIG_GRUSBDC_I6 (1024)
#define CONFIG_GRUSBDC_I7 (1024)
#define CONFIG_GRUSBDC_I8 (1024)
#define CONFIG_GRUSBDC_I9 (1024)
#define CONFIG_GRUSBDC_I10 (1024)
#define CONFIG_GRUSBDC_I11 (1024)
#define CONFIG_GRUSBDC_I12 (1024)
#define CONFIG_GRUSBDC_I13 (1024)
#define CONFIG_GRUSBDC_I14 (1024)
#define CONFIG_GRUSBDC_I15 (1024)
#define CONFIG_GRUSBDC_O0 (1024)
#define CONFIG_GRUSBDC_O1 (1024)
#define CONFIG_GRUSBDC_O2 (1024)
#define CONFIG_GRUSBDC_O3 (1024)
#define CONFIG_GRUSBDC_O4 (1024)
#define CONFIG_GRUSBDC_O5 (1024)
#define CONFIG_GRUSBDC_O6 (1024)
#define CONFIG_GRUSBDC_O7 (1024)
#define CONFIG_GRUSBDC_O8 (1024)
#define CONFIG_GRUSBDC_O9 (1024)
#define CONFIG_GRUSBDC_O10 (1024)
#define CONFIG_GRUSBDC_O11 (1024)
#define CONFIG_GRUSBDC_O12 (1024)
#define CONFIG_GRUSBDC_O13 (1024)
#define CONFIG_GRUSBDC_O14 (1024)
#define CONFIG_GRUSBDC_O15 (1024)
/*
 * UARTs, timers and I/O port         
 */
#define CONFIG_UART1_ENABLE 1
#undef  CONFIG_UA1_FIFO1
#undef  CONFIG_UA1_FIFO2
#define CONFIG_UA1_FIFO4 1
#undef  CONFIG_UA1_FIFO8
#undef  CONFIG_UA1_FIFO16
#undef  CONFIG_UA1_FIFO32
#define CONFIG_UART2_ENABLE 1
#undef  CONFIG_UA2_FIFO1
#undef  CONFIG_UA2_FIFO2
#define CONFIG_UA2_FIFO4 1
#undef  CONFIG_UA2_FIFO8
#undef  CONFIG_UA2_FIFO16
#undef  CONFIG_UA2_FIFO32
#define CONFIG_IRQ3_ENABLE 1
#undef  CONFIG_IRQ3_SEC
#define CONFIG_GPT_ENABLE 1
#define CONFIG_GPT_NTIM (2)
#define CONFIG_GPT_SW (16)
#define CONFIG_GPT_TW (32)
#define CONFIG_GPT_IRQ (8)
#define CONFIG_GPT_SEPIRQ 1
#undef  CONFIG_GPT_WDOGEN
#define CONFIG_GRGPIO_ENABLE 1
#define CONFIG_GRGPIO_WIDTH (8)
#define CONFIG_GRGPIO_IMASK fe
/*
 * MIL-STD-1553B
 */
#undef  CONFIG_GR1553B_ENABLE
#undef  CONFIG_GR1553B_BCEN
#undef  CONFIG_GR1553B_RTEN
#undef  CONFIG_GR1553B_BMEN
/*
 * VHDL Debugging        
 */
#undef  CONFIG_DEBUG_UART
