#if defined CONFIG_SYN_INFERRED
#define CONFIG_SYN_TECH inferred
#elif defined CONFIG_SYN_UMC
#define CONFIG_SYN_TECH umc
#elif defined CONFIG_SYN_RHUMC
#define CONFIG_SYN_TECH rhumc
#elif defined CONFIG_SYN_DARE
#define CONFIG_SYN_TECH dare
#elif defined CONFIG_SYN_SAED32
#define CONFIG_SYN_TECH saed32
#elif defined CONFIG_SYN_RHS65
#define CONFIG_SYN_TECH rhs65
#elif defined CONFIG_SYN_ATC18
#define CONFIG_SYN_TECH atc18s
#elif defined CONFIG_SYN_ATC18RHA
#define CONFIG_SYN_TECH atc18rha
#elif defined CONFIG_SYN_AXCEL
#define CONFIG_SYN_TECH axcel
#elif defined CONFIG_SYN_AXDSP
#define CONFIG_SYN_TECH axdsp
#elif defined CONFIG_SYN_PROASICPLUS
#define CONFIG_SYN_TECH proasic
#elif defined CONFIG_SYN_ALTERA
#define CONFIG_SYN_TECH altera
#elif defined CONFIG_SYN_STRATIX
#define CONFIG_SYN_TECH stratix1
#elif defined CONFIG_SYN_STRATIXII
#define CONFIG_SYN_TECH stratix2
#elif defined CONFIG_SYN_STRATIXIII
#define CONFIG_SYN_TECH stratix3
#elif defined CONFIG_SYN_STRATIXIV
#define CONFIG_SYN_TECH stratix4
#elif defined CONFIG_SYN_CYCLONEII
#define CONFIG_SYN_TECH stratix2
#elif defined CONFIG_SYN_CYCLONEIII
#define CONFIG_SYN_TECH cyclone3
#elif defined CONFIG_SYN_CYCLONEIV
#define CONFIG_SYN_TECH cyclone3
#elif defined CONFIG_SYN_IHP25
#define CONFIG_SYN_TECH ihp25
#elif defined CONFIG_SYN_IHP25RH
#define CONFIG_SYN_TECH ihp25rh
#elif defined CONFIG_SYN_CMOS9SF
#define CONFIG_SYN_TECH cmos9sf
#elif defined CONFIG_SYN_LATTICE
#define CONFIG_SYN_TECH lattice
#elif defined CONFIG_SYN_ECLIPSE
#define CONFIG_SYN_TECH eclipse
#elif defined CONFIG_SYN_PEREGRINE
#define CONFIG_SYN_TECH peregrine
#elif defined CONFIG_SYN_PROASIC
#define CONFIG_SYN_TECH proasic
#elif defined CONFIG_SYN_PROASIC3
#define CONFIG_SYN_TECH apa3
#elif defined CONFIG_SYN_PROASIC3E
#define CONFIG_SYN_TECH apa3e
#elif defined CONFIG_SYN_PROASIC3L
#define CONFIG_SYN_TECH apa3l
#elif defined CONFIG_SYN_IGLOO
#define CONFIG_SYN_TECH apa3
#elif defined CONFIG_SYN_IGLOO2
#define CONFIG_SYN_TECH igloo2
#elif defined CONFIG_SYN_SF2
#define CONFIG_SYN_TECH smartfusion2
#elif defined CONFIG_SYN_RTG4
#define CONFIG_SYN_TECH rtg4
#elif defined CONFIG_SYN_FUSION
#define CONFIG_SYN_TECH actfus
#elif defined CONFIG_SYN_SPARTAN2
#define CONFIG_SYN_TECH virtex
#elif defined CONFIG_SYN_VIRTEX
#define CONFIG_SYN_TECH virtex
#elif defined CONFIG_SYN_VIRTEXE
#define CONFIG_SYN_TECH virtex
#elif defined CONFIG_SYN_SPARTAN3
#define CONFIG_SYN_TECH spartan3
#elif defined CONFIG_SYN_SPARTAN3E
#define CONFIG_SYN_TECH spartan3e
#elif defined CONFIG_SYN_SPARTAN6
#define CONFIG_SYN_TECH spartan6
#elif defined CONFIG_SYN_VIRTEX2
#define CONFIG_SYN_TECH virtex2
#elif defined CONFIG_SYN_VIRTEX4
#define CONFIG_SYN_TECH virtex4
#elif defined CONFIG_SYN_VIRTEX5
#define CONFIG_SYN_TECH virtex5
#elif defined CONFIG_SYN_VIRTEX6
#define CONFIG_SYN_TECH virtex6
#elif defined CONFIG_SYN_VIRTEX7
#define CONFIG_SYN_TECH virtex7
#elif defined CONFIG_SYN_KINTEX7
#define CONFIG_SYN_TECH kintex7
#elif defined CONFIG_SYN_ARTIX7
#define CONFIG_SYN_TECH artix7
#elif defined CONFIG_SYN_ZYNQ7000
#define CONFIG_SYN_TECH zynq7000
#elif defined CONFIG_SYN_ARTIX77
#define CONFIG_SYN_TECH artix7
#elif defined CONFIG_SYN_ZYNQ7000
#define CONFIG_SYN_TECH zynq7000
#elif defined CONFIG_SYN_RH_LIB18T
#define CONFIG_SYN_TECH rhlib18t
#elif defined CONFIG_SYN_SMIC13
#define CONFIG_SYN_TECH smic013
#elif defined CONFIG_SYN_UT025CRH
#define CONFIG_SYN_TECH ut25
#elif defined CONFIG_SYN_UT130HBD
#define CONFIG_SYN_TECH ut130
#elif defined CONFIG_SYN_UT90NHBD
#define CONFIG_SYN_TECH ut90
#elif defined CONFIG_SYN_TSMC90
#define CONFIG_SYN_TECH tsmc90
#elif defined CONFIG_SYN_TM65GPLUS
#define CONFIG_SYN_TECH tm65gplus
#elif defined CONFIG_SYN_CUSTOM1
#define CONFIG_SYN_TECH custom1
#else
#error "unknown target technology"
#endif

#if defined CONFIG_SYN_INFER_RAM
#define CFG_RAM_TECH inferred
#elif defined CONFIG_MEM_UMC
#define CFG_RAM_TECH umc
#elif defined CONFIG_MEM_RHUMC
#define CFG_RAM_TECH rhumc
#elif defined CONFIG_MEM_DARE
#define CFG_RAM_TECH dare
#elif defined CONFIG_MEM_SAED32
#define CFG_RAM_TECH saed32
#elif defined CONFIG_MEM_RHS65
#define CFG_RAM_TECH rhs65
#elif defined CONFIG_MEM_VIRAGE
#define CFG_RAM_TECH memvirage
#elif defined CONFIG_MEM_ARTISAN
#define CFG_RAM_TECH memartisan
#elif defined CONFIG_MEM_CUSTOM1
#define CFG_RAM_TECH custom1
#elif defined CONFIG_MEM_VIRAGE90
#define CFG_RAM_TECH memvirage90
#elif defined CONFIG_MEM_INFERRED
#define CFG_RAM_TECH inferred
#else
#define CFG_RAM_TECH CONFIG_SYN_TECH
#endif

#if defined CONFIG_TRANS_GTP0
#define CFG_TRANS_TECH GTP0
#elif defined CONFIG_TRANS_GTP1
#define CFG_TRANS_TECH GTP1
#elif defined CONFIG_TRANS_GTX0
#define CFG_TRANS_TECH GTX0
#elif defined CONFIG_TRANS_GTX1
#define CFG_TRANS_TECH GTX1
#elif defined CONFIG_TRANS_GTH0
#define CFG_TRANS_TECH GTH0
#elif defined CONFIG_TRANS_GTH1
#define CFG_TRANS_TECH GTH1
#else
#define CFG_TRANS_TECH GTP0
#endif

#if defined CONFIG_SYN_INFER_PADS
#define CFG_PAD_TECH inferred
#else
#define CFG_PAD_TECH CONFIG_SYN_TECH
#endif

#ifndef CONFIG_SYN_NO_ASYNC
#define CONFIG_SYN_NO_ASYNC 0
#endif

#ifndef CONFIG_SYN_SCAN
#define CONFIG_SYN_SCAN 0
#endif


#if defined CONFIG_CLK_ALTDLL
#define CFG_CLK_TECH CONFIG_SYN_TECH
#elif defined CONFIG_CLK_HCLKBUF
#define CFG_CLK_TECH axcel
#elif defined CONFIG_CLK_LATDLL
#define CFG_CLK_TECH lattice
#elif defined CONFIG_CLK_PRO3PLL
#define CFG_CLK_TECH apa3
#elif defined CONFIG_CLK_PRO3EPLL
#define CFG_CLK_TECH apa3e
#elif defined CONFIG_CLK_PRO3LPLL
#define CFG_CLK_TECH apa3l
#elif defined CONFIG_CLK_FUSPLL
#define CFG_CLK_TECH actfus
#elif defined CONFIG_CLK_CLKDLL
#define CFG_CLK_TECH virtex
#elif defined CONFIG_CLK_CLKPLLE2
#define CFG_CLK_TECH CONFIG_SYN_TECH
#elif defined CONFIG_CLK_DCM
#define CFG_CLK_TECH CONFIG_SYN_TECH
#elif defined CONFIG_CLK_LIB18T
#define CFG_CLK_TECH rhlib18t
#elif defined CONFIG_CLK_RHUMC
#define CFG_CLK_TECH rhumc
#elif defined CONFIG_CLK_SAED32
#define CFG_CLK_TECH saed32
#elif defined CONFIG_CLK_RHS65
#define CFG_CLK_TECH rhs65
#elif defined CONFIG_CLK_DARE
#define CFG_CLK_TECH dare
#elif defined CONFIG_CLK_EASIC45
#define CFG_CLK_TECH easic45
#elif defined CONFIG_CLK_UT130HBD
#define CFG_CLK_TECH ut130
#else
#define CFG_CLK_TECH inferred
#endif

#ifndef CONFIG_CLK_MUL
#define CONFIG_CLK_MUL 2
#endif

#ifndef CONFIG_CLK_DIV
#define CONFIG_CLK_DIV 2
#endif

#ifndef CONFIG_OCLK_DIV
#define CONFIG_OCLK_DIV 1
#endif

#ifndef CONFIG_OCLKB_DIV
#define CONFIG_OCLKB_DIV 0
#endif

#ifndef CONFIG_OCLKC_DIV
#define CONFIG_OCLKC_DIV 0
#endif

#ifndef CONFIG_PCI_CLKDLL
#define CONFIG_PCI_CLKDLL 0
#endif

#ifndef CONFIG_PCI_SYSCLK
#define CONFIG_PCI_SYSCLK 0
#endif

#ifndef CONFIG_CLK_NOFB
#define CONFIG_CLK_NOFB 0
#endif
#ifdef CONFIG_LEON4
#define CONFIG_LEON 4
#else
#define CONFIG_LEON 3
#endif

#ifndef CONFIG_PROC_NUM
#define CONFIG_PROC_NUM 1
#endif

#ifndef CONFIG_IU_NWINDOWS
#define CONFIG_IU_NWINDOWS 8
#endif

#ifndef CONFIG_IU_RSTADDR
#define CONFIG_IU_RSTADDR 8
#endif

#ifndef CONFIG_IU_LDELAY
#define CONFIG_IU_LDELAY 1
#endif

#ifndef CONFIG_IU_WATCHPOINTS
#define CONFIG_IU_WATCHPOINTS 0
#endif

#ifdef CONFIG_IU_V8MULDIV
#ifdef CONFIG_IU_MUL_LATENCY_4
#define CFG_IU_V8 1
#elif defined CONFIG_IU_MUL_LATENCY_5
#define CFG_IU_V8 2
#elif defined CONFIG_IU_MUL_LATENCY_2
#define CFG_IU_V8 16#32#
#endif
#else
#define CFG_IU_V8 0
#endif

#ifdef CONFIG_IU_MUL_MODGEN
#define CFG_IU_MUL_STRUCT 1
#elif defined CONFIG_IU_MUL_TECHSPEC
#define CFG_IU_MUL_STRUCT 2
#elif defined CONFIG_IU_MUL_DW
#define CFG_IU_MUL_STRUCT 3
#else
#define CFG_IU_MUL_STRUCT 0
#endif

#ifndef CONFIG_PWD
#define CONFIG_PWD 0
#endif

#ifndef CONFIG_IU_MUL_MAC
#define CONFIG_IU_MUL_MAC 0
#endif

#ifndef CONFIG_IU_SVT
#define CONFIG_IU_SVT 0
#endif

#if defined CONFIG_FPU_GRFPC1
#define CONFIG_FPU_GRFPC 1
#elif defined CONFIG_FPU_GRFPC2
#define CONFIG_FPU_GRFPC 2
#else
#define CONFIG_FPU_GRFPC 0
#endif

#if defined CONFIG_FPU_GRFPU_INFMUL
#define CONFIG_FPU_GRFPU_MUL 0
#elif defined CONFIG_FPU_GRFPU_DWMUL
#define CONFIG_FPU_GRFPU_MUL 1
#elif defined CONFIG_FPU_GRFPU_MODGEN 
#define CONFIG_FPU_GRFPU_MUL 2
#elif defined CONFIG_FPU_GRFPU_TECHSPEC
#define CONFIG_FPU_GRFPU_MUL 3
#else
#define CONFIG_FPU_GRFPU_MUL 0
#endif

#if defined CONFIG_FPU_GRFPU_SH
#define CONFIG_FPU_GRFPU_SHARED 1
#else
#define CONFIG_FPU_GRFPU_SHARED 0
#endif

#if defined CONFIG_FPU_GRFPU
#define CONFIG_FPU (1+CONFIG_FPU_GRFPU_MUL)
#elif defined CONFIG_FPU_GRFPULITE
#define CONFIG_FPU (8+CONFIG_FPU_GRFPC)
#else
#define CONFIG_FPU 0
#endif

#ifndef CONFIG_FPU_NETLIST
#define CONFIG_FPU_NETLIST 0
#endif

#ifndef CONFIG_ICACHE_ENABLE
#define CONFIG_ICACHE_ENABLE 0
#endif

#if defined CONFIG_ICACHE_ASSO1
#define CFG_IU_ISETS 1
#elif defined CONFIG_ICACHE_ASSO2
#define CFG_IU_ISETS 2
#elif defined CONFIG_ICACHE_ASSO3
#define CFG_IU_ISETS 3
#elif defined CONFIG_ICACHE_ASSO4
#define CFG_IU_ISETS 4
#else
#define CFG_IU_ISETS 1
#endif

#if defined CONFIG_ICACHE_SZ1
#define CFG_ICACHE_SZ 1
#elif defined CONFIG_ICACHE_SZ2
#define CFG_ICACHE_SZ 2
#elif defined CONFIG_ICACHE_SZ4
#define CFG_ICACHE_SZ 4
#elif defined CONFIG_ICACHE_SZ8
#define CFG_ICACHE_SZ 8
#elif defined CONFIG_ICACHE_SZ16
#define CFG_ICACHE_SZ 16
#elif defined CONFIG_ICACHE_SZ32
#define CFG_ICACHE_SZ 32
#elif defined CONFIG_ICACHE_SZ64
#define CFG_ICACHE_SZ 64
#elif defined CONFIG_ICACHE_SZ128
#define CFG_ICACHE_SZ 128
#elif defined CONFIG_ICACHE_SZ256
#define CFG_ICACHE_SZ 256
#else
#define CFG_ICACHE_SZ 1
#endif

#ifdef CONFIG_ICACHE_LZ16
#define CFG_ILINE_SZ 4
#else
#define CFG_ILINE_SZ 8
#endif

#if defined CONFIG_ICACHE_ALGORND
#define CFG_ICACHE_ALGORND 2
#else
#define CFG_ICACHE_ALGORND 0
#endif

#ifndef CONFIG_ICACHE_LOCK
#define CONFIG_ICACHE_LOCK 0
#endif

#ifndef CONFIG_ICACHE_LRAM
#define CONFIG_ICACHE_LRAM 0
#endif

#ifndef CONFIG_ICACHE_LRSTART
#define CONFIG_ICACHE_LRSTART 8E
#endif

#if defined CONFIG_ICACHE_LRAM_SZ2
#define CFG_ILRAM_SIZE 2
#elif defined CONFIG_ICACHE_LRAM_SZ4
#define CFG_ILRAM_SIZE 4
#elif defined CONFIG_ICACHE_LRAM_SZ8
#define CFG_ILRAM_SIZE 8
#elif defined CONFIG_ICACHE_LRAM_SZ16
#define CFG_ILRAM_SIZE 16
#elif defined CONFIG_ICACHE_LRAM_SZ32
#define CFG_ILRAM_SIZE 32
#elif defined CONFIG_ICACHE_LRAM_SZ64
#define CFG_ILRAM_SIZE 64
#elif defined CONFIG_ICACHE_LRAM_SZ128
#define CFG_ILRAM_SIZE 128
#elif defined CONFIG_ICACHE_LRAM_SZ256
#define CFG_ILRAM_SIZE 256
#else
#define CFG_ILRAM_SIZE 1
#endif


#ifndef CONFIG_DCACHE_ENABLE
#define CONFIG_DCACHE_ENABLE 0
#endif

#if defined CONFIG_DCACHE_ASSO1
#define CFG_IU_DSETS 1
#elif defined CONFIG_DCACHE_ASSO2
#define CFG_IU_DSETS 2
#elif defined CONFIG_DCACHE_ASSO3
#define CFG_IU_DSETS 3
#elif defined CONFIG_DCACHE_ASSO4
#define CFG_IU_DSETS 4
#else
#define CFG_IU_DSETS 1
#endif

#if defined CONFIG_DCACHE_SZ1
#define CFG_DCACHE_SZ 1
#elif defined CONFIG_DCACHE_SZ2
#define CFG_DCACHE_SZ 2
#elif defined CONFIG_DCACHE_SZ4
#define CFG_DCACHE_SZ 4
#elif defined CONFIG_DCACHE_SZ8
#define CFG_DCACHE_SZ 8
#elif defined CONFIG_DCACHE_SZ16
#define CFG_DCACHE_SZ 16
#elif defined CONFIG_DCACHE_SZ32
#define CFG_DCACHE_SZ 32
#elif defined CONFIG_DCACHE_SZ64
#define CFG_DCACHE_SZ 64
#elif defined CONFIG_DCACHE_SZ128
#define CFG_DCACHE_SZ 128
#elif defined CONFIG_DCACHE_SZ256
#define CFG_DCACHE_SZ 256
#else
#define CFG_DCACHE_SZ 1
#endif

#ifdef CONFIG_DCACHE_LZ32
#define CFG_DLINE_SZ 8
#else
#define CFG_DLINE_SZ 4
#endif

#if defined CONFIG_DCACHE_ALGORND
#define CFG_DCACHE_ALGORND 2
#else
#define CFG_DCACHE_ALGORND 0
#endif

#ifndef CONFIG_DCACHE_LOCK
#define CONFIG_DCACHE_LOCK 0
#endif

#ifndef CONFIG_DCACHE_SNOOP
#define CONFIG_DCACHE_SNOOP 0
#endif

#ifndef CONFIG_DCACHE_SNOOP_SEPTAG
#define CONFIG_DCACHE_SNOOP_SEPTAG 0
#endif

#ifndef CONFIG_DCACHE_SNOOP_SP
#define CONFIG_DCACHE_SNOOP_SP 0
#endif

#ifndef CONFIG_BWMASK
#define CONFIG_BWMASK 0
#endif

#ifndef CONFIG_CACHE_FIXED
#define CONFIG_CACHE_FIXED 0
#endif

#if defined CONFIG_CACHE_64BIT
#define OFG_CBUSW 64
#else
#define OFG_CBUSW 128
#endif

#ifndef CONFIG_DCACHE_LRSTART
#define CONFIG_DCACHE_LRSTART 8F
#endif

#ifndef CONFIG_DCACHE_LRAM
#define CONFIG_DCACHE_LRAM 0
#endif

#if defined CONFIG_DCACHE_LRAM_SZ2
#define CFG_DLRAM_SIZE 2
#elif defined CONFIG_DCACHE_LRAM_SZ4
#define CFG_DLRAM_SIZE 4
#elif defined CONFIG_DCACHE_LRAM_SZ8
#define CFG_DLRAM_SIZE 8
#elif defined CONFIG_DCACHE_LRAM_SZ16
#define CFG_DLRAM_SIZE 16
#elif defined CONFIG_DCACHE_LRAM_SZ32
#define CFG_DLRAM_SIZE 32
#elif defined CONFIG_DCACHE_LRAM_SZ64
#define CFG_DLRAM_SIZE 64
#elif defined CONFIG_DCACHE_LRAM_SZ128
#define CFG_DLRAM_SIZE 128
#elif defined CONFIG_DCACHE_LRAM_SZ256
#define CFG_DLRAM_SIZE 256
#else
#define CFG_DLRAM_SIZE 1
#endif


#ifdef CONFIG_MMU_ENABLE
#define CONFIG_MMUEN 1

#ifdef CONFIG_MMU_SPLIT
#define CONFIG_TLB_TYPE 0
#endif
#ifdef CONFIG_MMU_COMBINED
#define CONFIG_TLB_TYPE 1
#endif

#ifdef CONFIG_MMU_REPARRAY
#define CONFIG_TLB_REP 0
#endif
#ifdef CONFIG_MMU_REPINCREMENT
#define CONFIG_TLB_REP 1
#endif

#ifdef CONFIG_MMU_I2 
#define CONFIG_ITLBNUM 2
#endif
#ifdef CONFIG_MMU_I4 
#define CONFIG_ITLBNUM 4
#endif
#ifdef CONFIG_MMU_I8 
#define CONFIG_ITLBNUM 8
#endif
#ifdef CONFIG_MMU_I16 
#define CONFIG_ITLBNUM 16
#endif
#ifdef CONFIG_MMU_I32
#define CONFIG_ITLBNUM 32
#endif
#ifdef CONFIG_MMU_I64
#define CONFIG_ITLBNUM 64
#endif

#define CONFIG_DTLBNUM 2
#ifdef CONFIG_MMU_D2 
#undef CONFIG_DTLBNUM 
#define CONFIG_DTLBNUM 2
#endif
#ifdef CONFIG_MMU_D4 
#undef CONFIG_DTLBNUM 
#define CONFIG_DTLBNUM 4
#endif
#ifdef CONFIG_MMU_D8 
#undef CONFIG_DTLBNUM 
#define CONFIG_DTLBNUM 8
#endif
#ifdef CONFIG_MMU_D16 
#undef CONFIG_DTLBNUM 
#define CONFIG_DTLBNUM 16
#endif
#ifdef CONFIG_MMU_D32
#undef CONFIG_DTLBNUM 
#define CONFIG_DTLBNUM 32
#endif
#ifdef CONFIG_MMU_D64
#undef CONFIG_DTLBNUM 
#define CONFIG_DTLBNUM 64
#endif

#ifdef CONFIG_MMU_FASTWB
#define CFG_MMU_FASTWB 1
#else
#define CFG_MMU_FASTWB 0
#endif

#else
#define CONFIG_MMUEN 0
#define CONFIG_ITLBNUM 2
#define CONFIG_DTLBNUM 2
#define CONFIG_TLB_TYPE 1
#define CONFIG_TLB_REP 1
#define CFG_MMU_FASTWB 0
#endif

#ifndef CONFIG_DSU_ENABLE
#define CONFIG_DSU_ENABLE 0
#endif

#if defined CONFIG_DSU_ITRACESZ1
#define CFG_DSU_ITB 1
#elif CONFIG_DSU_ITRACESZ2
#define CFG_DSU_ITB 2
#elif CONFIG_DSU_ITRACESZ4
#define CFG_DSU_ITB 4
#elif CONFIG_DSU_ITRACESZ8
#define CFG_DSU_ITB 8
#elif CONFIG_DSU_ITRACESZ16
#define CFG_DSU_ITB 16
#else
#define CFG_DSU_ITB 0
#endif

#if defined CONFIG_DSU_ATRACESZ1
#define CFG_DSU_ATB 1
#elif CONFIG_DSU_ATRACESZ2
#define CFG_DSU_ATB 2
#elif CONFIG_DSU_ATRACESZ4
#define CFG_DSU_ATB 4
#elif CONFIG_DSU_ATRACESZ8
#define CFG_DSU_ATB 8
#elif CONFIG_DSU_ATRACESZ16
#define CFG_DSU_ATB 16
#else
#define CFG_DSU_ATB 0
#endif

#ifndef CONFIG_DSU_ITRACE_2P
#define CONFIG_DSU_ITRACE_2P 0
#endif

#if defined CONFIG_DSU_ASTAT
#define CFG_DSU_AHBPF 2
#elif defined CONFIG_DSU_AFILT
#define CFG_DSU_AHBPF 1
#else
#define CFG_DSU_AHBPF 0
#endif

#if defined CONFIG_DSU_AHBWP2
#define CFG_DSU_AHBWP 2
#elif defined CONFIG_DSU_AHBWP1
#define CFG_DSU_AHBWP 1
#else
#define CFG_DSU_AHBWP 0
#endif

#ifndef CONFIG_LEONFT_EN
#define CONFIG_LEONFT_EN 0
#endif

#if defined CONFIG_IUFT_PAR
#define CONFIG_IUFT_EN 1
#elif defined CONFIG_IUFT_DMR
#define CONFIG_IUFT_EN 2
#elif defined CONFIG_IUFT_BCH
#define CONFIG_IUFT_EN 3
#elif defined CONFIG_IUFT_TMR
#define CONFIG_IUFT_EN 4
#else
#define CONFIG_IUFT_EN 0
#endif
#ifndef CONFIG_RF_ERRINJ
#define CONFIG_RF_ERRINJ 0
#endif

#ifndef CONFIG_FPUFT_EN
#define CONFIG_FPUFT 0
#else
#ifdef CONFIG_FPU_GRFPU
#define CONFIG_FPUFT 2
#else
#define CONFIG_FPUFT 1
#endif
#endif

#ifndef CONFIG_CACHE_FT_EN
#define CONFIG_CACHE_FT_EN 0
#endif
#ifndef CONFIG_CACHE_ERRINJ
#define CONFIG_CACHE_ERRINJ 0
#endif

#ifndef CONFIG_LEON_NETLIST
#define CONFIG_LEON_NETLIST 0
#endif

#ifdef CONFIG_DEBUG_PC32
#define CFG_DEBUG_PC32 0 
#else
#define CFG_DEBUG_PC32 2
#endif
#ifndef CONFIG_IU_DISAS
#define CONFIG_IU_DISAS 0
#endif
#ifndef CONFIG_IU_DISAS_NET
#define CONFIG_IU_DISAS_NET 0
#endif

#ifndef CONFIG_STAT_ENABLE
#define CONFIG_STAT_ENABLE 0
#endif

#ifndef CONFIG_STAT_CNT
#define CONFIG_STAT_CNT 1
#endif

#ifndef CONFIG_STAT_NMAX
#define CONFIG_STAT_NMAX 0
#endif

#if defined CONFIG_DSU_ASTAT
#define CONFIG_STAT_DSUEN 1
#else
#define CONFIG_STAT_DSUEN 0
#endif

#ifndef CONFIG_WRPSR
#define CONFIG_WRPSR 0
#endif

#ifndef CONFIG_NP_ASI
#define CONFIG_NP_ASI 0
#endif

#ifndef CONFIG_ALTWIN
#define CONFIG_ALTWIN 0
#endif

#ifndef CONFIG_REX
#define CONFIG_REX 0
#endif

#ifndef CONFIG_AHB_SPLIT
#define CONFIG_AHB_SPLIT 0
#endif

#ifndef CONFIG_AHB_RROBIN
#define CONFIG_AHB_RROBIN 0
#endif

#ifndef CONFIG_AHB_FPNPEN
#define CONFIG_AHB_FPNPEN 0
#endif

#ifndef CONFIG_AHB_IOADDR
#define CONFIG_AHB_IOADDR FFF
#endif

#ifndef CONFIG_APB_HADDR
#define CONFIG_APB_HADDR 800
#endif

#ifndef CONFIG_AHB_MON
#define CONFIG_AHB_MON 0
#endif

#ifndef CONFIG_AHB_MONERR
#define CONFIG_AHB_MONERR 0
#endif

#ifndef CONFIG_AHB_MONWAR
#define CONFIG_AHB_MONWAR 0
#endif

#ifndef CONFIG_AHB_DTRACE
#define CONFIG_AHB_DTRACE 0
#endif

#ifndef CONFIG_DSU_UART
#define CONFIG_DSU_UART 0
#endif


#ifndef CONFIG_DSU_JTAG
#define CONFIG_DSU_JTAG 0
#endif

#ifndef CONFIG_DSU_ETH
#define CONFIG_DSU_ETH 0
#endif

#ifndef CONFIG_DSU_IPMSB
#define CONFIG_DSU_IPMSB C0A8
#endif

#ifndef CONFIG_DSU_IPLSB
#define CONFIG_DSU_IPLSB 0033
#endif

#ifndef CONFIG_DSU_ETHMSB
#define CONFIG_DSU_ETHMSB 020000
#endif

#ifndef CONFIG_DSU_ETHLSB
#define CONFIG_DSU_ETHLSB 000009
#endif

#if defined CONFIG_DSU_ETHSZ1
#define CFG_DSU_ETHB 1
#elif CONFIG_DSU_ETHSZ2
#define CFG_DSU_ETHB 2
#elif CONFIG_DSU_ETHSZ4
#define CFG_DSU_ETHB 4
#elif CONFIG_DSU_ETHSZ8
#define CFG_DSU_ETHB 8
#elif CONFIG_DSU_ETHSZ16
#define CFG_DSU_ETHB 16
#elif CONFIG_DSU_ETHSZ32
#define CFG_DSU_ETHB 32
#else
#define CFG_DSU_ETHB 1
#endif

#ifndef CONFIG_DSU_ETH_PROG
#define CONFIG_DSU_ETH_PROG 0
#endif

#ifndef CONFIG_DSU_ETH_DIS
#define CONFIG_DSU_ETH_DIS 0
#endif

#ifndef CONFIG_MCTRL_LEON2
#define CONFIG_MCTRL_LEON2 0
#endif

#ifndef CONFIG_MCTRL_SDRAM
#define CONFIG_MCTRL_SDRAM 0
#endif

#ifndef CONFIG_MCTRL_SDRAM_SEPBUS
#define CONFIG_MCTRL_SDRAM_SEPBUS 0
#endif

#ifndef CONFIG_MCTRL_SDRAM_INVCLK
#define CONFIG_MCTRL_SDRAM_INVCLK 0
#endif

#ifndef CONFIG_MCTRL_SDRAM_BUS64
#define CONFIG_MCTRL_SDRAM_BUS64 0
#endif

#ifndef CONFIG_MCTRL_8BIT
#define CONFIG_MCTRL_8BIT 0
#endif

#ifndef CONFIG_MCTRL_16BIT
#define CONFIG_MCTRL_16BIT 0
#endif

#ifndef CONFIG_MCTRL_5CS
#define CONFIG_MCTRL_5CS 0
#endif

#ifndef CONFIG_MCTRL_EDAC
#define CONFIG_MCTRL_EDAC 0
#endif

#ifndef CONFIG_MCTRL_PAGE
#define CONFIG_MCTRL_PAGE 0
#endif

#ifndef CONFIG_MCTRL_PROGPAGE
#define CONFIG_MCTRL_PROGPAGE 0
#endif

#ifndef CONFIG_MCTRLFT
#define CONFIG_MCTRLFT 0
#endif

#ifndef CONFIG_MCTRLFT_SDRAM
#define CONFIG_MCTRLFT_SDRAM 0
#endif

#ifndef CONFIG_MCTRLFT_SDRAM_SEPBUS
#define CONFIG_MCTRLFT_SDRAM_SEPBUS 0
#endif

#ifndef CONFIG_MCTRLFT_SDRAM_INVCLK
#define CONFIG_MCTRLFT_SDRAM_INVCLK 0
#endif

#ifndef CONFIG_MCTRLFT_8BIT
#define CONFIG_MCTRLFT_8BIT 0
#endif

#ifndef CONFIG_MCTRLFT_16BIT
#define CONFIG_MCTRLFT_16BIT 0
#endif

#ifndef CONFIG_MCTRLFT_5CS
#define CONFIG_MCTRLFT_5CS 0
#endif

#ifndef CONFIG_MCTRLFT_EDAC
#define CONFIG_MCTRLFT_EDAC 0
#endif

#ifndef CONFIG_MCTRLFT_EDACPIPE
#define CONFIG_MCTRLFT_EDACPIPE 0
#endif

#ifndef CONFIG_MCTRLFT_RSEDAC
#define CONFIG_MCTRLFT_RSEDAC 0
#endif

#ifndef CONFIG_MCTRLFT_PAGE
#define CONFIG_MCTRLFT_PAGE 0
#endif

#ifndef CONFIG_MCTRLFT_PROGPAGE
#define CONFIG_MCTRLFT_PROGPAGE 0
#endif

#if defined CONFIG_MCTRLFT_ROMASEL0
#define CFG_M_CTRLFT_ROMASEL 0
#elif defined CONFIG_MCTRLFT_ROMASEL1
#define CFG_M_CTRLFT_ROMASEL 1
#elif defined CONFIG_MCTRLFT_ROMASEL2
#define CFG_M_CTRLFT_ROMASEL 2
#elif defined CONFIG_MCTRLFT_ROMASEL3
#define CFG_M_CTRLFT_ROMASEL 3
#elif defined CONFIG_MCTRLFT_ROMASEL4
#define CFG_M_CTRLFT_ROMASEL 4
#elif defined CONFIG_MCTRLFT_ROMASEL5
#define CFG_M_CTRLFT_ROMASEL 5
#elif defined CONFIG_MCTRLFT_ROMASEL6
#define CFG_M_CTRLFT_ROMASEL 6
#elif defined CONFIG_MCTRLFT_ROMASEL7
#define CFG_M_CTRLFT_ROMASEL 7
#elif defined CONFIG_MCTRLFT_ROMASEL8
#define CFG_M_CTRLFT_ROMASEL 8
#elif defined CONFIG_MCTRLFT_ROMASEL9
#define CFG_M_CTRLFT_ROMASEL 9
#elif defined CONFIG_MCTRLFT_ROMASEL10
#define CFG_M_CTRLFT_ROMASEL 10
#elif defined CONFIG_MCTRLFT_ROMASEL11
#define CFG_M_CTRLFT_ROMASEL 11
#elif defined CONFIG_MCTRLFT_ROMASEL12
#define CFG_M_CTRLFT_ROMASEL 12
#elif defined CONFIG_MCTRLFT_ROMASEL13
#define CFG_M_CTRLFT_ROMASEL 13
#elif defined CONFIG_MCTRLFT_ROMASEL14
#define CFG_M_CTRLFT_ROMASEL 14
#elif defined CONFIG_MCTRLFT_ROMASEL15
#define CFG_M_CTRLFT_ROMASEL 15
#elif defined CONFIG_MCTRLFT_ROMASEL16
#define CFG_M_CTRLFT_ROMASEL 16
#elif defined CONFIG_MCTRLFT_ROMASEL17
#define CFG_M_CTRLFT_ROMASEL 17
#elif defined CONFIG_MCTRLFT_ROMASEL18
#define CFG_M_CTRLFT_ROMASEL 18
#elif defined CONFIG_MCTRLFT_ROMASEL19
#define CFG_M_CTRLFT_ROMASEL 19
#elif defined CONFIG_MCTRLFT_ROMASEL20
#define CFG_M_CTRLFT_ROMASEL 20
#elif defined CONFIG_MCTRLFT_ROMASEL21
#define CFG_M_CTRLFT_ROMASEL 21
#elif defined CONFIG_MCTRLFT_ROMASEL22
#define CFG_M_CTRLFT_ROMASEL 22
#elif defined CONFIG_MCTRLFT_ROMASEL23
#define CFG_M_CTRLFT_ROMASEL 23
#elif defined CONFIG_MCTRLFT_ROMASEL24
#define CFG_M_CTRLFT_ROMASEL 24
#elif defined CONFIG_MCTRLFT_ROMASEL25
#define CFG_M_CTRLFT_ROMASEL 25
#elif defined CONFIG_MCTRLFT_ROMASEL26
#define CFG_M_CTRLFT_ROMASEL 26
#elif defined CONFIG_MCTRLFT_ROMASEL27
#define CFG_M_CTRLFT_ROMASEL 27
#elif defined CONFIG_MCTRLFT_ROMASEL28
#define CFG_M_CTRLFT_ROMASEL 28
#else
#define CFG_M_CTRLFT_ROMASEL 0
#endif

#ifndef CONFIG_MCTRLFT_WFB
#define CONFIG_MCTRLFT_WFB 0
#endif

#ifndef CONFIG_MCTRLFT_NETLIST
#define CONFIG_MCTRLFT_NETLIST 0
#endif

#ifndef CONFIG_MCTRLFT_SDRAM_BUS64
#define CONFIG_MCTRLFT_SDRAM_BUS64 0
#endif

#ifndef CONFIG_SDCTRL
#define CONFIG_SDCTRL 0
#endif

#ifndef CONFIG_SDCTRL_SEPBUS
#define CONFIG_SDCTRL_SEPBUS 0
#endif

#ifndef CONFIG_SDCTRL_INVCLK
#define CONFIG_SDCTRL_INVCLK 0
#endif

#ifndef CONFIG_SDCTRL_BUS64
#define CONFIG_SDCTRL_BUS64 0
#endif

#ifndef CONFIG_SDCTRL_PAGE
#define CONFIG_SDCTRL_PAGE 0
#endif

#ifndef CONFIG_SDCTRL_PROGPAGE
#define CONFIG_SDCTRL_PROGPAGE 0
#endif

#ifndef CONFIG_AHBSTAT_ENABLE
#define CONFIG_AHBSTAT_ENABLE  0
#endif

#ifndef CONFIG_AHBSTAT_NFTSLV
#define CONFIG_AHBSTAT_NFTSLV  1
#endif


#ifndef CONFIG_AHBRAM_ENABLE
#define CONFIG_AHBRAM_ENABLE 0
#endif

#ifndef CONFIG_AHBRAM_START
#define CONFIG_AHBRAM_START A00
#endif

#if defined CONFIG_AHBRAM_SZ1
#define CFG_AHBRAMSZ 1
#elif CONFIG_AHBRAM_SZ2
#define CFG_AHBRAMSZ 2
#elif CONFIG_AHBRAM_SZ4
#define CFG_AHBRAMSZ 4
#elif CONFIG_AHBRAM_SZ8
#define CFG_AHBRAMSZ 8
#elif CONFIG_AHBRAM_SZ16
#define CFG_AHBRAMSZ 16
#elif CONFIG_AHBRAM_SZ32
#define CFG_AHBRAMSZ 32
#elif CONFIG_AHBRAM_SZ64
#define CFG_AHBRAMSZ 64
#elif CONFIG_AHBRAM_SZ128
#define CFG_AHBRAMSZ 128
#elif CONFIG_AHBRAM_SZ256
#define CFG_AHBRAMSZ 256
#elif CONFIG_AHBRAM_SZ512
#define CFG_AHBRAMSZ 512
#elif CONFIG_AHBRAM_SZ1024
#define CFG_AHBRAMSZ 1024
#elif CONFIG_AHBRAM_SZ2048
#define CFG_AHBRAMSZ 2048
#elif CONFIG_AHBRAM_SZ4096
#define CFG_AHBRAMSZ 4096
#else
#define CFG_AHBRAMSZ 1
#endif

#ifndef CONFIG_AHBRAM_PIPE
#define CONFIG_AHBRAM_PIPE 0
#endif
#ifndef CONFIG_GRETH_ENABLE
#define CONFIG_GRETH_ENABLE 0
#endif

#ifndef CONFIG_GRETH_GIGA
#define CONFIG_GRETH_GIGA 0
#endif

#if defined CONFIG_GRETH_FIFO4
#define CFG_GRETH_FIFO 4
#elif defined CONFIG_GRETH_FIFO8
#define CFG_GRETH_FIFO 8
#elif defined CONFIG_GRETH_FIFO16
#define CFG_GRETH_FIFO 16
#elif defined CONFIG_GRETH_FIFO32
#define CFG_GRETH_FIFO 32
#elif defined CONFIG_GRETH_FIFO64
#define CFG_GRETH_FIFO 64
#else
#define CFG_GRETH_FIFO 8
#endif

#ifndef CONFIG_GRETH_FT
#define CONFIG_GRETH_FT 0
#endif

#ifndef CONFIG_GRETH_EDCLFT
#define CONFIG_GRETH_EDCLFT 0
#endif

#ifndef CONFIG_GRETH_SGMII_MODE
#define CONFIG_GRETH_SGMII_MODE 0
#endif
#ifndef CONFIG_CAN_ENABLE
#define CONFIG_CAN_ENABLE 0
#endif

#ifndef CONFIG_CAN_NUM
#define CONFIG_CAN_NUM 1
#endif

#ifndef CONFIG_CANIO
#define CONFIG_CANIO 0
#endif

#ifndef CONFIG_CANIRQ
#define CONFIG_CANIRQ 0
#endif

#ifndef CONFIG_CANSEPIRQ
#define CONFIG_CANSEPIRQ 0
#endif

#ifndef CONFIG_CAN_SYNCRST
#define CONFIG_CAN_SYNCRST 0
#endif

#ifndef CONFIG_CAN_FT
#define CONFIG_CAN_FT 0
#endif

#ifndef CONFIG_SPW_ENABLE
#define CONFIG_SPW_ENABLE 0
#endif

#ifndef CONFIG_SPW_NUM
#define CONFIG_SPW_NUM 1
#endif

#if defined CONFIG_SPW_AHBFIFO4
#define CONFIG_SPW_AHBFIFO 4
#elif defined CONFIG_SPW_AHBFIFO8
#define CONFIG_SPW_AHBFIFO 8
#elif defined CONFIG_SPW_AHBFIFO16
#define CONFIG_SPW_AHBFIFO 16
#elif defined CONFIG_SPW_AHBFIFO32
#define CONFIG_SPW_AHBFIFO 32
#elif defined CONFIG_SPW_AHBFIFO64
#define CONFIG_SPW_AHBFIFO 64
#else
#define CONFIG_SPW_AHBFIFO 4
#endif

#if defined CONFIG_SPW_RXFIFO16
#define CONFIG_SPW_RXFIFO 16
#elif defined CONFIG_SPW_RXFIFO32
#define CONFIG_SPW_RXFIFO 32
#elif defined CONFIG_SPW_RXFIFO64
#define CONFIG_SPW_RXFIFO 64
#else
#define CONFIG_SPW_RXFIFO 16
#endif

#ifndef CONFIG_SPW_RMAP
#define CONFIG_SPW_RMAP 0
#endif

#if defined CONFIG_SPW_RMAPBUF2
#define CONFIG_SPW_RMAPBUF 2
#elif defined CONFIG_SPW_RMAPBUF4
#define CONFIG_SPW_RMAPBUF 4
#elif defined CONFIG_SPW_RMAPBUF6
#define CONFIG_SPW_RMAPBUF 6
#elif defined CONFIG_SPW_RMAPBUF8
#define CONFIG_SPW_RMAPBUF 8
#else
#define CONFIG_SPW_RMAPBUF 4
#endif

#ifndef CONFIG_SPW_RMAPCRC
#define CONFIG_SPW_RMAPCRC 0
#endif

#ifndef CONFIG_SPW_RXUNAL
#define CONFIG_SPW_RXUNAL 0
#endif

#ifndef CONFIG_SPW_NETLIST
#define CONFIG_SPW_NETLIST 0
#endif

#ifndef CONFIG_SPW_FT
#define CONFIG_SPW_FT 0
#endif

#if defined CONFIG_SPW_GRSPW1
#define CONFIG_SPW_GRSPW 1
#else
#define CONFIG_SPW_GRSPW 2
#endif

#ifndef CONFIG_SPW_DMACHAN
#define CONFIG_SPW_DMACHAN 1
#endif

#ifndef CONFIG_SPW_PORTS
#define CONFIG_SPW_PORTS 1
#endif

#if defined CONFIG_SPW_RX_SDR
#define CONFIG_SPW_INPUT 2
#elif defined CONFIG_SPW_RX_DDR
#define CONFIG_SPW_INPUT 3
#elif defined CONFIG_SPW_RX_PAD
#define CONFIG_SPW_INPUT 4
#elif defined CONFIG_SPW_RX_XOR
#define CONFIG_SPW_INPUT 0
#elif defined CONFIG_SPW_RX_AFLEX
#define CONFIG_SPW_INPUT 1
#else
#define CONFIG_SPW_INPUT 2
#endif

#if defined CONFIG_SPW_TX_SDR
#define CONFIG_SPW_OUTPUT 0
#elif defined CONFIG_SPW_TX_DDR
#define CONFIG_SPW_OUTPUT 1
#elif defined CONFIG_SPW_TX_AFLEX
#define CONFIG_SPW_OUTPUT 2
#else
#define CONFIG_SPW_OUTPUT 0
#endif

#ifndef CONFIG_SPW_RTSAME
#define CONFIG_SPW_RTSAME 0
#endif
#if defined CONFIG_PCI_SIMPLE_TARGET
#define CFG_PCITYPE 1
#elif defined CONFIG_PCI_MASTER_TARGET_DMA
#define CFG_PCITYPE 3
#elif defined CONFIG_PCI_MASTER_TARGET
#define CFG_PCITYPE 2
#else
#define CFG_PCITYPE 0
#endif

#ifndef CONFIG_PCI_VENDORID
#define CONFIG_PCI_VENDORID 0
#endif

#ifndef CONFIG_PCI_DEVICEID
#define CONFIG_PCI_DEVICEID 0
#endif

#ifndef CONFIG_PCI_REVID
#define CONFIG_PCI_REVID 0
#endif

#if defined CONFIG_PCI_FIFO0
#define CFG_PCIFIFO 8
#define CFG_PCI_ENFIFO 0
#elif defined CONFIG_PCI_FIFO16
#define CFG_PCIFIFO 16
#elif defined CONFIG_PCI_FIFO32
#define CFG_PCIFIFO 32
#elif defined CONFIG_PCI_FIFO64
#define CFG_PCIFIFO 64
#elif defined CONFIG_PCI_FIFO128
#define CFG_PCIFIFO 128
#elif defined CONFIG_PCI_FIFO256
#define CFG_PCIFIFO 256
#else
#define CFG_PCIFIFO 8
#endif

#ifndef CFG_PCI_ENFIFO
#define CFG_PCI_ENFIFO 1
#endif

#if defined CONFIG_GRPCI2_MASTER
#define CFG_GRPCI2_MASTEREN 1
#else
#define CFG_GRPCI2_MASTEREN 0
#endif

#if defined CONFIG_GRPCI2_TARGET
#define CFG_GRPCI2_TARGETEN 1
#else
#define CFG_GRPCI2_TARGETEN 0
#endif

#if defined CONFIG_GRPCI2_DMA
#define CFG_GRPCI2_DMAEN 1
#else
#define CFG_GRPCI2_DMAEN 0
#endif

#ifndef CONFIG_GRPCI2_VENDORID
#define CONFIG_GRPCI2_VENDORID 0
#endif

#ifndef CONFIG_GRPCI2_DEVICEID
#define CONFIG_GRPCI2_DEVICEID 0
#endif

#ifndef CONFIG_GRPCI2_CLASS
#define CONFIG_GRPCI2_CLASS 0
#endif

#ifndef CONFIG_GRPCI2_REVID
#define CONFIG_GRPCI2_REVID 0
#endif

#ifndef CONFIG_GRPCI2_CAPPOINT
#define CONFIG_GRPCI2_CAPPOINT 40
#endif

#ifndef CONFIG_GRPCI2_NEXTCAPPOINT
#define CONFIG_GRPCI2_NEXTCAPPOINT 0
#endif

#ifndef CONFIG_GRPCI2_BAR0
#define CONFIG_GRPCI2_BAR0 0
#endif
#ifndef CONFIG_GRPCI2_BAR1
#define CONFIG_GRPCI2_BAR1 0
#endif
#ifndef CONFIG_GRPCI2_BAR2
#define CONFIG_GRPCI2_BAR2 0
#endif
#ifndef CONFIG_GRPCI2_BAR3
#define CONFIG_GRPCI2_BAR3 0
#endif
#ifndef CONFIG_GRPCI2_BAR4
#define CONFIG_GRPCI2_BAR4 0
#endif
#ifndef CONFIG_GRPCI2_BAR5
#define CONFIG_GRPCI2_BAR5 0
#endif

#if defined CONFIG_GRPCI2_FIFO8
#define CFG_GRPCI2_FIFO 3
#elif defined CONFIG_GRPCI2_FIFO16
#define CFG_GRPCI2_FIFO 4
#elif defined CONFIG_GRPCI2_FIFO32
#define CFG_GRPCI2_FIFO 5
#elif defined CONFIG_GRPCI2_FIFO64
#define CFG_GRPCI2_FIFO 6
#elif defined CONFIG_GRPCI2_FIFO128
#define CFG_GRPCI2_FIFO 7
#else
#define CFG_GRPCI2_FIFO 3
#endif

#if defined CONFIG_GRPCI2_FIFOCNT1
#define CFG_GRPCI2_FIFOCNT 1
#elif defined CONFIG_GRPCI2_FIFOCNT2
#define CFG_GRPCI2_FIFOCNT 2
#elif defined CONFIG_GRPCI2_FIFOCNT3
#define CFG_GRPCI2_FIFOCNT 3
#elif defined CONFIG_GRPCI2_FIFOCNT4
#define CFG_GRPCI2_FIFOCNT 4
#else
#define CFG_GRPCI2_FIFOCNT 2
#endif

#if defined CONFIG_GRPCI2_ENDIAN
#define CFG_GRPCI2_LENDIAN 1
#else
#define CFG_GRPCI2_LENDIAN 0
#endif

#if defined CONFIG_GRPCI2_DINT
#define CFG_GRPCI2_DINT 1
#else
#define CFG_GRPCI2_DINT 0
#endif
#ifndef CONFIG_GRPCI2_DINTMASK
#define CONFIG_GRPCI2_DINTMASK 0
#endif

#if defined CONFIG_GRPCI2_HINT
#define CFG_GRPCI2_HINT 1
#else
#define CFG_GRPCI2_HINT 0
#endif
#ifndef CONFIG_GRPCI2_HINTMASK
#define CONFIG_GRPCI2_HINTMASK 0
#endif

#if defined CONFIG_GRPCI2_TRACE0
#define CFG_GRPCI2_TRACEDEPTH 0
#elif defined CONFIG_GRPCI2_TRACE256
#define CFG_GRPCI2_TRACEDEPTH 256
#elif defined CONFIG_GRPCI2_TRACE512
#define CFG_GRPCI2_TRACEDEPTH 512
#elif defined CONFIG_GRPCI2_TRACE1024
#define CFG_GRPCI2_TRACEDEPTH 1024
#elif defined CONFIG_GRPCI2_TRACE2048
#define CFG_GRPCI2_TRACEDEPTH 2014
#elif defined CONFIG_GRPCI2_TRACE4096
#define CFG_GRPCI2_TRACEDEPTH 4096
#else
#define CFG_GRPCI2_TRACEDEPTH 0
#endif

#ifndef CONFIG_GRPCI2_TRACEAPB
#define CONFIG_GRPCI2_TRACEAPB 0
#endif

#if defined CONFIG_GRPCI2_BYPASS
#define CFG_GRPCI2_INBYPASS 1
#else
#define CFG_GRPCI2_INBYPASS 0
#endif

#ifndef CONFIG_GRPCI2_EXTCFG
#define CONFIG_GRPCI2_EXTCFG 0
#endif

#ifndef CONFIG_PCI_ARBITER_APB
#define CONFIG_PCI_ARBITER_APB 0
#endif

#ifndef CONFIG_PCI_ARBITER
#define CONFIG_PCI_ARBITER 0
#endif

#ifndef CONFIG_PCI_ARBITER_NREQ
#define CONFIG_PCI_ARBITER_NREQ 4
#endif

#ifndef CONFIG_PCI_TRACE
#define CONFIG_PCI_TRACE 0
#endif

#if defined CONFIG_PCI_TRACE512
#define CFG_PCI_TRACEBUF 512
#elif defined CONFIG_PCI_TRACE1024
#define CFG_PCI_TRACEBUF 1024
#elif defined CONFIG_PCI_TRACE2048
#define CFG_PCI_TRACEBUF 2048
#elif defined CONFIG_PCI_TRACE4096
#define CFG_PCI_TRACEBUF 4096
#else
#define CFG_PCI_TRACEBUF 256
#endif


#ifndef CONFIG_UART1_ENABLE
#define CONFIG_UART1_ENABLE 0
#endif

#if defined CONFIG_UA1_FIFO1
#define CFG_UA1_FIFO 1
#elif defined CONFIG_UA1_FIFO2
#define CFG_UA1_FIFO 2
#elif defined CONFIG_UA1_FIFO4
#define CFG_UA1_FIFO 4
#elif defined CONFIG_UA1_FIFO8
#define CFG_UA1_FIFO 8
#elif defined CONFIG_UA1_FIFO16
#define CFG_UA1_FIFO 16
#elif defined CONFIG_UA1_FIFO32
#define CFG_UA1_FIFO 32
#else
#define CFG_UA1_FIFO 1
#endif

#ifndef CONFIG_UART2_ENABLE
#define CONFIG_UART2_ENABLE 0
#endif

#if defined CONFIG_UA2_FIFO1
#define CFG_UA2_FIFO 1
#elif defined CONFIG_UA2_FIFO2
#define CFG_UA2_FIFO 2
#elif defined CONFIG_UA2_FIFO4
#define CFG_UA2_FIFO 4
#elif defined CONFIG_UA2_FIFO8
#define CFG_UA2_FIFO 8
#elif defined CONFIG_UA2_FIFO16
#define CFG_UA2_FIFO 16
#elif defined CONFIG_UA2_FIFO32
#define CFG_UA2_FIFO 32
#else
#define CFG_UA2_FIFO 1
#endif

#ifndef CONFIG_IRQ3_ENABLE
#define CONFIG_IRQ3_ENABLE 0
#endif
#ifndef CONFIG_IRQ3_NSEC
#define CONFIG_IRQ3_NSEC 0
#endif
#ifndef CONFIG_GPT_ENABLE
#define CONFIG_GPT_ENABLE 0
#endif

#ifndef CONFIG_GPT_NTIM
#define CONFIG_GPT_NTIM 1
#endif

#ifndef CONFIG_GPT_SW
#define CONFIG_GPT_SW 8
#endif

#ifndef CONFIG_GPT_TW
#define CONFIG_GPT_TW 8
#endif

#ifndef CONFIG_GPT_IRQ
#define CONFIG_GPT_IRQ 8
#endif

#ifndef CONFIG_GPT_SEPIRQ
#define CONFIG_GPT_SEPIRQ 0
#endif
#ifndef CONFIG_GPT_ENABLE
#define CONFIG_GPT_ENABLE 0
#endif

#ifndef CONFIG_GPT_NTIM
#define CONFIG_GPT_NTIM 1
#endif

#ifndef CONFIG_GPT_SW
#define CONFIG_GPT_SW 8
#endif

#ifndef CONFIG_GPT_TW
#define CONFIG_GPT_TW 8
#endif

#ifndef CONFIG_GPT_IRQ
#define CONFIG_GPT_IRQ 8
#endif

#ifndef CONFIG_GPT_SEPIRQ
#define CONFIG_GPT_SEPIRQ 0
#endif

#ifndef CONFIG_GPT_WDOGEN
#define CONFIG_GPT_WDOGEN 0
#endif

#ifndef CONFIG_GPT_WDOG
#define CONFIG_GPT_WDOG 0
#endif

#ifndef CONFIG_GRGPIO_ENABLE
#define CONFIG_GRGPIO_ENABLE 0
#endif
#ifndef CONFIG_GRGPIO_IMASK
#define CONFIG_GRGPIO_IMASK 0000
#endif
#ifndef CONFIG_GRGPIO_WIDTH
#define CONFIG_GRGPIO_WIDTH 1
#endif

#ifndef CONFIG_PARTIAL
#define CONFIG_PARTIAL 0
#endif

#ifndef CONFIG_CRC
#define CONFIG_CRC 0
#endif

#ifndef CONFIG_EDAC
#define CONFIG_EDAC 0
#endif

#ifndef CONFIG_BLOCK
#define CONFIG_BLOCK 100
#endif

#ifndef CONFIG_DCM_FIFO
#define CONFIG_DCM_FIFO 0
#endif

#ifndef CONFIG_FIFO_DEPTH
#define CONFIG_FIFO_DEPTH 9
#endif

#if defined CONFIG_DPR_FIFO64
#define CFG_DPRFIFO 6
#elif defined CONFIG_DPR_FIFO128
#define CFG_DPRFIFO 7
#elif defined CONFIG_DPR_FIFO256
#define CFG_DPRFIFO 8
#else
#define CFG_DPRFIFO 9
#endif



#ifndef CONFIG_DEBUG_UART
#define CONFIG_DEBUG_UART 0
#endif