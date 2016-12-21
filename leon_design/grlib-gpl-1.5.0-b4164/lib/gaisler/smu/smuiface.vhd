-----------------------------------------------------------------------------   
-- Entity:      smuiface
-- File:        smuiface.vhd
-- Author:      Bar Elharar
-- Description: SMU components and types
-- Edited:		22nd Dec., 2014 (Bar)
------------------------------------------------------------------------------  

library ieee;
use ieee.std_logic_1164.all;
USE ieee.numeric_std.ALL;

library grlib;
use grlib.amba.all; -- ahb interfaces
use grlib.stdlib.all; -- log2()

library gaisler;
use gaisler.mmuconfig.all; -- context size
use gaisler.mmuiface.all; -- mmu interface

package smuiface is
	constant SMU_REQ_OFFSET_WIDTH	: integer := 5;
	constant SMU_DATA_FIELD_BYTES : positive := 2**SMU_REQ_OFFSET_WIDTH;
	constant SMU_DATA_FIELD_WIDTH : positive := 8*SMU_DATA_FIELD_BYTES;
	subtype quanta is std_logic_vector(SMU_DATA_FIELD_WIDTH-1 downto 0);
	
	
	constant SMU_ADDRESS_WIDTH			: natural	:= 32; -- bits
	constant SMU_VIRT_ADDR_WIDTH		: natural	:= SMU_ADDRESS_WIDTH; -- bits
	
	subtype physical_address_type is std_logic_vector(SMU_ADDRESS_WIDTH-1 downto 0);
	subtype virtual_address_type is std_logic_vector(SMU_VIRT_ADDR_WIDTH-1 downto 0);
	
	constant SMU_MAX_SUPPORTED_VA_LOG	: natural	:= 30;
	constant SMU_MAX_SUPPORTED_VA		: virtual_address_type	:= x"40000000"; --1GB
	subtype extended_asi_type is std_logic_vector(7 downto 0);
	
	type smu_memory_ic_in_type is record
		 address          	: physical_address_type;			-- memory physical address
		 burst            	: std_ulogic;						-- burst request
		 req              	: std_ulogic;						-- memory cycle request
		 su               	: std_ulogic;						-- supervisor address space
		 flush            	: std_ulogic;						-- flush in progress
		 ---- SeM ----
		 vaddr				: virtual_address_type;				-- virtual address
		 ctx				: std_logic_vector(M_CTX_SZ-1 downto 0); -- process identifier
		 tmode				: std_ulogic;						-- Trusted mode
	end record;
	constant SMU_MEMORY_IC_IN_RESET_CONST : smu_memory_ic_in_type := (
		address => (others => '0'),
		burst => '0',
		req => '0',
		su => '0',
		flush => '0',
		vaddr => (others => '0'),
		ctx => (others => '0'),
		tmode => '0'
	);

	type smu_memory_ic_out_type is record
		data				: quanta;		-- memory data
		ready				: std_ulogic;	-- cycle ready
		grant				: std_ulogic;	-- 
		retry				: std_ulogic;	-- 
		mexc				: std_ulogic;	-- memory exception
		cache				: std_ulogic;	-- cacheable data
		---- SeM ----
		auth				: std_ulogic;	-- Authentication flag
	end record;
	constant SMU_MEMORY_IC_OUT_RESET_CONST : smu_memory_ic_out_type := (
		data => (others => '0'),
		ready => '0',
		grant => '0',
		retry => '0',
		mexc => '0',
		cache => '0',
		auth => '0'
	);

	type smu_memory_dc_in_type is record
		 address			: physical_address_type; 	-- memory physical address
		 data				: quanta;
		 asi				: extended_asi_type;		-- ASI for load/store -- extended to 8 bits for SeM
		 size				: std_logic_vector(1 downto 0);
		 burst				: std_ulogic;
		 read				: std_ulogic;
		 req				: std_ulogic;
		 lock				: std_ulogic;
		 cache				: std_ulogic;
		 ---- SeM ----
		 vaddr				: virtual_address_type;	-- virtual address
		 ctx				: std_logic_vector(M_CTX_SZ-1 downto 0); -- process identifier
		 tmode				: std_ulogic;						-- Trusted mode
	end record;
	constant SMU_MEMORY_DC_IN_RESET_CONST : smu_memory_dc_in_type := (
		address => (others => '0'),
		data => (others => '0'),
		asi => (others => '0'),
		size => (others => '0'),
		burst => '0',
		read => '0',
		req => '0',
		lock => '0',
		cache => '0',
		vaddr => (others => '0'),
		ctx => (others => '0'),
		tmode => '0'
	);

	type smu_memory_dc_out_type is record
		 data				: quanta;				-- memory data
		 ready				: std_ulogic;			-- cycle ready
		 grant				: std_ulogic;
		 retry				: std_ulogic;
		 mexc				: std_ulogic;			-- memory exception
		 werr				: std_ulogic;			-- memory write error (maybe for atomic swap)
		 cache				: std_ulogic;			-- cacheable data
		 ba					: std_ulogic;			-- bus active (used for snooping)
		 bg					: std_ulogic;			-- bus grant  (used for snooping)
		 ---- SeM ----
		 auth				: std_ulogic;			-- Authentication flag
	end record;
	constant SMU_MEMORY_DC_OUT_RESET_CONST : smu_memory_dc_out_type := (
		data => (others => '0'),
		ready => '0',
		grant => '0',
		retry => '0',
		mexc => '0',
		werr => '0',
		cache => '0',
		ba => '0',
		bg => '0',
		auth => '0'
	);

	component smu_mmu_acache
		generic (
			hindex    :     integer range 0 to NAHBMST-1 := 0;
			ilinesize :     integer range 4 to 8         := 4;
			dlinesize :     integer range 4 to 8         := 4;
			cached    :     integer                      := 0;
			clk2x     :     integer                      := 0;
			scantest  :     integer                      := 0
		);
		port (
			rst			: in  std_logic;
			clk, sclk	: in  std_logic;
			mcii		: in  smu_memory_ic_in_type;
			mcio		: out smu_memory_ic_out_type;
			mcdi		: in  smu_memory_dc_in_type;
			mcdo		: out smu_memory_dc_out_type;
			mcmmi		: in  memory_mm_in_type;
			mcmmo		: out memory_mm_out_type;
			ahbi		: in  ahb_mst_in_type;
			ahbo		: out ahb_mst_out_type;
			ahbso		: in  ahb_slv_out_vector;
			---- SeM ----
			-- mmulci		: out mmudc_in_type;		-- mmu outbound signal for future landlord cache
			-- mmulco		: in  mmudc_out_type;		-- mmu inbound signal for future landlord cache
			-------------
			hclken		: in  std_ulogic
		);
	end component;
	
	-- Alternate address space identifiers --
	constant ASI_SMU_TO_TRUSTED_MODE :	extended_asi_type := x"81";
	constant ASI_SMU_TO_UNTRUSTED_MODE :	extended_asi_type := x"82";
	constant ASI_SMU_APPEND_PID :	extended_asi_type := x"83";
	constant ASI_SMU_REMOVE_PID :	extended_asi_type := x"84";
	constant ASI_SMU_LL_ALLOC	:	extended_asi_type := x"85";
	constant ASI_SMU_LL_FREE	:	extended_asi_type := x"86";
	
end;	-- end of package smuiface
