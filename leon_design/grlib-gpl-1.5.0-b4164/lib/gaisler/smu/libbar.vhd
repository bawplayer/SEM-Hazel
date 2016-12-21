-----------------------------------------------------------------------------   
-- Entity:      libbar
-- File:        libbar.vhd
-- Author:      Bar Elharar
-- Description: SMU functions, components and types:
--				FIFO, Queue, noise generator, LRU, bidirectional LRU, arbiter
-- Edited:		12th Nov., 2014 (Bar)
------------------------------------------------------------------------------  

library ieee;
use ieee.std_logic_1164.all;
USE ieee.numeric_std.ALL;

package libbar is

	component bar_fifo
		generic (
			type elem_type;
			ELEM_RESET_CONST : elem_type;
			fifo_size	: positive
		);
		port (
			clk		: in std_ulogic;
			rstn	: in std_ulogic;
			ini		: in elem_type;
			push	: in std_ulogic;
			pop		: in std_ulogic;
			outi	: out elem_type;
			full, empty	: out std_ulogic
		);
	end component; -- entity of bar_fifo
	
	constant BAR_DEF_LEN_WIDTH	: natural := 8;
	
	component bar_queue
		generic (
			type elem_type;
			ELEM_RESET_CONST : elem_type;
			queue_max_size	: positive;
			length_in_width	: natural := BAR_DEF_LEN_WIDTH;
			multiplicand	: positive := 1
		);
		port (
			clk		: in std_ulogic;
			rstn	: in std_ulogic;
			stalln	: in std_ulogic; -- stall on low
			multiplier	: in std_logic_vector(length_in_width-1 downto 0); -- unsigned multiplier
			
			ini		: in elem_type;
			valid_in	: in std_ulogic;
			outi	: out elem_type;
			valid_out : out std_ulogic;
			empty_out	: out std_ulogic	-- no valid entries
		);
	end component; -- entity of queue
	
	component noise_gen
		Generic (
			W : integer := 16;					-- LFSR scaleable from 24 down to 4 bits
			V : integer := 18;					-- LFSR for non uniform clocking scalable from 24 down to 18 bit
			g_type : integer := 0;			-- gausian distribution type, 0 = unimodal, 1 = bimodal, from g_noise_out
			u_type : integer := 1			-- uniform distribution type, 0 = uniform, 1 =  ave-uniform, from u_noise_out
		);
		Port ( 
			clk 			: 		in  STD_LOGIC;
			n_reset 		: 		in  STD_LOGIC;
			enable			: 		in  STD_LOGIC;
			g_noise_out 	:		out STD_LOGIC_VECTOR (W-1 downto 0);	-- port for bimodal/unimodal gaussian distributions
			u_noise_out 	: 		out  STD_LOGIC_VECTOR (W-1 downto 0)	-- port for uniform/ave-uniform distributions
		);
	end component;
	
	type bar_lru_config_type is record
		random_eviction : std_ulogic;
		multiplier		: std_logic_vector(BAR_DEF_LEN_WIDTH-1 downto 0); -- unsigned multiplier
	end record;
	
	constant BAR_LRU_CONFIG_RESET_CONST : bar_lru_config_type := (
		random_eviction => '0',
		multiplier => (others => '0')
	);
	
	component bar_lru
		generic (
			type elem_type;
			ELEM_RESET_CONST : elem_type;
			lru_max_size	: positive;
			delete_on_load	: boolean;
			multiplicand	: positive := 1 -- logarithmic (sll steps)
		);
		port (
			clk			: in std_ulogic;
			rstn		: in std_ulogic;
			config_in	: in bar_lru_config_type; -- currently ignored
			
			ini			: in elem_type;
			store		: in std_ulogic;
			load		: in std_ulogic;
			
			outi		: out elem_type;
			hit_out		: out std_ulogic;
			evicted_out : out elem_type
		);
	end component; -- entity of bar_lru
	
	component bar_lru_cache
		generic (
			type lru_data_type;
			LRU_DATA_RESET_CONST : lru_data_type;
			type lru_key_a_type;
			LRU_KEY_A_RESET_CONST : lru_key_a_type;
			type lru_key_b_type;
			LRU_KEY_B_RESET_CONST : lru_key_b_type;
			lru_max_size	:	positive;
			multiplicand	:	positive := 1  -- logarithmic (sll steps)
		);
		port (
			clk				: in	std_ulogic;
			rstn			: in	std_ulogic;
			config_in		: in	bar_lru_config_type; -- currently ignored
			
			read_comm		: in	std_ulogic;
			load_key_a_in	: in	lru_key_a_type;
			load_key_b_in	: in	lru_key_b_type;
			load_data_out	: out	lru_data_type;
			hit_out			: out	std_ulogic;
			
			write_comm		: in	std_ulogic;
			store_key_a_in	: in	lru_key_a_type;
			store_key_b_in	: in	lru_key_b_type;
			store_data_in	: in	lru_data_type;
			
			evicted_key_a_out: out	lru_key_a_type;
			evicted_key_b_out: out	lru_key_b_type;
			evicted_data_out: out	lru_data_type;
			eviction_flag	: out	std_ulogic;
			
			evict_in		: in	std_ulogic; -- evict only dirty cells, don't remove from LRU
			flush_in		: in	std_ulogic; -- remove cells from LRU
			busy_out		: out	std_ulogic -- ongoing forced eviction or flush
		);
	end component; -- entity of bar_lru_cache
	
	type bar_arbiter_config_type is record
		multiplier		: std_logic_vector(BAR_DEF_LEN_WIDTH-1 downto 0); -- unsigned multiplier
	end record;
	constant BAR_ARBITER_CONFIG_RESET_TYPE : bar_arbiter_config_type := (
		multiplier => (others => '0')
	);
	
	component bar_arbiter
		generic (
			type head_type; -- identifier
			HEAD_RESET_CONST : head_type;
			type elem_type;
			ELEM_RESET_CONST : elem_type;
			arbiter_max_size	: positive;
			min_headroom 	: natural;
			multiplicand	: positive := 1 -- logarithmic (sll steps)
		);
		port (
			clk			: in	std_ulogic;
			rstn		: in	std_ulogic;
			config_in	: in	bar_arbiter_config_type; -- currently ignored
			
			full_th_out	: out	std_ulogic; -- threshold full
			empty_out	: out	std_ulogic;
			
			instruction_in: in	std_logic_vector(1 downto 0); -- 1-write, 2-read, 3-read&delete
			header_in	: in	head_type;
			data_in		: in	elem_type;
			data_out	: out	elem_type;
			load_valid_out: out	std_ulogic;
			store_hit	: out	std_ulogic -- true when former request with the same header is already found
		);
	end component; -- entity of bar_arbiter
	
	function f_round_robin_vector (vec, fav: std_logic_vector; prev: integer) return integer;
	function f_round_robin_vector (vec: std_logic_vector; prev: integer) return integer;
	function f_calculate_component_effective_length (multiplier : std_logic_vector;
		max_len, multiplicand : positive) return natural;
end;	-- end of package libsmu

package body libbar is
	-- fav argument is for favourite, otherwise place: (others => '0')
	function f_round_robin_vector (vec, fav: std_logic_vector; prev: integer)
	return integer is
		variable res_low, res_high : integer;
		variable v: std_logic_vector(vec'range);
		variable n: integer;
	begin
		res_low := 0;
		res_high := 0;
		n := prev + 1;
		v := vec and fav;
		if (v = (v'range => '0')) then
			v := vec;
		end if;
		
		for i in v'range loop
			if v(i) = '1' then
				if (i < n) and (res_low = 0) then
					res_low := i;
				elsif (i >= n) and (res_high = 0) then
					res_high := i;
				end if;
			end if;
		end loop;
		if (res_high = 0) then
			res_high := res_low;
		end if;
		return res_high;
	end; -- round_robin vector function
	
	function f_round_robin_vector (vec: std_logic_vector; prev: integer)
	return integer is
	begin
		return f_round_robin_vector(vec, (vec'range => '0'), prev);
	end; -- round_robin vector function
	
	function f_calculate_component_effective_length (multiplier : std_logic_vector;
		max_len, multiplicand : positive) return natural is
		variable prod : natural;
	begin
		prod := to_integer(unsigned(multiplier sll multiplicand));
		if (prod = 0) then
			prod := max_len;
		end if;
		return(minimum(max_len, prod));
	end; -- function length
end libbar;