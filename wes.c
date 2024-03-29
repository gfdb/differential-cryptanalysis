/**   wes.c
 * 
 * Date:    10 November 2022
 * Author:  IP, Concordia
 * License: Public domain
 * version: 0.1
 *
 * Course:  SOEN 321
 *
 * Description: Weak Encryption Scheme (WES) cipher. Reference implementation.
 *              Designed for Concordia SOEN 321 course. WES is a Feistel cipher
 *              intentionally made vulnerable to differential cryptanalysis. 
 *              
 * 
 * Compile: run `make` OR `gcc -O3 -DDEBUG wes.c -o wes`
 * Usage:   ./wes PLAINTEXT_HEX
 * Example: ./wes 72657475706D6F43
 *
 * Example output with debug enabled:
 * $ ./wes 72657475706D6F43
 *    ** Plaintext: 72657475706D6F43    Master key: 4E9C7AC90BCA3B98
 *    input to r1:  72657475  706D6F43     rkey = 3A7A3B7A
 *    input to r2:  706D6F43  2BF5CAF4     rkey = 4E9C7AC9
 *    input to r3:  2BF5CAF4  45B078CC     rkey = A6C91854
 *    input to r4:  45B078CC  562E187F     rkey = 0BCA3B98
 *    outp from r4:  55C4D482  562E187F --
 *   Ciphertext: 55C4D482562E187F
 *
 *
 * Example output with debug disabled:
 * $ ./wes 72657475706D6F43
 *    55C4D482562E187F
 *
 *
 * Note: Master key is set in the code, line 57 (i.e. changing it requires recompilation)
 *
 * Files: 		
 * 				- wes.c     : This file
 *              - Makefile  : For compilation 
 *
 * Platform: MacOS 13.0.1 (M1)
 * Compiler: Apple clang version 14.0.0 (clang-1400.0.29.202)
 *
 * */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h> /* for `false` symbol */

#ifdef DEBUG
#define DEBUG_PRINT(...) do{ fprintf( stderr, __VA_ARGS__ ); } while( false )
#else
#define DEBUG_PRINT(...) do{ } while ( false )
#endif

#ifndef MASTERKEY
#define MASTERKEY 0x4E9C7AC90BCA3B98
#endif

/* WES */

// Key scheduling tables 
int k1p[32] = {1,3,5,7,9,11,13,15,17,19,21,23,25,27,29,31,33,35,37,39,41,43,45,47,49,51,53,55,57,59,61,63};      // Odd bits
int k2p[32] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32};          // Left half
int k3p[32] = {2,4,6,8,10,12,14,16,18,20,22,24,26,28,30,32,34,36,38,40,42,44,46,48,50,52,54,56,58,60,62,64};     // Even bits
int k4p[32] = {33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,64}; // Right half

// S-box Table
int sbox[8][16] = {
	/* 1 */
	{ 6, 12, 3, 8, 14, 5, 11, 1, 2, 4, 13, 7, 0, 10, 15, 9}, 
	/* 2 */
	{ 10, 14, 15, 11, 6, 8, 3, 13, 7, 9, 2, 12, 1, 0, 4, 5},
	/* 3 */
	{ 10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8}, 
	/* 4 */
	{ 15, 9, 7, 0, 10, 13, 2, 4, 3, 6, 12, 5, 1, 8, 14, 11},
	/* 5 */
	{ 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9},
	/* 6 */
	{ 12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11},
	/* 7 */
	{ 4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1},
	/* 8 */
	{ 13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7}
};

// Permutation Table
int per[32]
	= { 16,  7, 20, 21, 
		29, 12, 28, 17,
		 1, 15, 23, 26,
		 5, 18, 31, 10, 
		 2,  8, 24, 14, 
		32, 27,  3,  9, 
		19, 13, 30,  6, 
		22, 11,  4, 25 };

uint32_t mask[32]; /* permutation mask to speed up the permutation transform */

/* ** */


uint32_t sbox_layer(uint32_t x)
{
	uint32_t res = 0;
	res = res | (sbox[0][(x>>28)&0xf] << 28);
	res = res | (sbox[1][(x>>24)&0xf] << 24);
	res = res | (sbox[2][(x>>20)&0xf] << 20);
	res = res | (sbox[3][(x>>16)&0xf] << 16);
	res = res | (sbox[4][(x>>12)&0xf] << 12);
	res = res | (sbox[5][(x>>8)&0xf] << 8);
	res = res | (sbox[6][(x>>4)&0xf] << 4);
	res = res | (sbox[7][x&0xf]);
	return res;
}

uint32_t permute(uint32_t x)
{
	uint32_t res = 0;
	for(int i = 0;i<32;i++)
		res |= ((x & mask[i]) << (per[i]-1)) >> i;
	return res;
}

/** 
 *  WES round function: 
 *
 *          1) xor with the round key
 *          2) Pass through f-box:
 *             -- sboxes
 *             -- permutaion
 *
 *
 *                         +------------- K (in)
 *                         |
 *           +------+      v
 *    out <--|  f   |<--- xor <--- x (in)
 *           +------+ 
 *
 *                 
 *  f(x) : out <-- PERMUTATION_BOX <-- SBOX's <-- x
 *
 * */
uint32_t round_func(uint32_t x, uint32_t rkey)
{
	x = x ^ rkey;
	x = sbox_layer(x);
	x = permute(x);
	return x;
}

/* Optimization: mask is used to extract bits at certain position.
 * Since we can do it once before the encryption, it will save us
 * some operations during the encryption */
int precompute_wes_permutation_mask()
{
	for(int i = 0; i<32; i++)
		mask[i] = 1 << (32-per[i]);
	return 0;

}

/* 
 * Key schedule function
 *
 * Generate 4 round keys based on master key. Each round key is a subset of 
 * master key's bits:
 *
 * 	  K1: odd bits
 * 	  K2: left 32bit-half
 * 	  K3: even bits
 * 	  K4: right 32bit-half
 *
 * @param      master_key  Master key (64-bits)
 * @param[out] rkeys       Array of 4 round keys (to be generated by this
 *                         function and returned to the caller)
 */
void key_schedule(uint64_t master_key, uint32_t rkeys[])
{
	uint32_t bit1, bit2, bit3, bit4;
	uint64_t s = master_key;

	memset(rkeys, 0, 4*sizeof(uint32_t));
	for(int i = 0; i<32; i++)
	{
		/* Extract specfic bits from the master key according to k1p, k2p, k3p,
		 * and k4p permutations */
		bit1 = ((s >> (64-k1p[i])) & 0x1);
		bit2 = ((s >> (64-k2p[i])) & 0x1);
		bit3 = ((s >> (64-k3p[i])) & 0x1);
		bit4 = ((s >> (64-k4p[i])) & 0x1);

		rkeys[0] |= bit1 << (31-i);
		rkeys[1] |= bit2 << (31-i);
		rkeys[2] |= bit3 << (31-i);
		rkeys[3] |= bit4 << (31-i);
	}
	return;
}

/* Encrypt a 64bit plaintext block with WES
 *
 * Execute WES encryption algorithm and generate the corresponding ciphertext 
 *
 * @param pt         Plaintext block to encrypt (64 bits)
 * @param master_key Encryption key (64 bits). Will be used to generate 4 round keys
 *
 * @return ct        Ciphertext (64 bits)
 *
 * */
uint64_t wes_encrypt(uint64_t pt, uint64_t master_key)
{
	uint32_t tmp;
	uint32_t l = pt >> 32;
	uint32_t r = pt & 0xffffffff;
	uint32_t rkeys[4] = {0}; /* Round keys */
	
	key_schedule(master_key, rkeys);   /* Generate round keys */   
	precompute_wes_permutation_mask(); /* Just an optimization: makes permutation step a bit faster */

	/* Do 4 rounds of encryption. */
	DEBUG_PRINT("** Plaintext: %016llX    Master key: %016llX\n", pt, master_key);
	for(int i = 0; i<4; i++)
	{
		DEBUG_PRINT("   input to r%d:  %08X  %08X     rkey = %08X\n", i+1, l, r, rkeys[i]);
		l = l ^ round_func(r, rkeys[i]);
		if(i != 3) /* if not the last round */
			{tmp = l; l = r; r = tmp;} /* swap left and rigth */
	}
	
	DEBUG_PRINT("  outp from r4:  %08X  %08X --\n", l, r);
	/* Recombine 64bits ciphertext from 32bits-left and 32bits-right */
	uint64_t ct = ((uint64_t )l << 32) | r;
	return ct;
}

uint64_t wes_decrypt(uint64_t ct, uint64_t master_key)
{
	uint32_t tmp;
	uint32_t l = ct >> 32;
	uint32_t r = ct & 0xffffffff;
	uint32_t rkeys[4] = {0}; /* Round keys */
	
	key_schedule(master_key, rkeys);   /* Generate round keys */   
	precompute_wes_permutation_mask(); /* Just an optimization: makes permutation step a bit faster */

	/* Do 4 rounds of encryption. */
	DEBUG_PRINT("** Ciphertext: %016llX    Master key: %016llX\n", ct, master_key);
	for(int i = 0; i<4; i++)
	{
		DEBUG_PRINT("   input to r%d:  %08X  %08X     rkey = %08X\n", i+1, l, r, rkeys[3-i]);
		l = l ^ round_func(r, rkeys[3-i]);
		if(i != 3) /* if not the last round */
			{tmp = l; l = r; r = tmp;} /* swap left and rigth */
	}
	
	DEBUG_PRINT("  outp from r4:  %08X  %08X --\n", l, r);
	/* Recombine 64bits ciphertext from 32bits-left and 32bits-right */
	uint64_t pt = ((uint64_t )l << 32) | r;
	return pt;
}

/* Driver function */
int main(int argc, char *argv[])
{
	uint64_t master_key = MASTERKEY; /* 8 bytes, global  */

	if(argc < 2)
	{
		printf("error: plaintext is missing\n");
		printf("Usage:   ./wes PLAINTEXT_HEX\n");
		printf("Example: ./wes 72657475706D6F43\n");
		exit(0);
	}
	if(strnlen(argv[1], 16) < 16)
	{
		printf("error: wrong input format (should be 16 hexadecimal digits). Run without arugments for an example.\n");
		exit(0);
	}

	char plaintext_hex[17] = {0};
	uint64_t plaintext;
	
	strncpy(plaintext_hex, argv[1], 16);  /* Plaintext. Should be 8 bytes (16 digits), i.e. representd a uint64_t */
	char *endptr;
	plaintext = strtoul(plaintext_hex, &endptr, 16);
	if(endptr - &plaintext_hex[0] < 16) /* Non-hexadecimal digit was found in the first 16 character of the input */
	{
		printf("error: wrong input format (should be 16 hexadecimal digits). Run without arugments for an example.\n");
		exit(0);

	}

	uint64_t ciphertext = wes_encrypt(plaintext, master_key);
#ifdef DEBUG
	printf(" Ciphertext: %016llX\n", ciphertext);
	uint64_t pt_back = wes_decrypt(ciphertext, master_key);
	printf(" Back: %016llX\n", pt_back);
#else
	printf("%016llX\n", ciphertext);
#endif
	return 0;

}
