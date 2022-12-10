
#include <iostream>
#include <vector>
#include <string>
#include <fstream>
#include <inttypes.h>
#include <stdint.h>
#include <thread>
#include <climits>
#include <chrono>
#include <limits>

using namespace std;

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

u_int32_t sbox_layer(u_int32_t x)
{
	u_int32_t res = 0;
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

int outputdiff[8][16][16];

int per[32]
	= { 16,  7, 20, 21, 
		29, 12, 28, 17,
		 1, 15, 23, 26,
		 5, 18, 31, 10, 
		 2,  8, 24, 14, 
		32, 27,  3,  9, 
		19, 13, 30,  6, 
		22, 11,  4, 25 };
u_int32_t mask[32]; /* permutation mask to speed up the permutation transform */

int precompute_wes_permutation_mask()
{
	for(int i = 0; i<32; i++)
		mask[i] = 1 << (32-per[i]);
	return 0;

}

u_int32_t permute(u_int32_t x) {
	u_int32_t res = 0;
	for(int i = 0;i<32;i++)
		res |= ((x & mask[i]) << (per[i]-1)) >> i;
	return res;
};

u_int32_t round_func_no_xor(u_int32_t x) {
	x = sbox_layer(x);
	x = permute(x);
	return x;
};
u_int32_t round_func(u_int32_t x, u_int32_t rkey) {
	x = x ^ rkey;
	x = sbox_layer(x);
	x = permute(x);
	return x;
};

int keycount = 0;

int test_keys_X_to_y(u_int32_t start, u_int64_t end, u_int32_t cipherL1, u_int32_t cipherR1, u_int32_t cipherL2, u_int32_t cipherR2, u_int32_t deltaZ) {
    string debuuu = "begin: " + to_string(start) + " --- end: " + to_string(end) + "\n";
    cout << debuuu;
    // u_int32_t result;
    for (u_int64_t key = start; key < end; key++) {
        // printf("%u", i);
        // printf("\n");
        if (0 == (deltaZ ^ ((cipherL1 ^ round_func(cipherR1,key)) ^ (cipherL2 ^ round_func(cipherR2,key))))) {
            // printf("KEY FOUND\n");
            printf("%u", key);
            printf("\n");
            keycount++;
        };
    };
    cout << "thread over...\n";
    return 0;
}


int main() {

    // for (int i = 0; i < sbox.size(); i++) {
    //     for (int j = 0; j < sbox[i].size(); j++) {
    //         for (int k = 0; k < sbox[i].size(); k++) {

    //         }
    //     };
    // };
    // for (int i = 0; i < 8; i++) {
    //     for (int j = 0; j < 16; j++) {
    //         for (int k = 0; k < 16; k++) {
    //             // cout << "combining X1: " << sbox[7][i] << " and X2: " << sbox[7][j] << endl;
    //             bitset<4> x1(j);
    //             bitset<4> x2(k);
    //             bitset<4> deltax;
    //             deltax = x1 xor x2;


    //             bitset<4> y1(sbox[i][j]);
    //             bitset<4> y2(sbox[i][k]);
    //             bitset<4> deltay = y1 xor y2;

    //             int deltax_int = (int)(deltax.to_ulong());
    //             int deltaxy_int = (int)(deltay.to_ulong());

    //             outputdiff[i][deltax_int][deltaxy_int] += 1;
    //             // cout << "delta x is: " << deltax << endl;;
    //         };
    //     };
    // };


    // for (int i = 0; i < 8; i++) {
    //     string filename = "output_table" + to_string(i+1) +".csv";
    //     string high_prob_diff = "high_prob_diff" + to_string(i+1) +".txt";
    //     ofstream outfile(filename);
    //     ofstream high_prob_outfile(high_prob_diff);

    //     for (int j = 0; j < 16; j++) {
    //         if (j != 0)
    //             outfile << "\n";
    //         for (int k = 0; k < 16; k++) {
    //             outfile << outputdiff[i][j][k];
    //             if (outputdiff[i][j][k] == 16) {
    //                 high_prob_outfile << "(" << j << ", " << k << "): ";
    //                 high_prob_outfile << outputdiff[i][j][k] << "/16\n";
    //             }
    //             if (k != 15)
    //                 outfile << ",";
    //         };
    //     };
    //     outfile.close();
    //     high_prob_outfile.close();
    // }
    // u_int32_t x = 1644560384;
    // cout << to_string(permute(x)) << endl;
    
    precompute_wes_permutation_mask();
    u_int32_t deltax = 0x62060000;

    u_int32_t ptextL1 = 0x75457375;//0x00000000;
    u_int32_t ptextR1 = 0x760D6F43;//0xA3010000;
    u_int32_t cipherL1 = 0x2DA0E12B;// 0x971C726F;
    u_int32_t cipherR1 = 0xD5A8CDB0;// 0x81B20517;
    u_int32_t ptextL2 = 0x78542358;//0xe286d052;
    u_int32_t ptextR2 = ptextR1 ^ deltax;//0xc1070000;
    u_int32_t cipherL2 = 0xA56ADF39;// 0x4348AF4A;
    u_int32_t cipherR2 = 0x19AF14C2;// 0x6FA55EC5;



    u_int32_t fdeltax = round_func_no_xor(ptextR1) ^ round_func_no_xor(ptextR2);
    u_int32_t deltaZ = fdeltax ^ deltax;

    // printf("f(r1) is: ");
    // printf("%u", ptextr1_after_func);
    // printf("-------");
    // printf("f(r2) is: ");
    // printf("%u", ptextr2_after_func);
    // printf("\n");
    // printf("FR1 XOR fR2: ");
    // printf("%u", fdeltax);
    // printf("\n");
    // printf("%08" PRIx32 "\n", fdeltax);
    // printf("\n");

    // printf("ptextr1_after_func is: ");
    // printf("%u", ptextr1_after_func);
    // printf("\n");
    // printf("ptextr2_after_func is: ");
    // printf("%u", ptextr2_after_func);
    // printf("\n");

    // printf("fdx is: ");
    // printf("%u", fdeltax);
    // printf("\n");
    // printf("%08" PRIx32 "\n", fdeltax);
    // printf("dz is: ");
	// printf("%u",deltaZ);
    // printf("\n");
    // printf("%08" PRIx32 "\n", deltaZ);
    // Print f(R1)
    // F(R2)
    // Then print FR1 XOR fR2
  


    auto start = chrono::high_resolution_clock::now();

    thread threads[10];

    u_int32_t startval = 0x00000000;
    uint64_t endval = 0x1999999A;
    u_int32_t increment_val = 0x1999999A;
    for (int i = 0; i < 10; i++) {
        threads[i] = thread(test_keys_X_to_y, startval, endval, cipherL1, cipherR1, cipherL2, cipherR2, deltaZ);
        startval = endval;
        endval += increment_val;
        if (i == 9)
            endval = numeric_limits<u_int32_t>::max();
    }
    for (int i = 0; i < 10; i++) {
        threads[i].join();
    }
    auto stop = chrono::high_resolution_clock::now();
    auto duration = chrono::duration_cast<chrono::seconds>(stop - start);
    cout << "Time taken by function: " << duration.count() << " seconds" << endl;
    cout << "Approximate number of keys: " << keycount << endl;

        // for (u_int32_t i = 0; i < 0xFFFFFFFF; i++) {
        //     k4 = i;
        //     u_int32_t result = cl1 xor round_func(cr1, k4) xor cl2 xor round_func(cr2, k4);
        //     if (result == deltaz) {
        //         cout << "FOUND IT: ";
        //         printf("%u", k4);
        //         break;
        //     } else {
        //         printf("%u", k4);
        //         printf("\n");
        //     }
        // }
        // 16BE7F6C xor f(CE89F195 xor k4) xor AA393D88 xor f(AA393D88 xor k4) = 3ade4bbe
        // precompute_wes_permutation_mask();
        // x = sbox_layer(x);
        // x = permute(x);
        // printf("%u", x);

    // cout << "This answer is something" << endl;
    
    // cout << x1 << "\n";
    return 0;
}

// g++ -std=c++14 breakcipher.cpp -o breakcipher && ./breakcipher