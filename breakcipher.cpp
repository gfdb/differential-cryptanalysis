
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
#include <unordered_map>

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

// key is thread id, value is vector of keys found in that thread
unordered_map<thread::id, vector<u_int32_t>> key4_vector_map;
u_int32_t deltax = 0x62060000;

u_int32_t pl1[6]{0xA2F1BF54, 0x45FB1F2A, 0x510A42D4, 0x7CDFDB48, 0x45652418, 0x498adc3b};
u_int32_t pr1[6]{0x12345678, 0x87654321, 0x959B6801, 0x8C41D693, 0x3B4D64C4, 0xB8E33CCE};
u_int32_t pl2[6]{pl1[0] xor deltax, pl1[1] xor deltax, pl1[2] xor deltax, pl1[3] xor deltax, pl1[4] xor deltax, pl1[5] xor deltax};
u_int32_t pr2[6]{0x12345678, 0x87654321, 0x959B6801, 0x8C41D693, 0x3B4D64C4, 0xB8E33CCE};

u_int32_t cl1[6]{0x4661866A, 0x261FBE7F, 0x96733C4F, 0xFB1D2E0B, 0xC1F6C1C1, 0x12419074};
u_int32_t cr1[6]{0x275114EC, 0x9B344686, 0x224F96F4, 0x707C35FA, 0xC8590ED2, 0xF5A73E60};
u_int32_t cl2[6]{0xFB0ED3A2, 0xF45E8F23, 0xBB1680F4, 0xA07D7683, 0x75BBCCB0, 0xDF39FBA7};
u_int32_t cr2[6]{0x43D4974F, 0xFDA14726, 0x6E5A13D5, 0x1479BC5B, 0xACDA85F3, 0xB826BDC2};



void check_key4_against_ctext_ptext_pairs(u_int64_t key) {
    for (int i = 0; i < 6; i++) {
        // deltaz = f(deltax) = vvvv
        u_int32_t deltaz = round_func_no_xor(pl1[i]) ^ round_func_no_xor(pl2[i]);;
        if (0 != (deltaz ^ ((cl1[i] ^ round_func(cr1[i], key)) ^ (cl2[i] ^ round_func(cr2[i], key))))) {
            return;
        };
    }
    // if it reaches this point it means the key works with all 5 
    // cipher text plaintext pairs
    // print key
    // cout << hex << key << endl;
    // add key to vector for this thread
    key4_vector_map[this_thread::get_id()].push_back(key);
    // keycount++;
};

u_int32_t kcount = 0;
void check_key_3_against_ctext_ptext_pairs(u_int64_t potential_k3, u_int64_t k4_to_test_with) {
    // cout << hex << potential_k3 << endl;

    // string debuggg = "trying k3 " + to_string(potential_k3) + "\n";
    // cout << debuggg;
    // cout << hex << potential_k3 << endl;
    for (int i = 0; i < 6; i++) {
        // u_int32_t deltaz = pr1[i] xor pr2[1]; which is just deltax
        u_int32_t newcl1 = cr1[i];
        u_int32_t newcr1 = cl1[i] xor round_func(cr1[i], k4_to_test_with);

        u_int32_t newcl2 = cr2[i];
        u_int32_t newcr2 = cl2[i] xor round_func(cr2[i], k4_to_test_with);

        u_int32_t deltaz = deltax;
        if (0 != (deltaz ^ ((newcl1 ^ round_func(newcr1, potential_k3)) ^ (newcl2 ^ round_func(newcr2, potential_k3))))) {
            return;
        };
    }
    cout << hex << potential_k3 << endl;
    kcount++;
}

int test_keys_X_to_y_k3(u_int32_t start, u_int64_t end, u_int32_t k4_to_test) {

    for (u_int64_t potential_k3 = start; potential_k3 < end; potential_k3 += 0x00010000) {
        check_key_3_against_ctext_ptext_pairs(potential_k3, k4_to_test);
    }
    cout << "thread over...\n";
    return 0;
}

int test_keys_X_to_y_k4(u_int32_t start, u_int64_t end) {
    // start: start of range to create thread with
    // end: end of range to create thread with
    // keynum: the key you are trying to break options: [1, 2, 3, 4]

    // string debuuu = "begin: " + to_string(start) + " --- end: " + to_string(end) + "\n";
    // cout << debuuu;
    thread::id thread_id = this_thread::get_id();
    // if thread id not already a key in map
    if (key4_vector_map.find(thread_id) == key4_vector_map.end()) {
        // create a vector for the keys this thread will find
        key4_vector_map[this_thread::get_id()] = vector<u_int32_t>();
    }
    // u_int32_t result;
    for (u_int64_t key = start; key <= end; key++) {
        check_key4_against_ctext_ptext_pairs(key);
    };
    cout << "thread over...\n";
    return 0;
}

void compute_all_io_differentials() {
    for (int i = 0; i < 8; i++) {
        for (int j = 0; j < 16; j++) {
            for (int k = 0; k < 16; k++) {

                bitset<4> x1(j);
                bitset<4> x2(k);
                bitset<4> deltax;
                deltax = x1 xor x2;

                bitset<4> y1(sbox[i][j]);
                bitset<4> y2(sbox[i][k]);
                bitset<4> deltay = y1 xor y2;

                int deltax_int = (int)(deltax.to_ulong());
                int deltaxy_int = (int)(deltay.to_ulong());

                outputdiff[i][deltax_int][deltaxy_int] += 1;
                // cout << "delta x is: " << deltax << endl;;
            };
        };
    };
}

void create_differential_tables_and_high_prob_pairs() {
    for (int i = 0; i < 8; i++) {
        string filename = "differential_tables/output_table" + to_string(i+1) +".csv";
        string high_prob_diff = "guaranteed_pairs/high_prob_diff" + to_string(i+1) +".txt";
        ofstream outfile(filename);
        ofstream high_prob_outfile(high_prob_diff);

        for (int j = 0; j < 16; j++) {
            if (j != 0)
                outfile << "\n";
            for (int k = 0; k < 16; k++) {
                outfile << outputdiff[i][j][k];
                if (outputdiff[i][j][k] == 16) {
                    high_prob_outfile << "(" << j << ", " << k << "): ";
                    high_prob_outfile << outputdiff[i][j][k] << "/16\n";
                }
                if (k != 15)
                    outfile << ",";
            };
        };
        outfile.close();
        high_prob_outfile.close();
    }
};




int main() {
    precompute_wes_permutation_mask();
    // compute_all_io_differentials();
    // create_differential_tables_and_high_prob_pairs();

    // find candidate keys for k4
    auto start = chrono::high_resolution_clock::now();

    thread threads[10];

    u_int32_t startval = 0x00000000;
    uint64_t endval = 0x1999999A;
    u_int32_t increment_val = 0x1999999A;
    for (int i = 0; i < 10; i++) {
        threads[i] = thread(test_keys_X_to_y_k4, startval, endval);
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
    cout << "Time taken to find k4 candidates: " << duration.count() << " seconds" << endl;
    keycount = 0;
    // for (const auto & [ thread_id, value ] : key4_vector_map) {
    //     keycount += key4_vector_map[thread_id].size();
    // }
    for (auto it: key4_vector_map) {
        // Do stuff
        cout << it.second.size() << endl;
        keycount += it.second.size();
    }
    cout << "Approximate number of candidate keys for k4: " << keycount << endl;

    auto start1 = chrono::high_resolution_clock::now();
    vector<thread> k3_threads;
    // for each of the key lists for k4
    for (auto item : key4_vector_map) {    
        // for each key in that list
        for (int i = 0; i < item.second.size(); i++) {
            u_int32_t start_range_k3 = 0;
            u_int32_t end_range_k3 = 0;
            u_int32_t curr_key = item.second[i];
            // kth bit of n
            // (n & ( 1 << k )) >> k
            string keybits = bitset<32>(curr_key).to_string();
            string bitbuffer = "";


            for (int j = 1; j < 32; j+=2) {
                bitbuffer.push_back(keybits[j]);
            };
            start_range_k3 = stoi(bitbuffer, 0, 2);
            end_range_k3 = stoi(bitbuffer, 0, 2) + 0xFFFF0000;
            
            k3_threads.push_back(thread(test_keys_X_to_y_k3, start_range_k3, end_range_k3, curr_key));
       }
    }
    cout << "k3 threads size: " << k3_threads.size() << endl;

    for (thread &t : k3_threads) {
        t.join();
    }
    auto stop1 = chrono::high_resolution_clock::now();
    auto duration1 = chrono::duration_cast<chrono::milliseconds>(stop - start);
    cout << "Time taken to find k3 candidates: " << duration.count() << " milliseconds" << endl;
    cout << "kcount: " << kcount;

        // 16BE7F6C xor f(CE89F195 xor k4) xor AA393D88 xor f(AA393D88 xor k4) = 3ade4bbe
        // precompute_wes_permutation_mask();
        // x = sbox_layer(x);
        // x = permute(x);
        // printf("%u", x);

    // cout << "This answer is something" << endl;
    
    // cout << x1 << "\n";
    return 0;
}

// g++ -std=c++14 breakc.cpp -o breakc && ./breakc