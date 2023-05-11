#include "plaintext_cyphertext_pairs.h"

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
#include <set>
#include <algorithm>
#include <bitset>
#include <cstring>
#include <cstdint>

using std::cout;
using std::endl;

using std::string;
using std::unordered_map;
using std::thread;
using std::vector;
using std::set;
using std::bitset;
using std::ofstream;
using std::hex;
using std::uint32_t;


// The following is the given code from the wes implementation
// *****************************************************************************
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
uint32_t mask[32]; /* permutation mask to speed up the permutation transform */

int precompute_wes_permutation_mask()
{
	for(int i = 0; i<32; i++)
		mask[i] = 1 << (32-per[i]);
	return 0;

}

uint32_t permute(uint32_t x) {
	uint32_t res = 0;
	for(int i = 0;i<32;i++)
		res |= ((x & mask[i]) << (per[i]-1)) >> i;
	return res;
};

uint32_t round_func_no_xor(uint32_t x) {
	x = sbox_layer(x);
	x = permute(x);
	return x;
};
uint32_t round_func(uint32_t x, uint32_t rkey) {
	x = x ^ rkey;
	x = sbox_layer(x);
	x = permute(x);
	return x;
};

// Key scheduling tables 
int k1p[32] = {1,3,5,7,9,11,13,15,17,19,21,23,25,27,29,31,33,35,37,39,41,43,45,47,49,51,53,55,57,59,61,63};      // Odd bits
int k2p[32] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32};          // Left half
int k3p[32] = {2,4,6,8,10,12,14,16,18,20,22,24,26,28,30,32,34,36,38,40,42,44,46,48,50,52,54,56,58,60,62,64};     // Even bits
int k4p[32] = {33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,64}; // Right half

void key_schedule(uint64_t master_key, uint32_t rkeys[])
{
	uint32_t bit1, bit2, bit3, bit4;
	uint64_t s = master_key;

	std::memset(rkeys, 0, 4*sizeof(uint32_t));
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
};
uint64_t wes_encrypt(uint64_t pt, uint64_t master_key)
{
	uint32_t tmp;
	uint32_t l = pt >> 32;
	uint32_t r = pt & 0xffffffff;
	uint32_t rkeys[4] = {0}; /* Round keys */
	
	key_schedule(master_key, rkeys);   /* Generate round keys */   
	precompute_wes_permutation_mask(); /* Just an optimization: makes permutation step a bit faster */

	/* Do 4 rounds of encryption. */
	for(int i = 0; i<4; i++)
	{
		l = l ^ round_func(r, rkeys[i]);
		if(i != 3) /* if not the last round */
			{tmp = l; l = r; r = tmp;} /* swap left and rigth */
	}
	
	/* Recombine 64bits ciphertext from 32bits-left and 32bits-right */
	uint64_t ct = ((uint64_t )l << 32) | r;
	return ct;
}
// *****************************************************************************
// *****************************************************************************


// key is thread id, value is vector of keys found in that thread

// define a type for the map
using ThreadIntVectorMap = unordered_map<thread::id, vector<uint32_t>>;

// lists of k4 candidates from each thread
ThreadIntVectorMap key4_vector_map;
// lists of k4 that were successfull in finding k3 candidates
unordered_map<thread::id, set<uint32_t>> key4_vector_map_confirmed;
// lists of k3 candidates from each thread
ThreadIntVectorMap key3_vector_map;
// lists of k2 candidates from each thread
ThreadIntVectorMap key2_vector_map;


vector<uint32_t> squash_threadid_intvector_map(const ThreadIntVectorMap& threadIntMap) {
    // Create a vector to hold the combined integers
    vector<uint32_t> combinedInts;

    // Loop over each element in the map
    for (const auto& pair : threadIntMap)
    {
        // Add the integers in the current vector to the combined vector
        combinedInts.insert(combinedInts.end(), pair.second.begin(), pair.second.end());
    }

    // Sort the vector and remove duplicates
    std::sort(combinedInts.begin(), combinedInts.end());
    combinedInts.erase(std::unique(combinedInts.begin(), combinedInts.end()), combinedInts.end());

    // Return the combined vector
    return combinedInts;
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
            };
        };
    };
}

void create_differential_tables_and_high_prob_pairs() {
    for (int i = 0; i < 8; i++) {
        string filename = "differential_tables/output_table" + std::to_string(i+1) +".csv";
        string high_prob_diff = "guaranteed_pairs/high_prob_diff" + std::to_string(i+1) +".txt";
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



void check_key_2_against_ctext_ptext_pairs(uint32_t potential_k2, uint32_t k3_to_test_with, uint32_t k4_to_test_with) {
    // cout << hex << potential_k2 << endl;
    for (int i = 0; i < 6; i++) {
        // uint32_t deltaz = pr1[i] xor pr2[1]; which is just deltax
        uint32_t newcl1 = cl1k2[i] ^ round_func(cr1k2[i], k4_to_test_with);
        uint32_t newcr1 = cr1k2[i] ^ round_func(newcl1, k3_to_test_with);

        uint32_t newcl2 = cl2k2[i] ^ round_func(cr2k2[i], k4_to_test_with);
        uint32_t newcr2 = cr2k2[i] ^ round_func(newcl2, k3_to_test_with);

        uint32_t deltaz = f_of_deltax;
        if (0 != (deltaz ^ ((newcl1 ^ round_func(newcr1, potential_k2)) ^ (newcl2 ^ round_func(newcr2, potential_k2))))) {
            return;
        };
    }
    // store the k2 candidates
    key2_vector_map[std::this_thread::get_id()].push_back(potential_k2);
}

int test_keys_X_to_y_k4(uint32_t start, u_int64_t end) {
    // start: start of range to create thread with
    // end: end of range to create thread with

    thread::id thread_id = std::this_thread::get_id();
    // if thread id not already a key in map
    if (key4_vector_map.find(thread_id) == key4_vector_map.end()) {
        // create a vector for the keys this thread will find
        key4_vector_map[std::this_thread::get_id()] = vector<uint32_t>();
    }

    for (u_int64_t key = start; key <= end; key++) {
        // test every key with the ciphertext plaintext pairs
        // there are 6 for k4

        // number of pairs the current k4 worked with
        uint32_t num_success = 0;
        for (int i = 0; i < 6; i++) {
            uint32_t actual_deltaz = round_func_no_xor(pl1[i]) ^ round_func_no_xor(pl2[i]);
            uint32_t z1 = cl1[i] ^ round_func(cr1[i], key);
            uint32_t z2 = cl2[i] ^ round_func(cr2[i], key);
            uint32_t test_deltaz = z1 ^ z2;
            if (0 == (actual_deltaz ^ test_deltaz)) {
                num_success++;
            } else {
                break;
            }
        }

        if (num_success == 6) {
            // add candidate key to vector for this thread
            key4_vector_map[std::this_thread::get_id()].push_back(key);
        }
    };
    return 0;
}

vector<uint32_t> crack_k4() {
    cout << "\n================ CRACKING K4 ==================" << endl;

    // start k4 cracking timer
    auto startk4 = std::chrono::high_resolution_clock::now();

    // number of cores on current cpu
    uint32_t num_cores = std::thread::hardware_concurrency();

    cout << "Using " << num_cores << " cpu cores " << endl;
    // create array of threads of size 10
    thread threads[num_cores];

    // the start value of thread n
    uint32_t startval = 0x00000000;
    // FFFFFFFF / num_cores, used to increment the ranges for start/end
    uint32_t increment_val = 0xFFFFFFFF / num_cores;
    // the end value of thread n
    uint64_t endval = increment_val;
    for (int i = 0; i < num_cores; i++) {
        // add a thread to the array of threads
        // its job will be to test all keys(k4) from 
        // startval to endval
        cout << "Start val: " << startval << " - End Val: " << endval << endl;
        threads[i] = thread(test_keys_X_to_y_k4, startval, endval);
        // the start value for the next thread becomes the 
        // end value of this thread
        startval = endval + 1;
        // increment the end value for the next thread
        endval += increment_val;
        // for the last thread, make the end value uint32_t max value (0xFFFFFFFF)
        if (i == num_cores-1)
            endval = 0xFFFFFFFF;
    }
    // stop execution of main until the threads have finished 
    for (int i = 0; i < num_cores; i++) {
        threads[i].join();
    }
    // counter for number of k4 candidates
    int keycount = 0;
    // for each vector of k4s found by a given thread
    for (auto it: key4_vector_map) {
        // increment the keycounter by the number of keys that thread found
        keycount += it.second.size();
    }
    cout << "Number of candidate keys for k4: " << keycount << endl;

    // stop the k4 search counter
    auto stopk4 = std::chrono::high_resolution_clock::now();
    // calculate how long it took to find k4
    auto durationk4 = std::chrono::duration_cast<std::chrono::seconds>(stopk4 - startk4);
    cout << "Time taken to find k4 candidates: " << durationk4.count() << " seconds\n" << endl;

    return squash_threadid_intvector_map(key4_vector_map);

}

uint32_t get_even_bits(const uint32_t& num) {
    // the first even bit starts at 1 because we consider an even bit in the
    // context of the 64 bit master key

    

}


int test_keys_X_to_y_k3(const vector<uint32_t>& k4s_to_test) {

    thread::id thread_id = std::this_thread::get_id();
    // if thread id not already a key in map
    if (key3_vector_map.find(thread_id) == key3_vector_map.end()) {
        // create a vector for the keys this thread will find
        key3_vector_map[std::this_thread::get_id()] = vector<uint32_t>();
        key4_vector_map_confirmed[std::this_thread::get_id()] = set<uint32_t>();
    }

    for (u_int64_t potential_k3 = start; potential_k3 < end; potential_k3 += 0x00010000) {
        // number of pairs the current k3 worked with
        uint32_t num_success = 0;

        for (int i = 0; i < 6; i++) {

            // CR becomes the new CL
            uint32_t new_CL1 = cr1k3[i];
            uint32_t new_CL2 = cr2k3[i];

            // partially decrpyt CL to get new CR
            uint32_t new_CR1 = cl1k3[i] ^ round_func(cr1k3[i], k4_to_test);
            uint32_t new_CR2 = cl2k3[i] ^ round_func(cr2k3[i], k4_to_test);

            uint32_t actual_deltaz = round_func_no_xor(pr1k3[i]) ^ round_func_no_xor(pr2k3[i]);

            uint32_t z1 = new_CL1 ^ round_func(new_CR1, potential_k3);
            uint32_t z2 = new_CL2 ^ round_func(new_CR2, potential_k3);
            uint32_t test_deltaz = z1 ^ z2;

            if (0 == (actual_deltaz ^ test_deltaz)) {
                num_success++;
            } else {
                break;
            }
        }

        if (num_success == 6) {
            // add k3 candidate to vector for this thread
            key3_vector_map[std::this_thread::get_id()].push_back(potential_k3);

            // keep track of k4 candidates that worked
            key4_vector_map_confirmed[std::this_thread::get_id()].insert(k4_to_test);
        }
    }
    return 0;
}

vector<uint32_t> crack_k3(const vector<uint32_t>& k4_candidates) {
    cout << "================ CRACKING K3 ==================" << endl;
    // start counter for cracking k3
    auto startk3 = std::chrono::high_resolution_clock::now();
    // create a vector for the threads we will use to find k3
    vector<thread> k3_threads;

    // number of cores on current cpu
    uint32_t num_cores = std::thread::hardware_concurrency();

    uint32_t num_k4s_per_thread = k4_candidates.size() / num_cores;

    for (int i = 0; i < k4_candidates.size(); i+=num_k4s_per_thread) {
        vector<uint32_t> k4s_to_test(k4_candidates.begin(), k4_candidates.begin() + num_k4s_per_thread);
        k3_threads.push_back(thread(test_keys_X_to_y_k3, k4s_to_test));
    }

    // for each of the key lists for k4
    for (auto item : key4_vector_map) {    
        // for each of the keys in the list
        for (int i = 0; i < item.second.size(); i++) {
            // start range for thread n
            uint32_t start_range_k3 = 0;
            // end range for thread n
            uint32_t end_range_k3 = 0;
            // k4 to test
            uint32_t curr_key = item.second[i];

            // convert k4 into binary and then into a string
            string keybits = bitset<32>(curr_key).to_string();
            // buffer to build k3 with
            string bitbuffer = "";

            // for each even bit in k4
            for (int j = 1; j < 32; j+=2) {
                // push the even bits to the bit buffer for potential k3s from this k4
                bitbuffer.push_back(keybits[j]);
            };
            // set the start range for this thread to minimum possible k3 value from this k4
            // Ex: 0x0000ABCD
            start_range_k3 = stoi(bitbuffer, 0, 2);

            // set the end range for this thread to maximum possible k3 value from this k4
            // Ex: 0xFFFFABCD
            end_range_k3 = stoi(bitbuffer, 0, 2) + 0xFFFF0000;
            
            // add thread to the vector of threads for finding k3
            k3_threads.push_back(thread(test_keys_X_to_y_k3, start_range_k3, end_range_k3, curr_key));
       }
    }

    // stop execution of main until threads for k3 are finished execution
    for (thread &t : k3_threads) {
        t.join();
    }
    // stop timer for cracking of k3
    auto stopk3 = std::chrono::high_resolution_clock::now();
    // subtract stop/start time to find duration
    auto durationk3 = std::chrono::duration_cast<std::chrono::milliseconds>(stopk3 - startk3);

    vector<uint32_t> k3_candidates = squash_threadid_intvector_map(key3_vector_map);

    cout << "Number of candidate keys for k3: " << k3_candidates.size() << endl;
    cout << "Time taken to find k3 candidates: " << durationk3.count();
    cout << " milliseconds\n" << endl;

    return k3_candidates;
}

int test_keys_X_to_y_k2(uint32_t k3_to_test, uint32_t k4_to_test) {
    string k3_bits_as_string = bitset<32>(k3_to_test).to_string();
    string k2_bitbuffer = "";
    
    thread::id thread_id = std::this_thread::get_id();
    // if thread id not already a key in map
    if (key2_vector_map.find(thread_id) == key2_vector_map.end()) {
        // create a vector for the keys this thread will find
        key2_vector_map[std::this_thread::get_id()] = vector<uint32_t>();
    }

    // cntr that will go from 0 to 16
    // to put the fist 16 bits of k3
    // in the even bit positions
    int cntr = 0;
    for (int i = 0; i < 32; i++) {
        if (i % 2 != 0) {
            // even bits
            k2_bitbuffer.push_back(k3_bits_as_string[cntr]);
            cntr++;
        } else {
            // we put 0 in the odd bit positions for now
            k2_bitbuffer.push_back('0');
        }
    }

    // 0000 -> FFFF
    for(uint32_t i = 0x0000; i <= 0xFFFF; i++) {
        // replace every odd bit in potential k2 with the bits from i
        string bits_to_put_in = bitset<16>(i).to_string();
        k2_bitbuffer[0] = bits_to_put_in[0];
        k2_bitbuffer[2] = bits_to_put_in[1];
        k2_bitbuffer[4] = bits_to_put_in[2];
        k2_bitbuffer[6] = bits_to_put_in[3];
        k2_bitbuffer[8] = bits_to_put_in[4];
        k2_bitbuffer[10] = bits_to_put_in[5];
        k2_bitbuffer[12] = bits_to_put_in[6];
        k2_bitbuffer[14] = bits_to_put_in[7];
        k2_bitbuffer[16] = bits_to_put_in[8];
        k2_bitbuffer[18] = bits_to_put_in[9];
        k2_bitbuffer[20] = bits_to_put_in[10];
        k2_bitbuffer[22] = bits_to_put_in[11];
        k2_bitbuffer[24] = bits_to_put_in[12];
        k2_bitbuffer[26] = bits_to_put_in[13];
        k2_bitbuffer[28] = bits_to_put_in[14];
        k2_bitbuffer[30] = bits_to_put_in[15];

        uint32_t potential_k2 = (uint32_t)std::stol(k2_bitbuffer, 0, 2);
        // check k2/k3 with cipher text pairs
        check_key_2_against_ctext_ptext_pairs(potential_k2, k3_to_test, k4_to_test);

    };

    return 0;
}



int main() {
    precompute_wes_permutation_mask();
    // compute_all_io_differentials();
    // create_differential_tables_and_high_prob_pairs();

    vector<uint32_t> k4_candidates = crack_k4();

    vector<uint32_t> vector_k3s = crack_k3(k4_candidates);

    // counter for the number of k4 candidates
    // that were successfully used to find 
    // a k3 candidate
    int k4counter = 0;
    // a variable for storing the single k4 we will get (spoilers!!)
    uint32_t fourth_subkey;
    // for each set of k4s successfully used to 
    // find a k3 candidate
    for (auto item: key4_vector_map_confirmed) {
        // add the size of the set to the k4counter
        k4counter += item.second.size();
        // if the set's size is not 0
        if (item.second.size() != 0) {
            // for each item in the set (its only going to be 1 item but just in case we'll loop over it)
            for (auto i: item.second) {
                // set our confirmed k4 subkey
                fourth_subkey = i;
            }
        }
    }

    cout << "Number of successful keys for k4: " << k4counter << endl;


    cout << "================ CRACKING K2 ==================" << endl;
    // start timer for cracking k2
    auto startk2 = std::chrono::high_resolution_clock::now();
    // create a vector for the threads we will use to find k2
    vector<thread> k2_threads;

    // for each k3 candidate
    for (auto potential_k3 : vector_k3s) {    
        // create a thead for that k4 candidate
        k2_threads.push_back(thread(test_keys_X_to_y_k2, potential_k3, fourth_subkey));
    }
    // pause execution of main until k2 thread execution is complete
    for (thread &t : k2_threads) {
        t.join();
    }
    // stop timer for cracking k2
    auto stopk2 = std::chrono::high_resolution_clock::now();
    // calculate duration for cracking k2
    auto durationk2 = std::chrono::duration_cast<std::chrono::milliseconds>(stopk2 - startk2);

    // vector for combining the vectors of 
    // k2 candidates found by each thread
    vector<uint32_t> vector_k2s;
    // for each vector of k2 candidates from each thread
    for (auto item: key2_vector_map) {
        // combine vector of k2 candidates together
        vector_k2s.insert(vector_k2s.end(), item.second.begin(), item.second.end());
    }
    cout << "Number of k2s found: " << vector_k2s.size() << endl;
    cout << "Time taken to find k2 candidates: " << durationk2.count() << " milliseconds\n" << endl;


    cout << "================ CRACKING MASTER KEY ==================" << endl;

    // plaintext to test master keys with
    u_int64_t pt_for_k1 = 0xA2F1BF5412345678;
    // corresponding cipher text encryption produced by ./wes-key-53 A2F1BF5412345678
    u_int64_t correct_ciphertext_k1 = 0x4661866A275114EC;

    // brute force k1 using k2s and k4
    for (uint32_t k2_to_test: vector_k2s) {
        // creater master key by using k2 as the first 8 bytes and k1 as the last 8 bytes
        u_int64_t master_key_to_test = (u_int64_t) k2_to_test << 32 | fourth_subkey;

        // check if encryption with trial master key results in correct encryption
        if (correct_ciphertext_k1 == wes_encrypt(pt_for_k1, master_key_to_test)) {
            cout << "Master key found: " << hex << master_key_to_test << endl;
            break;
        }
    }

    
    return 0;
}

// g++ -std=c++14 -pthread -O3 plaintext_cyphertext_pairs.cpp breakcipher.cpp -o breakcipher && ./breakcipher