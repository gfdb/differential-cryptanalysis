#include "plaintext_cyphertext_pairs.h"

// this is the deltax we got from analyzing the sbox
// distribution tables 
u_int32_t deltax = 0x62060000;

// this is deltax after it is passed through the 
// round function, defined here for convenience
u_int32_t f_of_deltax = 0x8080d052;


// All of the following cyphertexts were generated 
// using the ./wes-key-53 binary, the plaintexts were chosen
// manually

// chosen plaintext ciphertext pairs for k4
u_int32_t pl1[6]{0xA2F1BF54, 0x45FB1F2A, 0x510A42D4, 0x7CDFDB48, 0x45652418, 0x498adc3b};
u_int32_t pr1[6]{0x12345678, 0x87654321, 0x959B6801, 0x8C41D693, 0x3B4D64C4, 0xB8E33CCE};
u_int32_t pl2[6]{pl1[0]^deltax, pl1[1]^deltax, pl1[2]^deltax, pl1[3]^deltax, pl1[4]^deltax, pl1[5]^deltax};
u_int32_t pr2[6]{0x12345678, 0x87654321, 0x959B6801, 0x8C41D693, 0x3B4D64C4, 0xB8E33CCE};

u_int32_t cl1[6]{0x4661866A, 0x261FBE7F, 0x96733C4F, 0xFB1D2E0B, 0xC1F6C1C1, 0x12419074};
u_int32_t cr1[6]{0x275114EC, 0x9B344686, 0x224F96F4, 0x707C35FA, 0xC8590ED2, 0xF5A73E60};
u_int32_t cl2[6]{0xFB0ED3A2, 0xF45E8F23, 0xBB1680F4, 0xA07D7683, 0x75BBCCB0, 0xDF39FBA7};
u_int32_t cr2[6]{0x43D4974F, 0xFDA14726, 0x6E5A13D5, 0x1479BC5B, 0xACDA85F3, 0xB826BDC2};


// chosen plaintext ciphertext pairs for k3
u_int32_t pl1k3[6]{0x2B05BA27, 0xC6A7D642, 0x8E3E2389, 0x140ECA52, 0x1D583A17, 0x5EE3646E};
u_int32_t pr1k3[6]{0xFB57CB98, 0x4ED5B8B6, 0x62B81B03, 0x5238C04A, 0xCD977EB4, 0xD684DCD4};
u_int32_t pl2k3[6]{0x2B05BA27, 0xC6A7D642, 0x8E3E2389, 0x140ECA52, 0x1D583A17, 0x5EE3646E};
u_int32_t pr2k3[6]{pr1k3[0]^deltax, pr1k3[1]^deltax, pr1k3[2]^deltax, pr1k3[3]^deltax, pr1k3[4]^deltax, pr1k3[5]^deltax};

u_int32_t cl1k3[6]{0xF75C914A, 0x68A40473, 0x633DD6D9, 0xB9A443FE, 0x906ED794, 0xD99109AF};
u_int32_t cr1k3[6]{0x1749B0A3, 0x653FB73B, 0xEAC40CF9, 0x3A373C96, 0x50A89F53, 0xDDD1FDB7};
u_int32_t cl2k3[6]{0xFFFA34DB, 0x94351847, 0xEFBC408A, 0xA575B61E, 0x4869D8AA, 0x364E4006};
u_int32_t cr2k3[6]{0x9C598812, 0xB4AE40E1, 0x93B21C20, 0xC14B4417, 0x4EF3672C, 0x04DBC12E};

// chosen plaintext ciphertext pairs for k2
u_int32_t pl1k2[6]{0xA4E02F38, 0xBFC20741, 0x592872AF, 0xFDBD4BC8, 0x84E28701, 0xF527D693};
u_int32_t pr1k2[6]{0x985A7DBB, 0xD7EC8E1B, 0x662A4ECF, 0xB442BE28, 0x7F8EB1AC, 0x6CCC04F8};
u_int32_t pl2k2[6]{0xA4E02F38, 0xBFC20741, 0x592872AF, 0xFDBD4BC8, 0x84E28701, 0xF527D693};
u_int32_t pr2k2[6]{pr1k2[0]^f_of_deltax, pr1k2[1]^f_of_deltax, pr1k2[2]^f_of_deltax, pr1k2[3]^f_of_deltax, pr1k2[4]^f_of_deltax, pr1k2[5]^f_of_deltax};

u_int32_t cl1k2[6]{0xFE88EFD6, 0xCD519714, 0x18200C4D, 0xA3978E41, 0x70E28129, 0xD54C9F9F};
u_int32_t cr1k2[6]{0xC7456D4C, 0xAE2313AE, 0xDA34203A, 0x8CFD077D, 0x6774F669, 0xE0F175D6};
u_int32_t cl2k2[6]{0xEC293400, 0xDA246774, 0x0398EA2B, 0xE8E361B6, 0x09D21D4B, 0x4325CE0D};
u_int32_t cr2k2[6]{0xB8AC7837, 0x915D5297, 0x6DB17F12, 0x619EBF90, 0x07C658E0, 0x21E4ADD6};
