//----------------------------------------------------
//
//  Code: DES Encryption Header File
//  Authors: Tyler Travis & Justin Cox
//  Date: 3/23/16
//
//----------------------------------------------------

#ifndef DES_HH
#define DES_HH

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

extern const uint8_t IP[64];

extern const uint8_t FP[64];

extern const uint8_t E[48];

extern const uint8_t P[32];

extern const uint8_t PC_1[56];

extern const uint8_t PC_2[48];

extern const uint8_t ISV[16];

extern const uint8_t S_box1[4][16];

extern const uint8_t S_box2[4][16];

extern const uint8_t S_box3[4][16];

extern const uint8_t S_box4[4][16];

extern const uint8_t S_box5[4][16];

extern const uint8_t S_box6[4][16];

extern const uint8_t S_box7[4][16];

extern const uint8_t S_box8[4][16];

void encrypt(uint8_t *plain_text, uint16_t plain_text_size, uint8_t *cipher_text, uint8_t key[8]);
void decrypt(uint8_t *plain_text, uint8_t *cipher_text, uint8_t key[8]);
void generate_subkeys(uint8_t key[8], uint8_t subkey[][6]);
void desRound(uint8_t leftHalve[], uint8_t rightHalve[], uint8_t subkey[6]);
void fFunction(uint8_t rightHalve[], uint8_t subKey[6]);
void copy_bit(uint8_t source[], uint8_t dest[], uint16_t source_bit, uint16_t dest_bit);
void circular_shift_array(uint8_t array[4], uint8_t shift);
void combine_CD(uint8_t C[4], uint8_t D[4], uint8_t dest[7]);
void getPlainText(uint8_t plainText[], uint32_t genNum);

#endif