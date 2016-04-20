//----------------------------------------------------
//
//  Code: DES Encryption
//  Authors: Tyler Travis & Justin Cox
//  Date: 3/23/16
//
//----------------------------------------------------

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "des.h"

int main(int argc, char** argv)
{
    uint8_t key[8] = {0x6a, 0x65, 0x78, 0x6A, 0x65, 0x78, 0x6A, 0x65};
    uint8_t plain_text[8] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF }; // Test message: 0123 4567 89AB CDEF
    
    uint16_t plain_text_size = sizeof(plain_text); // plain_text_size = 8 
    uint8_t cipher_text[8];

    printf("Plain Text: %02x%02x %02x%02x %02x%02x %02x%02x\n", plain_text[0], plain_text[1], plain_text[2], 
        plain_text[3], plain_text[4], plain_text[5], plain_text[6], plain_text[7]);

    //Run DES Encryption
    encrypt(plain_text, plain_text_size, cipher_text, key);

    printf("Cipher Text: %02x%02x %02x%02x %02x%02x %02x%02x\n", cipher_text[0], cipher_text[1], cipher_text[2], 
            cipher_text[3], cipher_text[4], cipher_text[5], cipher_text[6], cipher_text[7]);

    // Run DES Decryption
    decrypt(plain_text, cipher_text, key);

    printf("Plain Text: %02x%02x %02x%02x %02x%02x %02x%02x\n", plain_text[0], plain_text[1], plain_text[2], 
        plain_text[3], plain_text[4], plain_text[5], plain_text[6], plain_text[7]);

}
