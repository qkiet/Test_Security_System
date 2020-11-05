/*
 * crypto_services.h
 *
 *  Created on: Oct 30, 2020
 *      Author: Tin
 */

#ifndef CRYPTO_SERVICES_H_
#define CRYPTO_SERVICES_H_

#define WJ_ENCRYPT 1

#include <stdbool.h>
#if !(WJ_ENCRYPT)
#include "../CryptoLib/Inc/crypto.h"
#else
#include "WjCryptLib_AesCbc.h"
#endif
/*************************
 * Declare all interface *
 *************************/



/**
 * Encrypt plaintext into ciphertext with specified length
 * @param plaintext: pointer to plaintext [in]
 * @param plaintext_len: length of plaintext [in]
 * @param AES_key: input AES Key [in]
 * @param AES_IV: input AES IV [in]
 * @param ciphertext: pointer to output ciphertext[out]
 * @retval number of encrypted bytes
 */
extern int32_t Encrypt(uint8_t* plaintext, uint32_t plaintext_len, uint8_t* AES_key, uint8_t* AES_IV, uint8_t* ciphertext);

/**
 * Decrypt incoming ciphertext with specified length
 * @param ciphertext: pointer to ciphertext [in]
 * @param plaintext_len: length of ciphertext [in]
 * @param AES_key: input AES Key [in]
 * @param AES_IV: input AES IV [in]
 * @param decrypted_text: pointer to output decrypted text [out]
 * @retval number of decrypted bytes
 */
extern int32_t Decrypt(uint8_t* ciphertext, uint16_t ciphertext_len, uint8_t* AES_key, uint8_t* AES_IV, uint8_t* decrypted_text);
#endif /* CRYPTO_SERVICES_H_ */
