/*
 * crypto_services.h
 *
 *  Created on: Oct 30, 2020
 *      Author: Tin
 */

#ifndef CRYPTO_SERVICES_H_
#define CRYPTO_SERVICES_H_

#define WJ_ENCRYPT 1

#include "main.h"
#include <stdbool.h>
#if !(WJ_ENCRYPT)
#include "../CryptoLib/Inc/crypto.h"
#else
#include "WjCryptLib_AesCbc.h"
#include "WjCryptLib_AesCtr.h"
#include "WjCryptLib_Sha256.h"
#include "WjCryptLib_Sha512.h"
#include <stdbool.h>
#endif

#define PASSWORD_LENGTH 10
#define SECRET_KEY_SIZE SHA256_HASH_SIZE
#define RANDOM_AUTHENTICATE_NUMBER_SIZE (128 / 8)
#define HMAC_SIZE SHA256_HASH_SIZE
#define MAXIMUM_MESSAGE_SIZE 1024
/*************************
 * Declare all interface *
 *************************/
/**
 * Generate random number with specified size. Must be DIVISIBLE by 32
 * @param number_of_bit: specifiy how big the random number is
 * @param output_buffer: pointer to output number
 */
extern void RNGBigNumber(uint16_t size_in_byte, uint8_t* output_buffer);

/**
 * Calculate HMAC of given message, key and compare with target_HMAC
 * @param message: pointer to message buffer
 * @param message_length: length of message
 * @key: pointer to key
 * @key_size: key size
 * @target_HMAC: HMAC that used to compare
 * return 1 if 2 HMACs are equal, return 0 otherwise
 */
extern int CompareHMAC_SHA256(uint8_t* message, uint16_t message_length, uint8_t* key, uint8_t key_size, SHA256_HASH target_HMAC);



/**
 * Prepares the sending buffer according to specification: 2 bytes of payload length + payload
 * @param key: Key used for encryption and HMAC 			[in]
 * @param keylen: size of key 												[in]
 * @param iv: Initialization Vector for encryption 		[in]
 * @param data: pointer to data buffer 								[in]
 * @param datalen: length of data (exclude HMAC) 			[in]
 * @param output_size: desired length of output buffer[in]
 * @param is_hmac: Append HMAC if set to true 				[in]
 * @param is_encrypt: Encrypt output if set to true 	[in]
 * @param result: pointer to output buffer 						[out]
 */
extern void PrepareSendingBuffer(const void* key, int keylen, const void* iv, uint8_t* data, uint16_t datalen, uint16_t output_size, bool is_hmac, bool is_encrypt, uint8_t* result);



/**
 * Create HMAC Digest of given message, key
 */
extern void CreateHMAC_SHA256(uint8_t* message, uint16_t message_length, uint8_t* key, uint8_t key_size, SHA256_HASH* output_HMAC);

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
