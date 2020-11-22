/*
 * crypto_services.c
 *
 *  Created on: Oct 30, 2020
 *      Author: Tin
 */



#include "crypto_services.h"

extern RNG_HandleTypeDef hrng;

/************************
 * Declare private APIs *
 ************************/
static void PaddingNull(uint8_t* buffer_in_out, uint16_t input_length, uint16_t output_length);

/***************************
 * Implement all interface *
 ***************************/

#if !(WJ_ENCRYPT)
/**
 * Initialize crypto service engine
 * @param AES_key: input AES Key [in]
 * @param AES_IV: input AES IV [in[
 */
int32_t Encrypt(uint8_t* plaintext, uint32_t plaintext_len, uint8_t* AES_key, uint8_t* AES_IV, uint8_t* ciphertext)
{

	AESCBCctx_stt AESctx;
	uint32_t error_status = AES_SUCCESS;
	int32_t outputLength = 0, temp_output_len;
	/* Set flag field to default value */



	AESctx.mFlags = E_SK_DEFAULT;

	/* Set key size to 24 (corresponding to AES-192) */
	AESctx.mKeySize = CRL_AES128_KEY;
	/* Set iv size field to IvLength*/
	AESctx.mIvSize = CRL_AES_BLOCK;
	/* Initialize the operation, by passing the key.
	* Third parameter is NULL because CBC doesn't use any IV */
	error_status = AES_CBC_Encrypt_Init(&AESctx, AES_key, AES_IV);

	if (error_status == AES_SUCCESS)
	{
	 error_status = AES_CBC_Encrypt_Append(&AESctx, plaintext, plaintext_len, ciphertext, &temp_output_len);
	 if (error_status == AES_SUCCESS)
	 {
		 outputLength += temp_output_len;
		 error_status = AES_CBC_Encrypt_Finish(&AESctx, ciphertext, &outputLength);
		 if (error_status == AES_SUCCESS)
		 {
			 outputLength += temp_output_len;



				AESCBCctx_stt AESctx_decrypt;

				AESctx_decrypt.mFlags = E_SK_DEFAULT;
				AESctx_decrypt.mKeySize = CRL_AES128_KEY;
				AESctx_decrypt.mIvSize = CRL_AES_BLOCK;
				error_status = AES_CBC_Decrypt_Init(&AESctx_decrypt, AES_key, AES_IV);

					if (error_status == AES_SUCCESS)
					{
					 error_status = AES_CBC_Decrypt_Append(&AESctx_decrypt, ciphertext, plaintext_len, plaintext, &temp_output_len);
					 if (error_status == AES_SUCCESS)
					 {
						 outputLength += temp_output_len;
						 error_status = AES_CBC_Decrypt_Finish(&AESctx_decrypt, ciphertext + outputLength, &temp_output_len);
						 if (error_status == AES_SUCCESS)
						 {
							 outputLength += temp_output_len;
							 return outputLength;
						 }
					 }
					}




			 return outputLength;
		 }
	 }
	}
	return error_status;
	/* check for initialization */
}

/**
 * Initialize crypto service engine
 * @param AES_key: input AES Key [in]
 * @param AES_IV: input AES IV [in[
 */
int32_t Decrypt(uint8_t* ciphertext, uint16_t ciphertext_len, uint8_t* AES_key, uint8_t* AES_IV, uint8_t* decrypted_text)
{
	AESCBCctx_stt AESctx;
	uint32_t error_status = AES_SUCCESS;
	int32_t outputLength = 0, temp_output_len;
	/* Set flag field to default value */
	AESctx.mFlags = E_SK_DEFAULT;

	/* Set key size to 24 (corresponding to AES-192) */
	AESctx.mKeySize = CRL_AES128_KEY;
	/* Set iv size field to IvLength*/
	AESctx.mIvSize = CRL_AES_BLOCK;
	/* Initialize the operation, by passing the key.
	* Third parameter is NULL because CBC doesn't use any IV */
	error_status = AES_CBC_Decrypt_Init(&AESctx, AES_key, AES_IV);

	if (error_status == AES_SUCCESS)
	{
	 error_status = AES_CBC_Decrypt_Append(&AESctx, ciphertext, ciphertext_len, decrypted_text, &temp_output_len);
	 if (error_status == AES_SUCCESS)
	 {
		 outputLength += temp_output_len;
		 error_status = AES_CBC_Decrypt_Finish(&AESctx, decrypted_text + outputLength, &temp_output_len);
		 if (error_status == AES_SUCCESS)
		 {
			 outputLength += temp_output_len;
			 return outputLength;
		 }
	 }
	}
 return error_status;
 /* check for initialization */
}

#else


/************************
 * Declare private APIs *
 ************************/


static void ArrayXOR(uint8_t* array1, uint8_t* array2, uint16_t length, uint8_t* output_array);
static void PaddingnNull(uint8_t* buffer_in_out, uint16_t input_length, uint16_t output_length);

/************************
 * Define public APIs *
 ************************/

/**
 * Initialize crypto service engine
 * @param AES_key: input AES Key [in]
 * @param AES_IV: input AES IV [in[
 */
int32_t Encrypt(uint8_t* plaintext, uint32_t plaintext_len, uint8_t* AES_key, uint8_t* AES_IV, uint8_t* ciphertext)
{
	int32_t result;
	result = AesCtrXorWithKey(AES_key, AES_KEY_SIZE_128, AES_IV, plaintext, ciphertext, plaintext_len);
	return result;
}

int32_t Decrypt(uint8_t* ciphertext, uint16_t ciphertext_len, uint8_t* AES_key, uint8_t* AES_IV, uint8_t* decrypted_text)
{
	int32_t result;
	result = AesCtrXorWithKey(AES_key, AES_KEY_SIZE_128, AES_IV, ciphertext, decrypted_text, ciphertext_len);
	return result;
}

/**
 * Generate random number with specified size. Must be DIVISIBLE by 32
 * @param size_in_byte: specifiy how big the random number is
 * @param output_buffer: pointer to output number
 */
void RNGBigNumber(uint16_t size_in_byte, uint8_t* output_buffer)
{
	uint32_t rng_number;
	for (int i = 0; i < size_in_byte/4; i++)
	{
		HAL_RNG_GenerateRandomNumber(&hrng, &rng_number);
		memcpy(output_buffer + 4 * i, &rng_number, sizeof(rng_number));
	}
}

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
 * @param command_id: command id of this payload			[in]
 * @param result: pointer to output buffer 						[out]
 */
void PrepareSendingBuffer(
		const void* key,
		int keylen,
		const void* iv,
		uint8_t* data,
		uint16_t datalen,
		uint16_t output_size,
		bool is_hmac,
		bool is_encrypt,
		uint16_t command_id,
		uint8_t* result)
{
    uint8_t temp_buff[1060];
    memcpy((void*)result, data, datalen);
    //First, append payload length
    memcpy((void*)temp_buff, result, datalen);
    memcpy(result, &datalen, sizeof(datalen));
    memcpy(result + MESSAGE_LENGTH_HEADER_SIZE, &command_id, sizeof(command_id));
    memcpy(result + MESSAGE_LENGTH_HEADER_SIZE + MESSAGE_COMMAND_ID_SIZE, temp_buff, datalen);

    //Second, padding with ISO 7816 padding scheme
    PaddingNull(result, datalen + MESSAGE_LENGTH_HEADER_SIZE + MESSAGE_COMMAND_ID_SIZE, output_size);

    //Then it encrypt
    if (is_encrypt)
    {
    	Encrypt(result, output_size, (uint8_t*)key, (uint8_t*)iv, result);
    }

    //Add HMAC if specified
    if (is_hmac)
    {
			SHA256_HASH hmac_buff;
			memcpy((void*)temp_buff, result, output_size);
			CreateHMAC_SHA256(result, output_size, key, keylen, &hmac_buff);
			memcpy(result, hmac_buff.bytes, 32);
			memcpy(result + 32, temp_buff, output_size);
    }

}

/**
 * Calculate HMAC of given message, key and compare with target_HMAC
 * @param message: pointer to message buffer 	[in]
 * @param message_length: length of message 	[in]
 * @key: pointer to key 											[in]
 * @key_size: key size												[in]
 * @target_HMAC: HMAC that used to compare		[in]
 * return 1 if 2 HMACs are equal, return 0 otherwise
 */
int CompareHMAC_SHA256(uint8_t* message, uint16_t message_length, uint8_t* key, uint8_t key_size, SHA256_HASH target_HMAC)
{
	SHA256_HASH calculated_HMAC;
	CreateHMAC_SHA256(message, message_length, key, key_size, &calculated_HMAC);
	for (int i= 0; i < SHA256_HASH_SIZE; i++)
	{
		if (calculated_HMAC.bytes[i] != target_HMAC.bytes[i])
		{
			return 0;
		}
	}
	return 1;
}

/**
 * Calculate HMAC of given message
 * @param message
 * @param message_length
 * @param key
 * @param key_size
 * @param output_HMAC
 */
void CreateHMAC_SHA256(uint8_t* message, uint16_t message_length, uint8_t* key, uint8_t key_size, SHA256_HASH* output_HMAC)
{
	SHA256_HASH hashed_key, hashed_inner_message, final_hash;

	uint8_t padding_size;

	uint8_t padded_key[SHA256_BLOCK_SIZE],
					outer_padded_key[SHA256_BLOCK_SIZE],
					inner_padded_key[SHA256_BLOCK_SIZE],
					inner_key_message[SHA256_BLOCK_SIZE + MAXIMUM_MESSAGE_SIZE],
					outer_hashed_key[SHA256_BLOCK_SIZE + SHA256_HASH_SIZE];


	uint8_t outer_padding[SHA256_BLOCK_SIZE] = {
			0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
			0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
			0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
			0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
			0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
			0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
			0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
			0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c
	};
	uint8_t inner_padding[SHA256_BLOCK_SIZE] = {
			0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
			0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
			0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
			0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
			0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
			0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
			0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
			0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36
	};

	if (key_size > SHA256_BLOCK_SIZE)
	{
		Sha256Calculate(key, key_size, &hashed_key);
		memcpy(padded_key, hashed_key.bytes, SHA256_HASH_SIZE);
		padding_size = SHA256_HASH_SIZE;
	}
	//If key length smaller than block size, padding with zeros
	else if (key_size < SHA256_BLOCK_SIZE)
	{
		memcpy(padded_key, key, key_size);
		for (int i = key_size; i < SHA256_BLOCK_SIZE; i++)
		{
			padded_key[i] = 0;
		}
		padding_size = SHA256_BLOCK_SIZE;
	}
	ArrayXOR(padded_key, outer_padding, padding_size, outer_padded_key);
	ArrayXOR(padded_key, inner_padding, padding_size, inner_padded_key);

	memcpy(inner_key_message, inner_padded_key, padding_size);
	memcpy(inner_key_message + padding_size, message, message_length);

	Sha256Calculate(inner_key_message, padding_size + message_length, &hashed_inner_message);

	memcpy(outer_hashed_key, outer_padded_key, padding_size);
	memcpy(outer_hashed_key + padding_size, hashed_inner_message.bytes, SHA256_HASH_SIZE);

	Sha256Calculate(outer_hashed_key, padding_size + SHA256_HASH_SIZE, output_HMAC);
}

/**
 * Update encrypted key by get first 128-bit of SHA256 (secret key || encrypt key || hint number)
 * @param secret_key: pointer to secret key		[in]
 * @param hint_number: pointer to hint number [in]
 * @param encrypt_key: pointer to encrypt key [in,out]
 */
void UpdateEncryptKey(uint8_t *secret_key, uint8_t *hint_number, uint8_t *encrypt_key)
{
	uint8_t temp_buff[SECRET_KEY_SIZE + ENCRYPT_KEY_SIZE + RANDOM_AUTHENTICATE_NUMBER_SIZE];
	SHA256_HASH sha256_digest;
	memcpy(temp_buff, secret_key , SECRET_KEY_SIZE);
	memcpy(temp_buff + SECRET_KEY_SIZE, encrypt_key, ENCRYPT_KEY_SIZE);
	memcpy(temp_buff + SECRET_KEY_SIZE + ENCRYPT_KEY_SIZE, hint_number, RANDOM_AUTHENTICATE_NUMBER_SIZE);
	Sha256Calculate(temp_buff, SECRET_KEY_SIZE + ENCRYPT_KEY_SIZE + RANDOM_AUTHENTICATE_NUMBER_SIZE, &sha256_digest);
	memcpy(encrypt_key, sha256_digest.bytes, ENCRYPT_KEY_SIZE);
}

/**
 * Update encrypted key and backup key from SHA512 digest of (secret key || back up key || hint number)
 * @param secret_key: pointer to secret key									[in]
 * @param reset_key_hint: pointer to reset key hint number 	[in]
 * @param backup_key: pointer to back up key								[in, out]
 * @param encrypt_key: pointer to encrypt key								[in, out]
 */
void ResetKeyUpdate(uint8_t *secret_key, uint8_t *reset_key_hint, uint8_t *backup_key, uint8_t *encrypt_key)
{
	uint8_t temp_buff[SECRET_KEY_SIZE + ENCRYPT_KEY_SIZE + RANDOM_AUTHENTICATE_NUMBER_SIZE];
	SHA512_HASH sha512_digest;
	memcpy(temp_buff, secret_key , SECRET_KEY_SIZE);
	memcpy(temp_buff + SECRET_KEY_SIZE, backup_key, ENCRYPT_KEY_SIZE);
	memcpy(temp_buff + SECRET_KEY_SIZE + ENCRYPT_KEY_SIZE, reset_key_hint, RANDOM_AUTHENTICATE_NUMBER_SIZE);
	Sha512Calculate(temp_buff, SECRET_KEY_SIZE + ENCRYPT_KEY_SIZE + RANDOM_AUTHENTICATE_NUMBER_SIZE, &sha512_digest);
	memcpy(encrypt_key, sha512_digest.bytes, ENCRYPT_KEY_SIZE);
	memcpy(backup_key, sha512_digest.bytes + ENCRYPT_KEY_SIZE, ENCRYPT_KEY_SIZE);
}

/************************
 * Define private APIs *
 ************************/

static void ArrayXOR(uint8_t* array1, uint8_t* array2, uint16_t length, uint8_t* output_array)
{
	for (int i = 0; i < length; i++)
	{
		output_array[i] = array1[i] ^ array2[i];
	}
}

static void PaddingNull(uint8_t* buffer_in_out, uint16_t input_length, uint16_t output_length)
{
    for (int i = input_length; i < output_length; i++)
    {
        buffer_in_out[i] = 0x00;
    }

}
#endif
