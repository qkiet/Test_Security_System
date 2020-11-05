/*
 * crypto_services.c
 *
 *  Created on: Oct 30, 2020
 *      Author: Tin
 */



#include "crypto_services.h"


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

/**
 * Initialize crypto service engine
 * @param AES_key: input AES Key [in]
 * @param AES_IV: input AES IV [in[
 */
int32_t Encrypt(uint8_t* plaintext, uint32_t plaintext_len, uint8_t* AES_key, uint8_t* AES_IV, uint8_t* ciphertext)
{
	AesCbcEncryptWithKey(AES_key, AES_KEY_SIZE_128, AES_IV, plaintext, ciphertext, plaintext_len);
}

int32_t Decrypt(uint8_t* ciphertext, uint16_t ciphertext_len, uint8_t* AES_key, uint8_t* AES_IV, uint8_t* decrypted_text)
{
	int32_t result;
	result = AesCbcDecryptWithKey(AES_key, AES_KEY_SIZE_128, AES_IV, ciphertext, decrypted_text, ciphertext_len);
	return result;
}
#endif
