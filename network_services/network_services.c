/*
 * network_services.c
 *
 *  Created on: Nov 21, 2020
 *      Author: Tin
 */
#include "network_services.h"

#define IS_ERROR(status) (status <= 0)


static uint8_t PDU_password[PASSWORD_LENGTH] = "HelloWorld";
static uint8_t first_random_salt[32] =
{
		0xcc, 0x5b, 0xdf, 0x8b, 0x8a, 0x14, 0x9b, 0x9d,
		0xc7, 0x52, 0x23, 0x2f, 0x2b, 0x09, 0x03, 0x39,
		0x66, 0x7e, 0xfa, 0x6f, 0x12, 0x8e, 0x13, 0xa5,
		0x51, 0x78, 0x00, 0x61, 0x46, 0x60, 0x59, 0xe6
};
static uint8_t second_random_salt[32] =
{
		0xaa, 0xc4, 0x59, 0xa4, 0x63, 0x57, 0xa1, 0x70,
		0x79, 0xad, 0x1c, 0x46, 0xf7, 0xc1, 0x63, 0x86,
		0x68, 0x83, 0xcf, 0xe1, 0x36, 0xaa, 0x7d, 0x27,
		0x7f, 0xef, 0x6a, 0x0f, 0xe3, 0xcd, 0x03, 0x25
};
static uint8_t secret_key[SHA256_HASH_SIZE];

void InitSecuredNetworkService()
{
  SHA256_HASH hashed_salted_password;
  uint8_t salted_string[64 + PASSWORD_LENGTH];
  //Prepare secret key
  memcpy(salted_string, first_random_salt, 32);
  memcpy(salted_string + 32, PDU_password, strlen((char*)PDU_password));
  memcpy(salted_string + 32 + strlen((char*)PDU_password), second_random_salt, 32);
  Sha256Calculate(salted_string, 64 + strlen((char*)PDU_password), &hashed_salted_password);
  memcpy(secret_key, hashed_salted_password.bytes, SHA256_HASH_SIZE);
}

void RunSession(int accepted_conn)
{
	uint8_t send_buff[1060],
					receive_buff[1060],
					temp_buff[1060],
					cached_response[1060],
					response_to_GUI[1060],
					secret_random_concate[48],
					session_encrypt_key[AES_KEY_SIZE_128],
					session_old_encrypt_key[AES_KEY_SIZE_128],
					session_encrypt_iv[AES_CTR_IV_SIZE],
					session_backup_key[AES_KEY_SIZE_128],
					random_authenticate_number[RANDOM_AUTHENTICATE_NUMBER_SIZE],
					next_encrypt_key_hint[RANDOM_AUTHENTICATE_NUMBER_SIZE];
	uint16_t cached_response_length, response_length, expected_command_id = 0, received_command_id, sending_command_id;
	SHA256_HASH sha256_digest;
	bool is_wait_for_resend = false;
	int status;

  struct timeval send_timeout =
  {
  		15, //seconds
			800000, // miliseconds
  };
  struct timeval receive_timeout =
  {
  		15,
			800000, //800 miliseconds
  };
  setsockopt(accepted_conn, SOL_SOCKET, SO_SNDTIMEO, (const char*)&send_timeout, sizeof(send_timeout));
  setsockopt(accepted_conn, SOL_SOCKET, SO_RCVTIMEO, (const char*)&receive_timeout, sizeof(receive_timeout));
	uint16_t message_size;


	//Wait for Authentication Phase from GUI
	status = read(accepted_conn, receive_buff, 64 + HMAC_SIZE);
	if (!IS_ERROR(status))
	{
		memcpy(sha256_digest.bytes, receive_buff, SHA256_HASH_SIZE);
		//Receive correct HMAC
		if (CompareHMAC_SHA256(	receive_buff + HMAC_SIZE,
														64,
														secret_key,
														SECRET_KEY_SIZE,
														sha256_digest))
		{
			//Correct "REQUEST" message
			if (strncmp((char*)(receive_buff + SHA256_HASH_SIZE + MESSAGE_LENGTH_HEADER_SIZE + MESSAGE_COMMAND_ID_SIZE), "REQUEST", 7) == 0)
			{
				//Get message size in REQUEST message
				message_size = (uint16_t)*(receive_buff + SHA256_HASH_SIZE + MESSAGE_LENGTH_HEADER_SIZE + MESSAGE_COMMAND_ID_SIZE + strlen("REQUEST"));
				RNGBigNumber(RANDOM_AUTHENTICATE_NUMBER_SIZE, random_authenticate_number);

				//Send the random number first, so that GUI can calculate immediately
				snprintf((char*)temp_buff, 3, "OK");
				memcpy(temp_buff + strlen("OK"), &random_authenticate_number, sizeof(random_authenticate_number));
				PrepareSendingBuffer(
						secret_key,
						SECRET_KEY_SIZE,
						NULL,
						temp_buff,
						strlen("OK")+RANDOM_AUTHENTICATE_NUMBER_SIZE,
						message_size,
						true,
						false,
						expected_command_id,
						send_buff);
				status = write(accepted_conn, send_buff, message_size + HMAC_SIZE);

				if (!IS_ERROR(status))
				{
					//Then calculate session parameters like encrypt key, encrypt iv, command key and backup key
					//usE SHA512(secret key || authentication number)
					memcpy(secret_random_concate, secret_key, SHA256_HASH_SIZE);
					memcpy(secret_random_concate + SHA256_HASH_SIZE, random_authenticate_number, RANDOM_AUTHENTICATE_NUMBER_SIZE);
					SHA512_HASH hashed_session_secret;
					Sha512Calculate(secret_random_concate, SHA256_HASH_SIZE + RANDOM_AUTHENTICATE_NUMBER_SIZE, &hashed_session_secret);
					memcpy(session_encrypt_key, hashed_session_secret.bytes, AES_KEY_SIZE_128);
					memcpy(session_backup_key, hashed_session_secret.bytes + AES_KEY_SIZE_128, AES_KEY_SIZE_128);
					memcpy(session_encrypt_iv,  secret_key, AES_CTR_IV_SIZE / 2);
					memcpy(session_encrypt_iv + AES_CTR_IV_SIZE / 2,  session_encrypt_key, AES_CTR_IV_SIZE / 2);


					//Wait for encrypted ACK
					status = read(accepted_conn, receive_buff, message_size + HMAC_SIZE);
					if (!IS_ERROR(status))
					{
						memcpy(sha256_digest.bytes, receive_buff, HMAC_SIZE);
						if (CompareHMAC_SHA256(	receive_buff + HMAC_SIZE,
																		message_size,
																		session_encrypt_key,
																		AES_KEY_SIZE_128,
																		sha256_digest))
						{
							Decrypt(receive_buff + HMAC_SIZE, message_size, session_encrypt_key, session_encrypt_iv, temp_buff);
							goto SESSION_BEGIN;
						}
					}
				}
			}
		}
	}
	goto SESSION_END;


SESSION_BEGIN:
	while (1)
	{
		response_length = 0;
		status = read(accepted_conn, receive_buff, message_size + HMAC_SIZE);
		if (!IS_ERROR(status))
		{
			memcpy(sha256_digest.bytes, receive_buff, SHA256_HASH_SIZE);

			//Valid HMAC with encrypt key
			if (CompareHMAC_SHA256(	receive_buff + HMAC_SIZE,
															message_size,
															session_encrypt_key,
															AES_KEY_SIZE_128,
															sha256_digest))
			{
				//Generate next encrypt key hint
				RNGBigNumber(RANDOM_AUTHENTICATE_NUMBER_SIZE, next_encrypt_key_hint);
				memcpy(response_to_GUI, next_encrypt_key_hint, RANDOM_AUTHENTICATE_NUMBER_SIZE);
				response_length += RANDOM_AUTHENTICATE_NUMBER_SIZE;

				//Decrypt into actual payload, beginning from 2 byte of payload length
				Encrypt(receive_buff + HMAC_SIZE, message_size, session_encrypt_key, session_encrypt_iv, temp_buff);

				//Prepare for response according to command

				received_command_id = (uint16_t)*(temp_buff + MESSAGE_LENGTH_HEADER_SIZE);

				//Receive command id is equal to expected command id. Execute command and send back response
				if (received_command_id == expected_command_id)
				{
					is_wait_for_resend = false;
					//Send back to GUI along with next_encrypt_key_hint
					status = ProcessCommand(temp_buff + MESSAGE_LENGTH_HEADER_SIZE + MESSAGE_COMMAND_ID_SIZE, (uint16_t)(*temp_buff));
					if (status == 1)
					{
						snprintf((char*)(response_to_GUI + RANDOM_AUTHENTICATE_NUMBER_SIZE), 19, "LED_1: %d; LED_2: %d", HAL_GPIO_ReadPin(LED_1_GPIO_Port, LED_1_Pin), HAL_GPIO_ReadPin(LED_2_GPIO_Port, LED_2_Pin));
						response_length += 18;
						cached_response_length = 18;
					}
					else if (status == 0)
					{
						snprintf((char*)(response_to_GUI + RANDOM_AUTHENTICATE_NUMBER_SIZE), 4, "ACK");
						response_length += 3;
						cached_response_length = 3;
					}
					else
					{
						response_to_GUI[0] = 0;
					}

					//Update cached response before encrypt
					memcpy(cached_response, response_to_GUI + RANDOM_AUTHENTICATE_NUMBER_SIZE, cached_response_length);
					sending_command_id = expected_command_id;
					expected_command_id++;

				}

				//Receive command id is less than expected command id. only send back cacded response
				else if (received_command_id < expected_command_id)
				{
						memcpy(response_to_GUI, cached_response, cached_response_length);
						response_length += cached_response_length;
						sending_command_id = expected_command_id - 1;
				}

				//Receive command id is greater than expected command id. This is insane! Defy Monitor and Control System logic
				//Terminate connection immediately
				else
				{
					break;
				}

				//Then encrypt response, append HMAC and send
				PrepareSendingBuffer(
						session_encrypt_key,
						AES_KEY_SIZE_128,
						session_encrypt_iv,
						response_to_GUI,
						response_length,
						message_size,
						true,
						true,
						sending_command_id,
						send_buff);
				status = write(accepted_conn, send_buff, message_size + HMAC_SIZE);
				//Connection problem, close connection now
				if (IS_ERROR(status))
				{
					break;
				}
				UpdateEncryptKey(secret_key, next_encrypt_key_hint, session_encrypt_key);
			}


			//Valid HMAC with backup key. Time out Reset Key Routine
			else if (CompareHMAC_SHA256(receive_buff + HMAC_SIZE,
					message_size,
					session_backup_key,
					AES_KEY_SIZE_128,
					sha256_digest))
			{
				//Decrypt payload
				Encrypt(send_buff + HMAC_SIZE, message_size, session_old_encrypt_key, session_encrypt_iv, temp_buff);

				//Check if this really is Reset Key Routine Request from GUI
				if (strncmp((char*)(temp_buff + MESSAGE_LENGTH_HEADER_SIZE + MESSAGE_COMMAND_ID_SIZE), "ResetKey", 8) == 0)
				{
					is_wait_for_resend = false;
					//Generate next reset key hint
					uint8_t reset_key_hint[RANDOM_AUTHENTICATE_NUMBER_SIZE];
					RNGBigNumber(RANDOM_AUTHENTICATE_NUMBER_SIZE, reset_key_hint);
					memcpy(response_to_GUI, reset_key_hint, RANDOM_AUTHENTICATE_NUMBER_SIZE);
					snprintf((char*)(response_to_GUI + RANDOM_AUTHENTICATE_NUMBER_SIZE), 3, "OK");
					response_length = RANDOM_AUTHENTICATE_NUMBER_SIZE + 2;

					//Then encrypt response, append HMAC and send
					PrepareSendingBuffer(
							session_backup_key,
							AES_KEY_SIZE_128,
							session_encrypt_iv,
							response_to_GUI,
							response_length,
							message_size,
							true,
							true,
							TYPE_PAYLOAD_NORMAL,
							send_buff);
					status = write(accepted_conn, send_buff, message_size + HMAC_SIZE);
					//Connection problem, close connection now
					if (IS_ERROR(status))
					{
						break;
					}
					//Then update encrypt key and backup key
					ResetKeyUpdate(secret_key, reset_key_hint, session_backup_key, session_encrypt_key);

				}
			}

			//Invalid command, send NAK
			else
			{
				//Generate next encrypt key hint
				RNGBigNumber(RANDOM_AUTHENTICATE_NUMBER_SIZE, next_encrypt_key_hint);
				memcpy(response_to_GUI, next_encrypt_key_hint, RANDOM_AUTHENTICATE_NUMBER_SIZE);
				response_length += RANDOM_AUTHENTICATE_NUMBER_SIZE;
				snprintf((char*)(response_to_GUI + RANDOM_AUTHENTICATE_NUMBER_SIZE), 4, "NAK");
				response_length += 3;
				//Then encrypt response, append HMAC and send
				PrepareSendingBuffer(
						session_encrypt_key,
						AES_KEY_SIZE_128,
						session_encrypt_iv,
						response_to_GUI,
						response_length,
						message_size,
						true,
						true,
						TYPE_PAYLOAD_NORMAL,
						send_buff);
				status = write(accepted_conn, send_buff, message_size + HMAC_SIZE);
				//Connection problem, close connection now
				if (IS_ERROR(status))
				{
					break;
				}
				UpdateEncryptKey(secret_key, next_encrypt_key_hint, session_encrypt_key);
			}
		}
		//Timeout or connection terminated
		else
		{
			break;
		}
	}



SESSION_END:
	return;



//	err_t recv_err;
//	uint16_t real_message_size;
//	uint8_t sending_ciphertext[1024];
//
//	uint8_t decrypted_buff[1024];
//	struct netbuf *receive_netbuf;
//	switch (message_size)
//	{
//	case 0:
//		real_message_size = 64;
//		break;
//	case 1:
//		real_message_size = 256;
//		break;
//	default:
//		real_message_size = 1024;
//	}
//	while (1)
//	{
//
//		recv_err = netconn_recv(received_conn, &receive_netbuf);
//
//		//If receive data successfully
//		if (recv_err == ERR_OK)
//		{
//
//			netbuf_copy(receive_netbuf, receive_buff, real_message_size);
//			netbuf_delete(receive_netbuf);
//			if (is_encrypted)
//			{
//				Decrypt(receive_buff, real_message_size, cipher_key, cipher_IV, decrypted_buff);
//
//			  Encrypt(sending_to_client, real_message_size, cipher_key, cipher_IV, sending_ciphertext);
//				if (netconn_write(received_conn, sending_ciphertext, real_message_size, NETCONN_COPY) != ERR_OK)
//				{
//					break;
//				}
//			}
//			else
//			{
//				if (netconn_write(received_conn, sending_to_client, real_message_size, NETCONN_COPY) != ERR_OK)
//				{
//					break;
//				}
//			}
//
//		}
//		//Close fin
//		else
//		{
//			break;
//		}
//	}


}
