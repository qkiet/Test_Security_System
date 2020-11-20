/* USER CODE BEGIN Header */
/**
  ******************************************************************************
  * @file           : main.c
  * @brief          : Main program body
  ******************************************************************************
  * @attention
  *
  * <h2><center>&copy; Copyright (c) 2020 STMicroelectronics.
  * All rights reserved.</center></h2>
  *
  * This software component is licensed by ST under BSD 3-Clause license,
  * the "License"; You may not use this file except in compliance with the
  * License. You may obtain a copy of the License at:
  *                        opensource.org/licenses/BSD-3-Clause
  *
  ******************************************************************************
  */
/* USER CODE END Header */

/* Includes ------------------------------------------------------------------*/
#include "main.h"
#include "cmsis_os.h"
#include "lwip.h"

/* Private includes ----------------------------------------------------------*/
/* USER CODE BEGIN Includes */
#include "lwip/sockets.h"
#include "api.h"
#include "crypto_services.h"
#include <string.h>
#include <stdbool.h>
/* USER CODE END Includes */

/* Private typedef -----------------------------------------------------------*/
/* USER CODE BEGIN PTD */

/* USER CODE END PTD */

/* Private define ------------------------------------------------------------*/
/* USER CODE BEGIN PD */
/* USER CODE END PD */

/* Private macro -------------------------------------------------------------*/
/* USER CODE BEGIN PM */
#define SEND_TIMEOUT 800
#define RECEIVE_TIMEOUT 800
#define IS_ERROR(status) (status <= 0)

/* USER CODE END PM */

/* Private variables ---------------------------------------------------------*/
RNG_HandleTypeDef hrng;

osThreadId defaultTaskHandle;
/* USER CODE BEGIN PV */
extern struct netif gnetif;
uint8_t cipher_key[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
uint8_t cipher_IV[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
uint8_t PDU_password[PASSWORD_LENGTH] = "HelloWorld";
uint8_t first_random_salt[32] =
{
		0xcc, 0x5b, 0xdf, 0x8b, 0x8a, 0x14, 0x9b, 0x9d,
		0xc7, 0x52, 0x23, 0x2f, 0x2b, 0x09, 0x03, 0x39,
		0x66, 0x7e, 0xfa, 0x6f, 0x12, 0x8e, 0x13, 0xa5,
		0x51, 0x78, 0x00, 0x61, 0x46, 0x60, 0x59, 0xe6
};
uint8_t second_random_salt[32] =
{
		0xaa, 0xc4, 0x59, 0xa4, 0x63, 0x57, 0xa1, 0x70,
		0x79, 0xad, 0x1c, 0x46, 0xf7, 0xc1, 0x63, 0x86,
		0x68, 0x83, 0xcf, 0xe1, 0x36, 0xaa, 0x7d, 0x27,
		0x7f, 0xef, 0x6a, 0x0f, 0xe3, 0xcd, 0x03, 0x25
};
uint8_t sending_to_client[1024];
osThreadId TCPservice_id;


uint8_t secret_key[SHA256_HASH_SIZE];
/* USER CODE END PV */

/* Private function prototypes -----------------------------------------------*/
void SystemClock_Config(void);
static void MX_GPIO_Init(void);
static void MX_RNG_Init(void);
void StartDefaultTask(void const * argument);

/* USER CODE BEGIN PFP */
static void Thread_TestService(void const * argument);
static void RunSession(int accepted_conn);
static int ProcessCommand(uint8_t* command, uint16_t command_length);
static void TurnOnLed1();
/* USER CODE END PFP */

/* Private user code ---------------------------------------------------------*/
/* USER CODE BEGIN 0 */

/* USER CODE END 0 */

/**
  * @brief  The application entry point.
  * @retval int
  */
int main(void)
{
  /* USER CODE BEGIN 1 */

  /* USER CODE END 1 */

  /* MCU Configuration--------------------------------------------------------*/

  /* Reset of all peripherals, Initializes the Flash interface and the Systick. */
  HAL_Init();

  /* USER CODE BEGIN Init */

  /* USER CODE END Init */

  /* Configure the system clock */
  SystemClock_Config();

  /* USER CODE BEGIN SysInit */

  /* USER CODE END SysInit */

  /* Initialize all configured peripherals */
  MX_GPIO_Init();
  MX_RNG_Init();
  /* USER CODE BEGIN 2 */

  /* USER CODE END 2 */

  /* USER CODE BEGIN RTOS_MUTEX */
  /* add mutexes, ... */
  /* USER CODE END RTOS_MUTEX */

  /* USER CODE BEGIN RTOS_SEMAPHORES */
  /* add semaphores, ... */
  /* USER CODE END RTOS_SEMAPHORES */

  /* USER CODE BEGIN RTOS_TIMERS */
  /* start timers, add new ones, ... */
  /* USER CODE END RTOS_TIMERS */

  /* USER CODE BEGIN RTOS_QUEUES */
  /* add queues, ... */
  /* USER CODE END RTOS_QUEUES */

  /* Create the thread(s) */
  /* definition and creation of defaultTask */
  osThreadDef(defaultTask, StartDefaultTask, osPriorityNormal, 0, 1024);
  defaultTaskHandle = osThreadCreate(osThread(defaultTask), NULL);

  /* USER CODE BEGIN RTOS_THREADS */
  /* add threads, ... */
  /* USER CODE END RTOS_THREADS */

  /* Start scheduler */
  osKernelStart();
 
  /* We should never get here as control is now taken by the scheduler */
  /* Infinite loop */
  /* USER CODE BEGIN WHILE */
  while (1)
  {
    /* USER CODE END WHILE */

    /* USER CODE BEGIN 3 */
  }
  /* USER CODE END 3 */
}

/**
  * @brief System Clock Configuration
  * @retval None
  */
void SystemClock_Config(void)
{
  RCC_OscInitTypeDef RCC_OscInitStruct = {0};
  RCC_ClkInitTypeDef RCC_ClkInitStruct = {0};

  /** Configure the main internal regulator output voltage 
  */
  __HAL_RCC_PWR_CLK_ENABLE();
  __HAL_PWR_VOLTAGESCALING_CONFIG(PWR_REGULATOR_VOLTAGE_SCALE1);
  /** Initializes the CPU, AHB and APB busses clocks 
  */
  RCC_OscInitStruct.OscillatorType = RCC_OSCILLATORTYPE_HSE;
  RCC_OscInitStruct.HSEState = RCC_HSE_ON;
  RCC_OscInitStruct.PLL.PLLState = RCC_PLL_ON;
  RCC_OscInitStruct.PLL.PLLSource = RCC_PLLSOURCE_HSE;
  RCC_OscInitStruct.PLL.PLLM = 4;
  RCC_OscInitStruct.PLL.PLLN = 168;
  RCC_OscInitStruct.PLL.PLLP = RCC_PLLP_DIV2;
  RCC_OscInitStruct.PLL.PLLQ = 7;
  if (HAL_RCC_OscConfig(&RCC_OscInitStruct) != HAL_OK)
  {
    Error_Handler();
  }
  /** Initializes the CPU, AHB and APB busses clocks 
  */
  RCC_ClkInitStruct.ClockType = RCC_CLOCKTYPE_HCLK|RCC_CLOCKTYPE_SYSCLK
                              |RCC_CLOCKTYPE_PCLK1|RCC_CLOCKTYPE_PCLK2;
  RCC_ClkInitStruct.SYSCLKSource = RCC_SYSCLKSOURCE_PLLCLK;
  RCC_ClkInitStruct.AHBCLKDivider = RCC_SYSCLK_DIV1;
  RCC_ClkInitStruct.APB1CLKDivider = RCC_HCLK_DIV4;
  RCC_ClkInitStruct.APB2CLKDivider = RCC_HCLK_DIV2;

  if (HAL_RCC_ClockConfig(&RCC_ClkInitStruct, FLASH_LATENCY_5) != HAL_OK)
  {
    Error_Handler();
  }
}

/**
  * @brief RNG Initialization Function
  * @param None
  * @retval None
  */
static void MX_RNG_Init(void)
{

  /* USER CODE BEGIN RNG_Init 0 */

  /* USER CODE END RNG_Init 0 */

  /* USER CODE BEGIN RNG_Init 1 */

  /* USER CODE END RNG_Init 1 */
  hrng.Instance = RNG;
  if (HAL_RNG_Init(&hrng) != HAL_OK)
  {
    Error_Handler();
  }
  /* USER CODE BEGIN RNG_Init 2 */

  /* USER CODE END RNG_Init 2 */

}

/**
  * @brief GPIO Initialization Function
  * @param None
  * @retval None
  */
static void MX_GPIO_Init(void)
{
  GPIO_InitTypeDef GPIO_InitStruct = {0};

  /* GPIO Ports Clock Enable */
  __HAL_RCC_GPIOH_CLK_ENABLE();
  __HAL_RCC_GPIOC_CLK_ENABLE();
  __HAL_RCC_GPIOA_CLK_ENABLE();
  __HAL_RCC_GPIOB_CLK_ENABLE();
  __HAL_RCC_GPIOE_CLK_ENABLE();

  /*Configure GPIO pin Output Level */
  HAL_GPIO_WritePin(GPIOE, LED_1_Pin|LED_2_Pin, GPIO_PIN_RESET);

  /*Configure GPIO pins : LED_1_Pin LED_2_Pin */
  GPIO_InitStruct.Pin = LED_1_Pin|LED_2_Pin;
  GPIO_InitStruct.Mode = GPIO_MODE_OUTPUT_PP;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_LOW;
  HAL_GPIO_Init(GPIOE, &GPIO_InitStruct);

}

/* USER CODE BEGIN 4 */

static void TurnOnLed1()
{
	HAL_GPIO_WritePin(LED_1_GPIO_Port, LED_1_Pin, SET);
}

static void TurnOnLed2()
{
	HAL_GPIO_WritePin(LED_2_GPIO_Port, LED_2_Pin, SET);
}

static void TurnOffLed1()
{
	HAL_GPIO_WritePin(LED_1_GPIO_Port, LED_1_Pin, RESET);
}

static void TurnOffLed2()
{
	HAL_GPIO_WritePin(LED_2_GPIO_Port, LED_2_Pin, RESET);
}

static void ToggleLed1()
{
	HAL_GPIO_TogglePin(LED_1_GPIO_Port, LED_1_Pin);
}

static void ToggleLed2()
{
	HAL_GPIO_TogglePin(LED_2_GPIO_Port, LED_2_Pin);
}

/**
 * Process incoming command
 * @param command: pointer to command buffer [in]
 * @param command_length: length of command buffer [in]
 * @return 1 if command is STATUS, 0 otherwise
 */
static int ProcessCommand(uint8_t* command, uint16_t command_length)
{
  typedef struct {
      char command_text[20];
      void (*command)();
  } pdu_command;
  uint8_t total_number_of_commands = 7;
  pdu_command commands_list[7] =
  {
      {
          "TURN ON 1",
      		&TurnOnLed1
      },
      {
          "TURN ON 2",
					&TurnOnLed2

      },
      {
          "TURN OFF 1",
					&TurnOffLed1
      },
      {
          "TURN OFF 2",
					&TurnOffLed2
      },
      {
          "TOGGLE 1",
					&ToggleLed1
      },
      {
          "TOGGLE 2",
					&ToggleLed2
      },
      {
          "STATUS"
      }
  };
	//Just a lot of strncmp
	for (int i = 0; i < total_number_of_commands - 1; i++)
	{
		if (strncmp((char*)command, (char*)commands_list[i].command_text, command_length) == 0)
		{
			commands_list[i].command();
			return 0;
		}
	}

	//If this is STATUS command
	if (strncmp((char*)command, (char*)commands_list[total_number_of_commands - 1].command_text, command_length) == 0)
	{
		return 1;
	}

	return -1;
}


static void RunSession(int accepted_conn)
{
	uint8_t send_buff[1060],
					receive_buff[1060],
					secret_random_concate[48],
					session_encrypt_key[AES_KEY_SIZE_128],
					session_old_encrypt_key[AES_KEY_SIZE_128],
					session_encrypt_iv[AES_CTR_IV_SIZE],
					session_backup_key[AES_KEY_SIZE_128],
					temp_buff[1060],
					old_send_buff[1060],
					random_authenticate_number[RANDOM_AUTHENTICATE_NUMBER_SIZE],
					next_encrypt_key_hint[RANDOM_AUTHENTICATE_NUMBER_SIZE];
	uint32_t original_send_buff_length;
	SHA256_HASH sha256_digest;
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

	status = read(accepted_conn, receive_buff, 64);
	if (!IS_ERROR(status))
	{
		memcpy(sha256_digest.bytes, receive_buff, SHA256_HASH_SIZE);
		//Receive correct HMAC
		if (CompareHMAC_SHA256(	receive_buff + SHA256_HASH_SIZE,
														32,
														secret_key,
														SECRET_KEY_SIZE,
														sha256_digest))
		{
			//Correct "REQUEST" message
			if (strncmp(receive_buff + SHA256_HASH_SIZE + 2, "REQUEST", 7) == 0)
			{
				//Get message size in REQUEST message
				message_size = (uint16_t)*(receive_buff + SHA256_HASH_SIZE + 9);

				RNGBigNumber(RANDOM_AUTHENTICATE_NUMBER_SIZE, random_authenticate_number);

				//Send the random number first, so that GUI can calculate immediately
				snprintf(temp_buff, 3, "OK");
				memcpy(temp_buff + 2, &random_authenticate_number, sizeof(random_authenticate_number));
				PrepareSendingBuffer(secret_key, 32, NULL, temp_buff, 2+RANDOM_AUTHENTICATE_NUMBER_SIZE, message_size, true, false, send_buff);
				status = write(accepted_conn, send_buff, message_size + HMAC_SIZE);

				if (!IS_ERROR(status))
				{
					//Then calculate session parameters like encrypt key, encrypt iv, command key and backup key
					memcpy(secret_random_concate, secret_key, SHA256_HASH_SIZE);
					memcpy(secret_random_concate + SHA256_HASH_SIZE, random_authenticate_number, 16);
					SHA512_HASH hashed_session_secret;
					Sha512Calculate(secret_random_concate, 48, &hashed_session_secret);
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
		original_send_buff_length = 0;
		status = read(accepted_conn, receive_buff, message_size + HMAC_SIZE);
		if (!IS_ERROR(status))
		{
			memcpy(sha256_digest.bytes, receive_buff, SHA256_HASH_SIZE);
			//Valid HMAC
			if (CompareHMAC_SHA256(	receive_buff + HMAC_SIZE,
															message_size,
															session_encrypt_key,
															AES_KEY_SIZE_128,
															sha256_digest))
			{
				//Decrypt into actual payload, beginning from 2 byte of payload length
				Encrypt(receive_buff + HMAC_SIZE, message_size, session_encrypt_key, session_encrypt_iv, temp_buff);

				//Send back to GUI along with next_encrypt_key_hint
				status = ProcessCommand(temp_buff + 2, (uint16_t)(*temp_buff));
				if (status == 1)
				{
					///@todo: send LED status back to GUI
					///
					snprintf(temp_buff + RANDOM_AUTHENTICATE_NUMBER_SIZE, 19, "LED_1: %d; LED_2: %d", HAL_GPIO_ReadPin(LED_1_GPIO_Port, LED_1_Pin), HAL_GPIO_ReadPin(LED_2_GPIO_Port, LED_2_Pin));
					original_send_buff_length += 18;
				}
				else if (status == 0)
				{
					///@todo: send command status GUI


					snprintf(temp_buff + RANDOM_AUTHENTICATE_NUMBER_SIZE, 4, "ACK");
					original_send_buff_length += 3;
				}
				else
				{
					temp_buff[0] = 0;
				}
				//Generate next command key

				RNGBigNumber(RANDOM_AUTHENTICATE_NUMBER_SIZE, next_encrypt_key_hint);
				memcpy(temp_buff, next_encrypt_key_hint, RANDOM_AUTHENTICATE_NUMBER_SIZE);
				original_send_buff_length += RANDOM_AUTHENTICATE_NUMBER_SIZE;
				PrepareSendingBuffer(session_encrypt_key, AES_KEY_SIZE_128, session_encrypt_iv, temp_buff, original_send_buff_length, message_size, true, true, send_buff);
				PrepareSendingBuffer(session_encrypt_key, AES_KEY_SIZE_128, session_encrypt_iv, temp_buff, original_send_buff_length, message_size, false, false, old_send_buff);
				status = write(accepted_conn, send_buff, message_size + HMAC_SIZE);

				if (!IS_ERROR(status))
				{
					//Update new key
					memcpy(session_old_encrypt_key, session_encrypt_key, AES_KEY_SIZE_128);
//					memcpy(temp_buff, temp_buff + 2, RANDOM_AUTHENTICATE_NUMBER_SIZE);
					memcpy(temp_buff + RANDOM_AUTHENTICATE_NUMBER_SIZE, session_encrypt_key, AES_KEY_SIZE_128);
					Sha256Calculate(temp_buff, RANDOM_AUTHENTICATE_NUMBER_SIZE + AES_KEY_SIZE_128, &sha256_digest);
					memcpy(session_encrypt_key, sha256_digest.bytes, AES_KEY_SIZE_128);


				}
				//Something wrong with socket, close connection now
				else
				{
					break;
				}
			}

			//Time for Key Repair Routine
			else
			{
				///@todo: add Key Repair Routine here
				Encrypt(send_buff + HMAC_SIZE, message_size, session_old_encrypt_key, session_encrypt_iv, temp_buff);
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


static void Thread_TestService(void const * argument)
{
  int sock, newconn, size;
  struct sockaddr_in address, remotehost;

 /* create a TCP socket */
  sock = socket(AF_INET, SOCK_STREAM, 0);

  /* bind to port 80 at any interface */
  address.sin_family = AF_INET;
  address.sin_port = htons(7);
  address.sin_addr.s_addr = INADDR_ANY;

  bind(sock, (struct sockaddr *)&address, sizeof (address));

  /* listen for incoming connections (TCP listen backlog = 1) */
  listen(sock, 1);
  size = sizeof(remotehost);
  while (1)
	{
		newconn = accept(sock, (struct sockaddr *)&remotehost, (socklen_t *)&size);
		RunSession(newconn);
		close(newconn);
	}


	//Netconn
//	err_t err, accept_err, recv_err;
//	struct netbuf *receive_buffer_ptr;
//	uint16_t data_receive_len;
//
//	struct netconn *server_conn, *accepted_conn;
//
//	char receive_buffer[1024];
//
//	//Setup server and binding port
//
//	int Result;
//
//
//	server_conn = netconn_new(NETCONN_TCP);
//	netconn_bind(server_conn, NULL, 7);
//	netconn_listen(server_conn);
//	while(1) //Serve TCP service forever
//	{
//		accept_err = netconn_accept(server_conn, &accepted_conn);// This will block this thread until a TCP SYN packet arrive.
//		if (accept_err == ERR_OK)
//		{
//
//			recv_err = netconn_recv(accepted_conn, &receive_buffer_ptr);
//
//			//There is data in receive buffer.
//			if (recv_err == ERR_OK)
//			{
//
//				data_receive_len = netbuf_len(receive_buffer_ptr);
//				netbuf_copy(receive_buffer_ptr, (void*)receive_buffer, data_receive_len);
//				netbuf_delete(receive_buffer_ptr);
//				//Announce message. Format is: (session_type)_(message_size)_(transaction_length)
//				//real message size  = 16 * 4 ^(message_size)
//				//real transaction length = (transaction_length + 1)*2
//				switch (receive_buffer[0] - 48)
//				{
//				case 0:
//					RunSession(accepted_conn, receive_buffer[2] - 48, false);
//				default:
//					RunSession(accepted_conn, receive_buffer[2] - 48, true);
//				}
//
//
//			}
//			netconn_close(accepted_conn);
//			netconn_delete(accepted_conn);
//		}
//	}
}
/* USER CODE END 4 */

/* USER CODE BEGIN Header_StartDefaultTask */
/**
  * @brief  Function implementing the defaultTask thread.
  * @param  argument: Not used
  * @retval None
  */
/* USER CODE END Header_StartDefaultTask */
void StartDefaultTask(void const * argument)
{
  /* init code for LWIP */
  MX_LWIP_Init();
  /* USER CODE BEGIN 5 */
  /* Infinite loop */

  uint8_t encrypted_key[AES_KEY_SIZE_128] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14 ,15};
  uint8_t encrypted_iv[AES_KEY_SIZE_128] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14 ,15};

  uint8_t test_data[36] =
  { 0, 1, 2, 3, 4, 0, 0, 7, 8, 9, 10, 11, 12, 13, 0, 15, 16, 17,
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 0, 14, 15, 16, 17 };
  uint8_t test_data_2[36] =
  { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17,
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17 };
  uint8_t temp[36], decrypted[36];

  Encrypt(test_data, 36, encrypted_key, encrypted_iv, temp);
  Encrypt(temp, 36, encrypted_key, encrypted_iv, decrypted);

  Encrypt(test_data_2, 36, encrypted_key, encrypted_iv, temp);
  Encrypt(temp, 36, encrypted_key, encrypted_iv, decrypted);



  uint32_t heap_size;
  SHA256_HASH hashed_salted_password;
  uint8_t salted_string[64 + PASSWORD_LENGTH];
  //Prepare secret key
  memcpy(salted_string, first_random_salt, 32);
  memcpy(salted_string + SHA256_HASH_SIZE, PDU_password, PASSWORD_LENGTH);
  memcpy(salted_string + SHA256_HASH_SIZE + PASSWORD_LENGTH, second_random_salt, 32);
  Sha256Calculate(salted_string, 64 + PASSWORD_LENGTH, &hashed_salted_password);
  memcpy(secret_key, hashed_salted_password.bytes, SHA256_HASH_SIZE);

  for (;;)
  {
  	if (gnetif.ip_addr.addr != 0)
  	{
  		TCPservice_id = sys_thread_new("TestService", (void*) Thread_TestService, NULL, 3000, osPriorityAboveNormal);
  		break;
  	}
  }


  for(;;)
  {
    osDelay(500);
    heap_size = xPortGetFreeHeapSize();
  }
  /* USER CODE END 5 */ 
}

 /**
  * @brief  Period elapsed callback in non blocking mode
  * @note   This function is called  when TIM1 interrupt took place, inside
  * HAL_TIM_IRQHandler(). It makes a direct call to HAL_IncTick() to increment
  * a global variable "uwTick" used as application time base.
  * @param  htim : TIM handle
  * @retval None
  */
void HAL_TIM_PeriodElapsedCallback(TIM_HandleTypeDef *htim)
{
  /* USER CODE BEGIN Callback 0 */

  /* USER CODE END Callback 0 */
  if (htim->Instance == TIM1) {
    HAL_IncTick();
  }
  /* USER CODE BEGIN Callback 1 */

  /* USER CODE END Callback 1 */
}

/**
  * @brief  This function is executed in case of error occurrence.
  * @retval None
  */
void Error_Handler(void)
{
  /* USER CODE BEGIN Error_Handler_Debug */
  /* User can add his own implementation to report the HAL error return state */

  /* USER CODE END Error_Handler_Debug */
}

#ifdef  USE_FULL_ASSERT
/**
  * @brief  Reports the name of the source file and the source line number
  *         where the assert_param error has occurred.
  * @param  file: pointer to the source file name
  * @param  line: assert_param error line source number
  * @retval None
  */
void assert_failed(uint8_t *file, uint32_t line)
{ 
  /* USER CODE BEGIN 6 */
  /* User can add his own implementation to report the file name and line number,
     tex: printf("Wrong parameters value: file %s on line %d\r\n", file, line) */
  /* USER CODE END 6 */
}
#endif /* USE_FULL_ASSERT */

/************************ (C) COPYRIGHT STMicroelectronics *****END OF FILE****/
