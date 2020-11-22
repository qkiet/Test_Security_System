/*
 * network_services.h
 *
 *  Created on: Nov 21, 2020
 *      Author: Tin
 */

#ifndef NETWORK_SERVICES_H_
#define NETWORK_SERVICES_H_
#include "lwip/sockets.h"
#include "crypto_services.h"
#include "main.h"

#define SECRET_KEY_SIZE SHA256_HASH_SIZE
#define MESSAGE_LENGTH_HEADER_SIZE 2
#define MESSAGE_COMMAND_ID_SIZE 2
#define TYPE_PAYLOAD_NORMAL 0x00
#define TYPE_PAYLOAD_RESEND 0x01

extern void InitSecuredNetworkService();
extern void RunSession(int accepted_conn);

#endif /* NETWORK_SERVICES_H_ */
