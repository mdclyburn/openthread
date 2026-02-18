#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "common/message.hpp"
#include "net/socket.hpp"

#include <libtock/tock.h>
#include <libtock/crypto/isle.h>

#define ISLE_WORK_BUFFER_LEN ((uint32_t) 64)
extern uint8_t __isle_wbuf[ISLE_WORK_BUFFER_LEN];
extern uint8_t __isle_piv_buf[ISLE_PIV_BUFFER_LEN];
extern uint8_t __isle_host_buf[ISLE_SRC_BUFFER_LEN];
extern uint8_t __isle_obuf[ISLE_WORK_BUFFER_LEN];
extern uint8_t __isle_opts[ISLE_WORK_BUFFER_LEN];

// Mapping indicating class E options.
// E.g., is option 4, ETag, class E? g_coap_e_options & 4.
#define ISLE_COAP_CLASS_E_OPTIONS ((uint32_t) 0b010011101001101101001)

returncode_t
otIsleWaitForMessageReady(
	const uint32_t messageLength,
	const uint32_t aadLength,
	const bool is_encrypt);

uint32_t
otIsleGetOutMessageLength();

void
__otIsleFinishUdpSend(
	int messageLength,
	int arg1,
	int arg2,
	void* data);

returncode_t
otIslePrepareReceivedMessage(
	ot::Message& inMessage,
	const ot::Ip6::MessageInfo& inMessageInfo);
