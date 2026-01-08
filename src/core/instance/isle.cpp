#include <libtock/tock.h>
#include <libtock/crypto/isle.h>

#include "isle.hpp"

static bool __isle_out_message_ready = false;
static uint32_t __isle_out_message_length;

returncode_t
otIsleWaitForMessageReady(
	const uint32_t messageLength,
	const uint32_t aadLength)
{
	__isle_out_message_ready = false;

    returncode_t tock_cmd_rval = libtock_isle_command_encrypt(messageLength, aadLength);
	if (tock_cmd_rval != RETURNCODE_SUCCESS) {
		return tock_cmd_rval;
	}

	while (!__isle_out_message_ready) {
		yield();
	}

	return tock_cmd_rval;
}

// Returns the length of the CoAP message payload, including the AEAD tag.
uint32_t
otIsleGetOutMessageLength()
{
	return __isle_out_message_length;
}

void
__otIsleFinishUdpSend(
	int messageLength,
	int arg1,
	int arg2,
	void* data)
{
	__isle_out_message_ready = true;
	__isle_out_message_length = messageLength;

	return;
}
