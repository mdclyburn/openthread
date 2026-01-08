#include <libtock/tock.h>
#include <libtock/crypto/isle.h>

#include "isle.hpp"

static bool __isle_out_message_ready = false;
static uint32_t __isle_out_message_length;
static int32_t __isle_cb_result;

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

	return (returncode_t) __isle_cb_result;
}

// Returns the length of the CoAP message payload, including the AEAD tag.
uint32_t
otIsleGetOutMessageLength()
{
	return __isle_out_message_length;
}

void
__otIsleFinishUdpSend(
	int res,
	int messageLength,
	int arg3,
	void* data)
{
	if (res != 0) {
		__isle_cb_result = RETURNCODE_FAIL;
	} else {
		__isle_cb_result = RETURNCODE_SUCCESS;
	}

	__isle_out_message_ready = true;
	__isle_out_message_length = messageLength;

	return;
}
