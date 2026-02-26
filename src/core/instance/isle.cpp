#include <libtock/tock.h>
#include <libtock/crypto/isle.h>

#include "isle.hpp"

uint8_t __isle_wbuf[ISLE_WORK_BUFFER_LEN];
uint8_t __isle_piv_buf[ISLE_PIV_BUFFER_LEN];
uint8_t __isle_host_buf[ISLE_SRC_BUFFER_LEN];
uint8_t __isle_obuf[ISLE_WORK_BUFFER_LEN];
uint8_t __isle_opts[ISLE_WORK_BUFFER_LEN];

/// Whether the outgoing message is available to transmit.
static bool __isle_out_message_ready = false;
/// Length of the outgoing message.
static uint32_t __isle_out_message_length;
/// Result of the most recent asynchronous operation with the ISLE capsule.
static int32_t __isle_cb_result;


/// Create a synchronous, non-system-blocking wait for a message to be ready for transmission.
returncode_t
otIsleWaitForMessageReady(
	const uint64_t iid,
	const uint32_t messageLength,
	const bool is_encrypt)
{
	__isle_out_message_ready = false;

    returncode_t tock_cmd_rval;
	if (is_encrypt)
	{
		// TODO: fill in with address.
		tock_cmd_rval = libtock_isle_command_encrypt(iid);
	}
	else
	{
		// TODO: fill in with address.
		tock_cmd_rval = libtock_isle_command_decrypt(iid);
	}

	if (tock_cmd_rval != RETURNCODE_SUCCESS) {
		return tock_cmd_rval;
	}

	while (!__isle_out_message_ready) {
		yield();
	}

	return (returncode_t) __isle_cb_result;
}

/// Returns the length of the CoAP message payload, including the AEAD tag.
uint32_t
otIsleGetOutMessageLength()
{
	return __isle_out_message_length;
}

/// Callback waiting for the ISLE capsule to finish with the buffer.
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

/// Construct the AAD to authenticate and decrypt an ISLE-wrapped message.
void
otIsleBuildAad(
	ot::Message& message,
	const ot::Ip6::MessageInfo& messageInfo)
{
	const uint16_t read_bytes = message.ReadBytes(
		0,
		__isle_wbuf,
		message.GetLength());
	printf("got %d raw bytes:\n", read_bytes);
	for (uint16_t i = 0; i < read_bytes; i++)
	{
		printf("%x ", __isle_wbuf[i]);
		if ((i + 1) % 8 == 0)
			printf("\n");
	}

	// We need to extract just the payload and not any of the header information.
	uint16_t payload_offset = 0;
	const uint8_t payload_marker = 0xFF;
	while (!message.CompareBytes(
			   payload_offset,
			   &payload_marker,
			   1)
		   && payload_offset < message.GetLength())
		payload_offset++;
	// ASSUME: there is a payload to retrieve?
	// Even if the sending application does not include a payload,
	// OSCORE may be moving headers into the encrypted payload anyway,
	// so we may always have a payload to decrypt.
	payload_offset++; // One more increment to skip the payload marker.

	printf("[otisle] payload is at %d bytes\n", payload_offset);

	const uint16_t message_len = message.ReadBytes(
		payload_offset,
		__isle_wbuf,
		message.GetLength() - payload_offset);
	printf("[otisle] in message is %d bytes\n", message_len);
	printf("in message: ");
	for (uint8_t i = 0; i < message_len; i++)
		printf("%x ", __isle_wbuf[i]);
	printf("\n");

	// Place the peer address in the source IID buffer.
	printf("[otisle] peer IID: ");
	const uint8_t* peer_addr = messageInfo.GetPeerAddr().GetBytes();
	for (uint8_t i = 0; i < 8; i++)
	{
		printf("%x ", peer_addr[8+i]);
		__isle_host_buf[i] = peer_addr[8+i];
	}
	printf("\n");

	// Place the partial IV in the pIV buffer.
	message.ReadBytes(
		// Skip the payload marker and go backward to the pIV.
		payload_offset - 1 - 4,
		__isle_piv_buf,
		4);

	// Give the OS the buffers.
	// If this fails, well...
    libtock_isle_allow_ro_set_in_buffer(
		__isle_wbuf,
		ISLE_WORK_BUFFER_LEN);
	libtock_isle_allow_rw_set_piv_buffer(
		__isle_piv_buf);
	libtock_isle_allow_ro_set_srchost_buffer(
		__isle_host_buf);
    libtock_isle_allow_rw_set_out_buffer(
		__isle_obuf,
		ISLE_WORK_BUFFER_LEN);

	// Ask ISLE to decrypt this for us.
	// Wait for the message to be ready.
	returncode_t tock_cmd_rval = otIsleWaitForMessageReady(
		*((uint64_t*) messageInfo.mPeerAddr.mFields.m8),
		message_len,
		false);
	if (tock_cmd_rval != RETURNCODE_SUCCESS) {
		// printf("ISLE driver failed to process message.\n");
	    libtock_isle_allow_ro_set_in_buffer(NULL, 0);
		libtock_isle_allow_rw_set_out_buffer(NULL, 0);

		return;
	}

	// printf("Got %ld B message back from OS.\n",
		   // otIsleGetOutMessageLength());

	// Take the buffers back.
    libtock_isle_allow_ro_set_in_buffer(
	    NULL,
	    0);
    libtock_isle_allow_rw_set_out_buffer(
		NULL,
		0);

	// Replace the contents of the message buffer with the decrypted message.
	message.WriteBytes(
		0,
		__isle_obuf,
		otIsleGetOutMessageLength());

	return;
}

returncode_t
otIslePrepareReceivedMessage(
	ot::Message& inMessage,
	const ot::Ip6::MessageInfo& inMessageInfo)
{
	// printf("[otisle] got message from peer port %d\n",
	// 	   inMessageInfo.GetSockPort());
	if (inMessageInfo.GetSockPort() == 5683)
	{
		printf("[otisle] processing received %d B message\n", inMessage.GetLength());
		otIsleBuildAad(inMessage, inMessageInfo);
	}

	return RETURNCODE_SUCCESS;
}
