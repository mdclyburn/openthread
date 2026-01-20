/*
 *  Copyright (c) 2016, The OpenThread Authors.
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are met:
 *  1. Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *  2. Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *  3. Neither the name of the copyright holder nor the
 *     names of its contributors may be used to endorse or promote products
 *     derived from this software without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *  POSSIBILITY OF SUCH DAMAGE.
 */

/**
 * @file
 *   This file implements the OpenThread UDP API.
 */

#include <stdio.h>

#include "openthread-core-config.h"

#include <openthread/coap.h>
#include <openthread/udp.h>

#include "common/as_core_type.hpp"
#include "common/locator_getters.hpp"
#include "instance/isle.hpp"

#include <libtock/crypto/isle.h>

using namespace ot;

otMessage *otUdpNewMessage(otInstance *aInstance, const otMessageSettings *aSettings)
{
    return AsCoreType(aInstance).Get<Ip6::Udp>().NewMessage(0, Message::Settings::From(aSettings));
}

otError otUdpOpen(otInstance *aInstance, otUdpSocket *aSocket, otUdpReceive aCallback, void *aContext)
{
    return AsCoreType(aInstance).Get<Ip6::Udp>().Open(AsCoreType(aSocket), aCallback, aContext);
}

bool otUdpIsOpen(otInstance *aInstance, const otUdpSocket *aSocket)
{
    return AsCoreType(aInstance).Get<Ip6::Udp>().IsOpen(AsCoreType(aSocket));
}

otError otUdpClose(otInstance *aInstance, otUdpSocket *aSocket)
{
    return AsCoreType(aInstance).Get<Ip6::Udp>().Close(AsCoreType(aSocket));
}

otError otUdpBind(otInstance *aInstance, otUdpSocket *aSocket, const otSockAddr *aSockName, otNetifIdentifier aNetif)
{
    return AsCoreType(aInstance).Get<Ip6::Udp>().Bind(AsCoreType(aSocket), AsCoreType(aSockName), MapEnum(aNetif));
}

otError otUdpConnect(otInstance *aInstance, otUdpSocket *aSocket, const otSockAddr *aSockName)
{
    return AsCoreType(aInstance).Get<Ip6::Udp>().Connect(AsCoreType(aSocket), AsCoreType(aSockName));
}


otError __otUdpCoapSecure(
	otInstance *aInstance,
	otMessage *aMessage,
	otMessage *outMessage)
{
	otError err = OT_ERROR_NONE;
	otCoapOptionIterator coapOptionIt;
	uint8_t prevCoapOptionNumber;
	// Work buffer offset index.
	uint16_t wi;
	uint8_t payload_offset;
	uint8_t rb;
	uint8_t token_len;
	uint16_t message_len;
	// Options buffer offset index.
	uint16_t oi;
	const uint8_t* myAddr;
	returncode_t tock_cmd_rval;

	// printf("building oscore msg\n");
	// ===== Step 1: Form the OSCORE plaintext.
	// The plaintext consists of:
	// - the code
	// - E-class options
	// - the payload
	// - AAD (OSCORE version no., AEAD algo. used, kid [sender ID], piv [partial IV])
	wi = 0;
	oi = 0;

	// Get the CoAP code.
	otMessageRead(
		aMessage,
		1, // byte offset to get to the CoAP code
		__isle_wbuf,
		1);
	wi++;

	// See if there are options to collect.
	// Initialize rb to zero and read until we reach the payload marker.
	otMessageRead(
		aMessage,
		0,
		&token_len,
		1);
	token_len = token_len >> 4;
	otMessageRead(
		aMessage,
		4 + token_len,
		&rb,
		1);
	while (rb != 0xFF)
	{
		// Collect all of the class E options.
		prevCoapOptionNumber = 0;
		VerifyOrExit((err = otCoapOptionIteratorInit(&coapOptionIt, aMessage)) == OT_ERROR_NONE);
		for (const otCoapOption* presentOption = otCoapOptionIteratorGetNextOption(&coapOptionIt);
			 presentOption != NULL;
			 presentOption = otCoapOptionIteratorGetNextOption(&coapOptionIt)) {
			if ((ISLE_COAP_CLASS_E_OPTIONS & (1 << presentOption->mNumber))) {
				// Tag
				// TODO: handle large option deltas (> 12).
				__isle_wbuf[wi] = (presentOption->mNumber - prevCoapOptionNumber) & 0b00001111;
				// Length
				__isle_wbuf[wi++] |= presentOption->mLength << 4;
				// Value
				otCoapOptionIteratorGetOptionValue(
					&coapOptionIt,
					(__isle_wbuf + wi));
				printf("Got class E option: %d => %d\n", __isle_wbuf[wi-1], __isle_wbuf[wi]);
				wi += presentOption->mLength;
			} else {
				// Save class U options for later.
				// Tag
				// TODO: handle large option deltas (> 12).
				__isle_opts[oi] = (presentOption->mNumber - prevCoapOptionNumber) & 0b00001111;
				// Length
				__isle_opts[oi++] |= presentOption->mLength << 4;
				// Value
				otCoapOptionIteratorGetOptionValue(
					&coapOptionIt,
					(__isle_opts + oi));
				oi += presentOption->mLength;
			}
		}
	}
	printf("Class U options size: %d\n", oi);
	printf("Payload size after options: %d B\n", wi);

	// The payload.
	// Scan until we reach the payload marker.
	payload_offset = 0;
	rb = 0x00;
	while (rb != 0xFF) {
		otMessageRead(
			aMessage,
			payload_offset++,
			&rb,
			1);
	}
	printf("CoAP payload at byte offset %d.\n", payload_offset);
	printf("Total payload size: %d B.\n",
		   otMessageGetLength(aMessage) - payload_offset);

	otMessageRead(
		aMessage,
		payload_offset,
		(void*) (__isle_wbuf + wi),
		otMessageGetLength(aMessage) - payload_offset);
	wi += (otMessageGetLength(aMessage) - payload_offset);
	message_len = wi;
	printf("set message_len to %d B \n", message_len);

	// Add the AAD.
	__isle_wbuf[wi++] = (4 << 5) | (4); // Array, 4 items.

	// Item 1, OSCORE version.
	__isle_wbuf[wi++] = (0b00000000) | 1; // OSCORE version => integer, 1.
	// Item 2, Algorithms.
	__isle_wbuf[wi++] = (0b01000000) | 4; // Algorithms => array, 4 items.
	__isle_wbuf[wi++] = (0b00000000) | 10; // AEAD alg.: AES-CCM-16-64-128 => integer, 10.
	__isle_wbuf[wi++] = (0b00000000) | 10; // Group enc. algo.: AES-CCM-16-64-128 => integer, 10.
	__isle_wbuf[wi++] = (0b00111001); // Sig. Algo.: EdDSA => -8 -> 2-byte unsigned integer extension, 7
	__isle_wbuf[wi++] = 0;
	__isle_wbuf[wi++] = 7;
	__isle_wbuf[wi++] = (0b00111001); // Pairwise key agreement: ECDH-SS + HKDF-256 => -27 -> 2-byte unsigned integer extension, 26
	__isle_wbuf[wi++] = 0;
	__isle_wbuf[wi++] = 26;
	// Item 3, kid (key ID)/sender ID.
    myAddr = otIp6GetUnicastAddresses(aInstance) // HACK; just use the first one.
		->mAddress    // Get the address...
		.mFields      // as divided fields...
		.mComponents  // where the fields are the network prefix and the interface ID (IID)...
		.mIid         // and we want the IID...
		.mFields      // as divided fields...
		.m8;          // where the fields are 8-bit values.
	// The choice of the sender ID is user-defined.
	// We use the lower 7 bits as the sender ID.
	// The length is constrained to the nonce length - 6 (13 - 6 = 7).
	for (uint8_t i = 1; i < 8; i++) { __isle_wbuf[wi++] = myAddr[i]; }
	// Item 4, Partial IV (uses the sender sequence no.).
	// The OS will handle this field.
	__isle_wbuf[wi++] = 0xFE;
	__isle_wbuf[wi++] = 0xFE;
	__isle_wbuf[wi++] = 0xFE;
	__isle_wbuf[wi++] = 0xFE;

	// printf("message + aad = %d + %d = %d\n", message_len, wi - message_len, wi);

	// Get the OS to process, encrypt this buffer.
	// Based on ISLE grouping, the OS will accept or reject it.
	// TODO: we can run a check earlier to save computation.
	VerifyOrExit(
		RETURNCODE_SUCCESS == libtock_isle_allow_ro_set_in_buffer(
			__isle_wbuf,
			ISLE_WORK_BUFFER_LEN),
		err = OT_ERROR_FAILED);
	VerifyOrExit(
		RETURNCODE_SUCCESS == libtock_isle_allow_rw_set_out_buffer(
			__isle_obuf,
			ISLE_WORK_BUFFER_LEN),
		err = OT_ERROR_FAILED);

	// Wait for the message to be ready.
	// printf("awaiting encrypted message to come back\n");
	tock_cmd_rval = otIsleWaitForMessageReady(
		message_len,
		wi - message_len);
	if (tock_cmd_rval != RETURNCODE_SUCCESS) {
		printf("ISLE driver failed to process message.\n");
	    libtock_isle_allow_ro_set_in_buffer(NULL, 0);
		libtock_isle_allow_rw_set_out_buffer(NULL, 0);
		return OT_ERROR_FAILED;
	}

	printf("Got %ld B message back from OS.\n",
		   otIsleGetOutMessageLength());

	// Build the final message.
	// Initialize the message for CoAP.
	wi = 0;
	// Version, Type, Token Length (4 bytes)
	__isle_wbuf[wi++] = 0b10000001;
	// Code
	__isle_wbuf[wi++] = 0b01000101;
	// Message ID
	__isle_wbuf[wi++] = 0b00000000;
	__isle_wbuf[wi++] = 0b00000000;
	// Token
	__isle_wbuf[wi++] = 0b00101011;
	__isle_wbuf[wi++] = 0b00101011;
	__isle_wbuf[wi++] = 0b00101011;
	__isle_wbuf[wi++] = 0b00101011;

	// Class U options.
	for (uint8_t i = 0; i < oi; i++) {
		__isle_wbuf[wi + i] = __isle_opts[i];
	}
	wi += oi;

	// Payload marker.
	__isle_wbuf[wi++] = 0xFF;

	// Payload.
	for (uint8_t i = 0; i < otIsleGetOutMessageLength(); i++) {
		__isle_wbuf[wi++] = __isle_obuf[i];
	}
	printf("final message size = %d\n", wi);

	otMessageFree(aMessage);
	otMessageAppend(outMessage, __isle_wbuf, wi);

exit:
	return err;
}

otError otUdpSend(otInstance *aInstance, otUdpSocket *aSocket, otMessage *aMessage, const otMessageInfo *aMessageInfo)
{
    otError error;
	uint16_t partial_header;

    VerifyOrExit(!AsCoreType(aMessage).IsOriginThreadNetif(), error = kErrorInvalidArgs);

	// Translate the CoAP message into a Group OSCORE message.
	// Quick test to make sure this is a CoAP message.
    if (aMessageInfo->mPeerPort == 5683) {
		otMessage* const outMessage = otUdpNewMessage(aInstance, NULL);
		VerifyOrExit(
			(error = __otUdpCoapSecure(
				aInstance,
				aMessage,
				outMessage)) == OT_ERROR_NONE);

		printf("[otisle] transformation done; sending\n");
		error = AsCoreType(aInstance).Get<Ip6::Udp>().SendTo(AsCoreType(aSocket), AsCoreType(outMessage),
															 AsCoreType(aMessageInfo));
	} else {
		error = AsCoreType(aInstance).Get<Ip6::Udp>().SendTo(AsCoreType(aSocket), AsCoreType(aMessage),
                                                         AsCoreType(aMessageInfo));
	}

exit:
    return error;
}

otUdpSocket *otUdpGetSockets(otInstance *aInstance) { return AsCoreType(aInstance).Get<Ip6::Udp>().GetUdpSockets(); }

#if OPENTHREAD_CONFIG_UDP_FORWARD_ENABLE
void otUdpForwardSetForwarder(otInstance *aInstance, otUdpForwarder aForwarder, void *aContext)
{
    AsCoreType(aInstance).Get<Ip6::Udp>().SetUdpForwarder(aForwarder, aContext);
}

void otUdpForwardReceive(otInstance         *aInstance,
                         otMessage          *aMessage,
                         uint16_t            aPeerPort,
                         const otIp6Address *aPeerAddr,
                         uint16_t            aSockPort)
{
    Ip6::MessageInfo messageInfo;

    messageInfo.SetSockAddr(AsCoreType(aInstance).Get<Mle::MleRouter>().GetMeshLocal16());
    messageInfo.SetSockPort(aSockPort);
    messageInfo.SetPeerAddr(AsCoreType(aPeerAddr));
    messageInfo.SetPeerPort(aPeerPort);
    messageInfo.SetIsHostInterface(true);

    AsCoreType(aInstance).Get<Ip6::Udp>().HandlePayload(AsCoreType(aMessage), messageInfo);

    AsCoreType(aMessage).Free();
}
#endif // OPENTHREAD_CONFIG_UDP_FORWARD_ENABLE

otError otUdpAddReceiver(otInstance *aInstance, otUdpReceiver *aUdpReceiver)
{
    return AsCoreType(aInstance).Get<Ip6::Udp>().AddReceiver(AsCoreType(aUdpReceiver));
}

otError otUdpRemoveReceiver(otInstance *aInstance, otUdpReceiver *aUdpReceiver)
{
    return AsCoreType(aInstance).Get<Ip6::Udp>().RemoveReceiver(AsCoreType(aUdpReceiver));
}

otError otUdpSendDatagram(otInstance *aInstance, otMessage *aMessage, otMessageInfo *aMessageInfo)
{
    otError error;

    VerifyOrExit(!AsCoreType(aMessage).IsOriginThreadNetif(), error = kErrorInvalidArgs);

    return AsCoreType(aInstance).Get<Ip6::Udp>().SendDatagram(AsCoreType(aMessage), AsCoreType(aMessageInfo));
exit:
    return error;
}

bool otUdpIsPortInUse(otInstance *aInstance, uint16_t port)
{
    return AsCoreType(aInstance).Get<Ip6::Udp>().IsPortInUse(port);
}
