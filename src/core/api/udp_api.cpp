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

#include "openthread-core-config.h"

#include <openthread/coap.h>
#include <openthread/udp.h>

#include "common/as_core_type.hpp"
#include "common/locator_getters.hpp"

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

#define ISLE_WORK_BUFFER_LEN ((uint32_t) 64)
static uint8_t g_wbuf[ISLE_WORK_BUFFER_LEN];
static uint8_t g_obuf[ISLE_WORK_BUFFER_LEN];
// Mapping indicating class E options.
// E.g., is option 4, ETag, class E? g_coap_e_options & 4.
static uint32_t g_coap_e_options =
	0b010011101001101101001;

otError __otUdpCoapSecure(
	otInstance *aInstance,
	otMessage **aMessage,
	const otMessageInfo *aMessageInfo)
{
	otError err = OT_ERROR_NONE;
	GroupOSCOREContext* gosc_ctx;
	otMessage* outMessage;
	otCoapOptionIterator coapOptionIt;
	uint8_t prevCoapOptionNumber;
	// Work buffer offset index.
	uint16_t wi;
	const uint8_t* myAddr;

	// ===== Step 1: Form the OSCORE plaintext.
	// The plaintext consists of:
	// - the code
	// - E-class options
	// - the payload
	// - AAD (OSCORE version no., AEAD algo. used, kid [sender ID], piv [partial IV])
	wi = 0;

	// Get the CoAP code.
	g_wbuf[wi++] = otCoapMessageGetCode(*aMessage);

	// Collect all of the class E options.
	prevCoapOptionNumber = 0;
	VerifyOrExit((err = otCoapOptionIteratorInit(&coapOptionIt, *aMessage)) == OT_ERROR_NONE);
	for (const otCoapOption* presentOption = otCoapOptionIteratorGetNextOption(&coapOptionIt);
		 presentOption != NULL;
		 presentOption = otCoapOptionIteratorGetNextOption(&coapOptionIt)) {
		if ((g_coap_e_options & presentOption->mNumber)) {
			// Tag
			// TODO: handle large option deltas (> 12).
			g_wbuf[wi] = (presentOption->mNumber - prevCoapOptionNumber) & 0b00001111;
			// Length
			g_wbuf[wi++] |= presentOption->mLength << 4;
			// Value
			otCoapOptionIteratorGetOptionValue(
				&coapOptionIt,
				(g_wbuf + wi));
			wi += presentOption->mLength;
		}
	}

	// The payload.
	otMessageRead(
		*aMessage,
		0,
		(void*) (g_wbuf + wi),
		otMessageGetLength(*aMessage));
	wi += otMessageGetLength(*aMessage);

	// Retrieve the Group OSCORE context based on the destination.
	// TODO: correctly determine the Group OSCORE context.
	gosc_ctx = AsCoreType(aInstance).GetGroupOSCOREContexts();

	// Add the AAD.
	g_wbuf[wi++] = (4 << 5) | (4); // Array, 4 items.

	// Item 1, OSCORE version.
	g_wbuf[wi++] = (0b00000000) | 1; // OSCORE version => integer, 1.
	// Item 2, Algorithms.
	g_wbuf[wi++] = (0b01000000) | 4; // Algorithms => array, 4 items.
	g_wbuf[wi++] = (0b00000000) | 10; // AEAD alg.: AES-CCM-16-64-128 => integer, 10.
	g_wbuf[wi++] = (0b00000000) | 10; // Group enc. algo.: AES-CCM-16-64-128 => integer, 10.
	g_wbuf[wi++] = (0b00111001); // Sig. Algo.: EdDSA => -8 -> 2-byte unsigned integer extension, 7
	g_wbuf[wi++] = 0;
	g_wbuf[wi++] = 7;
	g_wbuf[wi++] = (0b00111001); // Pairwise key agreement: ECDH-SS + HKDF-256 => -27 -> 2-byte unsigned integer extension, 26
	g_wbuf[wi++] = 0;
	g_wbuf[wi++] = 26;
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
	for (uint8_t i = 1; i < 8; i++) { g_wbuf[wi++] = myAddr[i]; }
	// Item 4, Partial IV (uses the sender sequence no.).
	g_wbuf[wi++] = gosc_ctx->mSenderSequenceNumber++; // Increment the sequence no. for the next message.

	// Get the OS to encrypt this buffer.
	// Based on ISLE grouping, the OS will accept or reject it.
	// TODO: we can run a check earlier to save computation.
	VerifyOrExit(
		RETURNCODE_SUCCESS == libtock_isle_allow_ro_set_in_buffer(
			g_wbuf,
			ISLE_WORK_BUFFER_LEN),
		err = OT_ERROR_FAILED);
	VerifyOrExit(
		RETURNCODE_SUCCESS == libtock_isle_allow_rw_set_out_buffer(
			g_obuf,
			ISLE_WORK_BUFFER_LEN),
		err = OT_ERROR_FAILED);
	VerifyOrExit(
		RETURNCODE_SUCCESS == libtock_isle_command_encrypt(wi),
		err = OT_ERROR_FAILED);

	// This is the transformed message the caller should work with.
	*aMessage = NULL;

exit:
	return err;
}

otError otUdpSend(otInstance *aInstance, otUdpSocket *aSocket, otMessage *aMessage, const otMessageInfo *aMessageInfo)
{
    otError error;
	// uint8_t first_byte_of_secret;

    VerifyOrExit(!AsCoreType(aMessage).IsOriginThreadNetif(), error = kErrorInvalidArgs);

	// Translate the CoAP message into a Group OSCORE message.
    error = __otUdpCoapSecure(
		aInstance,
		&aMessage,
		aMessageInfo);

    error = AsCoreType(aInstance).Get<Ip6::Udp>().SendTo(AsCoreType(aSocket), AsCoreType(aMessage),
                                                         AsCoreType(aMessageInfo));

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
