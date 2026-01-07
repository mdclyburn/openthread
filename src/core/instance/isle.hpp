#include <stdbool.h>
#include <stdint.h>

#include <libtock/tock.h>

struct GroupOSCOREContext {
	/// Byte-string used to derive keys.
	uint8_t mMasterSecret[16];
	/// Byte-string used for key derivation.
	uint8_t mMasterSalt[8];
	/// Uniquely identifies the group among other Group OSCORE groups.
	uint16_t mGroupIdentifier;
	/// Key for encrypting and decrypting countersignatures.
	uint8_t mSignatureEncryptionKey[16];
	/// The sender sequence number (used as the partial IV when sending messages.
	uint32_t mSenderSequenceNumber;
};

returncode_t
otIsleWaitForMessageReady();

uint32_t
otIsleGetOutMessageLength();

void
__otIsleFinishUdpSend(
	int arg0,
	int arg1,
	int arg2,
	void* data);
