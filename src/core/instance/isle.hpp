#include <stdbool.h>
#include <stdint.h>

#include <libtock/tock.h>

returncode_t
otIsleWaitForMessageReady(
	const uint32_t messageLength,
	const uint32_t aadLength);

uint32_t
otIsleGetOutMessageLength();

void
__otIsleFinishUdpSend(
	int messageLength,
	int arg1,
	int arg2,
	void* data);
