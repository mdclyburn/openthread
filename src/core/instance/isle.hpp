#include <stdbool.h>
#include <stdint.h>

#include <libtock/tock.h>

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
