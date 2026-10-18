#ifdef ESP8266
#include "ESP8285Board.h"
#include <target.h>


bool ESP8285Board::startOTAUpdate(const char* id, char reply[]) {
  return false; // not supported
}


void ESP8285Board::powerOff() {
  enterDeepSleep(0); // Do not wakeup
}

void ESP8285Board::enterDeepSleep(uint32_t secs) {
	while(1); // no rest for the wicked
}
#endif