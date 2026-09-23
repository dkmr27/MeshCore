#pragma once

#include <helpers/ESP8285Board.h>
#include <Arduino.h>

class Nano8285Board : public ESP8285Board {
public:
  void begin() {
    ESP8285Board::begin();
  }

  uint16_t getBattMilliVolts() override {
    return 0;  // not supported
  }

  const char* getManufacturerName() const override {
    return "Nano8285";
  }
};
