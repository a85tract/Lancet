#ifndef LANCET_COMMON_HPP
#define LANCET_COMMON_HPP

#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <fstream>
#include <sstream>

#include "pin.H"
#include "xed-interface.h"

#define UNKNOWN_ADDR ((ADDRINT)-1)

#define RESET   "\033[0m"
#define RED     "\033[31m"
#define GREEN   "\033[32m"
#define YELLOW  "\033[33m"
#define BLUE    "\033[34m"

template<typename T>
std::string toHex(T value) {
    std::stringstream stream;
    stream << "0x" << std::hex << value;
    return stream.str();
}

class CommonTools {
public:
    static REG ConvertXedRegToPinReg(xed_reg_enum_t xed_reg_enum);
    static ADDRINT get_mod_base(ADDRINT Address);
    static bool is_valid_pointer(ADDRINT addr);
};

#endif
