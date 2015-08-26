#pragma once
#include <stdio.h>
namespace hadmap {

class BufferRAII {
public:
    BufferRAII(char** buffer) : _buffer(buffer) {}
    ~BufferRAII() {
        delete[] * _buffer;
    }

private:
    BufferRAII() {}

    char** _buffer;
};
}

