#pragma once
#include <stdio.h>
namespace hadmap {

class FileRAII {
public:
    FileRAII(FILE* aFile) : _file(aFile) {}
    ~FileRAII() {
        fclose(_file);
    }

    FILE* file() const {
        return _file;
    }
    void file(FILE* val) {
        _file = val;
    }
private:
    FileRAII() {}

    FILE* _file;
};
}

