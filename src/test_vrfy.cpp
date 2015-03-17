/*
Copyright (c) <2014> Verisign, Inc.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights 
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell 
copies of the Software, and to permit persons to whom the Software is furnished 
to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all 
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, 
INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A 
PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT 
HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION 
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE 
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include <string>
#include <cstdlib>
#include <iostream>     // std::cout
#include <fstream>      // std::ifstream

#include "dane_openssl.h"

void usage() {
    std::cout << "Usage: test_vrfy <file> <email addr>" << std::endl;
    exit(-1);
}

int readFile(std::string & buf, const char *fname) {
  std::ifstream is (fname, std::ifstream::binary);
     if (is) {
    // get length of file:
    is.seekg (0, is.end);
    int length = is.tellg();
    is.seekg (0, is.beg);

    char * buffer = new char [length];

    std::cout << "test_vrfy::readFile Reading [" << std::string(fname) 
              << "] size  [" << length << "] characters... ";
    // read data as a block:
    is.read (buffer,length);

    if (is)
      std::cout << "test_vrfy::readFile all characters read successfully." << std::endl;
    else
      std::cout << "test_vrfy::readFile error: only " << is.gcount() << " could be read" << std::endl;
    is.close();

    // ...buffer contains the entire file...
    buf = std::string(buffer);
    delete[] buffer;
    } else {
        std::cout << "test_vrfy::readFile Error Reading [" << std::string(fname) << "]" << std::endl;
        return 1;
    }
    return 0;
}

int main(int argc, char *argv[]) {
    std::string fileBuf;

    if (argc != 3) {
	   usage();
    }

    // read email sample file 
    readFile(fileBuf, argv[1]);
    
    if (verify( fileBuf, std::string(argv[2]))) {
        std::cout << "test_vrfy::main [Verification Successful]" << std::endl;
    } else 
        std::cout << "test_vrfy::main [Verification Failure]" << std::endl;

    return 0;
}
