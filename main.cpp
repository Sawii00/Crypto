#include "sha.h"
#include <iostream>
#include <fstream>


int main(void)
{
    std::ifstream file("Competition.exe", std::ios::binary | std::ios::ate);
    if (!file.is_open())
    {
        std::cout << "Error\n";
        exit(-1);
    }

    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);

    u8* buf = new u8[size];
    if (file.read((char*)buf, size))
    {
        struct internal_state res = sha1(buf, size);
        print_state(res);
    }

    system("pause"); 

}
