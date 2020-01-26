#include "openssl/blowfish.h"
#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <cstring>
#include <vector>
using namespace std;


void *fs_encrypt(void *plaintext, int bufsize, char *keystr, int *resultlen);
void *fs_decrypt(void *ciphertext, int bufsize, char *keystr, int *resultlen);
const int BLOCKSIZE = 8;
