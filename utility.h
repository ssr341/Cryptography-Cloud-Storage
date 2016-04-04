#ifndef UTILITY_H
#define UTILITY_H

#include "crypto++/cryptlib.h"
#include "crypto++/rsa.h"
#include "crypto++/sha.h"
#include "crypto++/hex.h"
#include "crypto++/aes.h"
#include "crypto++/modes.h"
#include "crypto++/filters.h"
#include "crypto++/osrng.h"
#include "crypto++/files.h"
#include "crypto++/base64.h"
#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <cstdlib>
#include <cstdio>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
using namespace std;
using namespace CryptoPP;

#define DELIMETER 178
#define BACKLOG 1
#define BUF_SIZE 4096

struct AESParams{
  SecByteBlock key;
  SecByteBlock iv;
};

class RSAKeys{
public:
  RSA::PrivateKey* privateKey;
  RSA::PublicKey* publicKey;
  ~RSAKeys(){
    free(privateKey);
    free(publicKey);
  }
};

//Hash functions
string computeHash(const string& data);
void addHash(string& data);
void checkHash(string data, string existingHash);
string btos(byte* data, int len);

//AES functions
AESParams genAESParams();
string AESEncrypt(SecByteBlock& key, SecByteBlock& iv, string data);
string AESDecrypt(string& key, string& iv, string& cipher);

//RSA functions
RSAKeys genRSAKeys();
void saveRSAKeys(RSAKeys& keys, const char* priv, const char* pub);
void saveRSAPubKey(RSA::PublicKey& key, const char* filename);
void saveRSAPriKey(RSA::PrivateKey& key, const char* filename);
void loadRSAPubKey(RSA::PublicKey& key, const char* filename);
void loadRSAPriKey(RSA::PrivateKey& key, const char* filename);
string RSAEncrypt(RSA::PublicKey pubK, string& data);
string RSADecrypt(RSA::PrivateKey privK, string& cipher);
void sendRSAData(int fd, const char* buf, const char* sender, const char *rcvr);
string rcvRSAData(int fd);

//Helper functions
int prompt(string& fileName);
string htos(string& hex);
string btoh(string &bytes);
string btoh(SecByteBlock& str);
void getInput(char *name, int size);
int getPortNum();
void readData(int fd, char *buf, int size);
void writeData(int fd, const char *buf, int size);
void getPublicKey(const char* name, const char *ip, int port);
void sendPublicKey(int fd, const string& keyNeeded, const string& sender, const string& rcvr);

#endif