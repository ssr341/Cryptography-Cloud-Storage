#include "utility.h"
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

/*
***********************************************************************************
***********************************************************************************
***********************************************************************************
***********************************************************************************
***********************************************************************************
***********************************************************************************
***********************************************************************************
***********************************************************************************
***********************************************************************************
***********************************************************************************
***********************************************************************************
***********************************************************************************

Hash Functions
*/

string computeHash(const string& data){
  byte const* byteData = (byte*)data.data();
  unsigned int nDataLen = data.size();
  byte digest[SHA256::DIGESTSIZE];
  SHA256().CalculateDigest(digest, byteData, nDataLen);
  stringstream ss;
  for (int i = 0; i < SHA256::DIGESTSIZE; i++)
    ss << hex << (int)digest[i];
  return ss.str();
}


// hash a string and attach the hash to the end of the string
void addHash(string& data){
  data.append("TheHash:");
  data.append(computeHash(data));
}

// compare hash at end of file to newly computed hash. data is information to be hashed. existing hash is hash at end of file
void checkHash(string data, string existingHash) {
  // set up hash
  byte const* byteData = (byte*)data.data();
  unsigned int nDataLen = data.size();
  byte digest[SHA256::DIGESTSIZE];
  SHA256().CalculateDigest(digest, byteData, nDataLen);

  // convert digest into a string to be compared
  string newHash = btos(digest, SHA256::DIGESTSIZE);

  /*cout << "Hash of file received: " << newHash << ". Length: " << newHash.length() << endl;
  cout << "Hash in the file: " << existingHash << ". Length: " << existingHash.length() << endl;*/

  bool same = true;
  for (size_t i = 0; i < newHash.length(); i++) {
    if (newHash[i] != existingHash[i]) {
      bool same = false;
      break;
    }
  }
  if (same)
    cout << "Message authentic.\n";
  else
    cout << "Message unauthentic.\n";

  // existing hash is always 1 more than newHash for some reason length wise even though they output identical
  /*if (newHash == existingHash)
    cout << "Message authentic.\n";
  else
    cout << "Message unauthentic.\n";*/
  
}

/*
***********************************************************************************
***********************************************************************************
***********************************************************************************
***********************************************************************************
***********************************************************************************
***********************************************************************************
***********************************************************************************
***********************************************************************************
***********************************************************************************
***********************************************************************************
***********************************************************************************
***********************************************************************************

AES Functions
*/

AESParams genAESParams(){
  AESParams params;
  AutoSeededRandomPool rnd;
  SecByteBlock key(0x00, AES::DEFAULT_KEYLENGTH);
  SecByteBlock iv(0x00, AES::BLOCKSIZE);
  rnd.GenerateBlock(iv, AES::BLOCKSIZE);
  rnd.GenerateBlock(key, AES::DEFAULT_KEYLENGTH);  
  params.key = key;
  params.iv = iv;
  return params;
}


// encrypt data (file contents) and write to new file
string AESEncrypt(SecByteBlock& key, SecByteBlock& iv, string data) {

  // create cipher
  string ciphertext;
  AES::Encryption aesEncryption(key, AES::DEFAULT_KEYLENGTH);
  CBC_Mode_ExternalCipher::Encryption cbcEncryption(aesEncryption, iv);

  StreamTransformationFilter stfEncryptor(cbcEncryption, new StringSink(ciphertext));
  stfEncryptor.Put(reinterpret_cast<const unsigned char*>(data.c_str()), data.length() + 1);
  stfEncryptor.MessageEnd();
  
  // hex encode ciphertext and write to file
  string encoded;
  HexEncoder encoder(new StringSink(encoded));
  encoder.Put((byte*)ciphertext.data(), ciphertext.size());
  encoder.MessageEnd();
  return encoded;
}

// decrypt an encrypted string. does not have line breaks
string AESDecrypt(string& keyString, string& ivString, string& encryption){
  SecByteBlock key((byte *)(keyString.data()), keyString.size());
  SecByteBlock iv((byte *)(ivString.data()), ivString.size());

  // hex decode the message
  string decoded = htos(encryption);
  
  AES::Decryption aesDecryption(key, AES::DEFAULT_KEYLENGTH);
  //CBC_Mode_ExternalCipher::Decryption cbcDecryption(aesDecryption, (byte *)ivString.data());
  CBC_Mode_ExternalCipher::Decryption cbcDecryption(aesDecryption, iv.data());

  string decryption;
  StreamTransformationFilter stfDecryptor(cbcDecryption, new StringSink(decryption));
  stfDecryptor.Put(reinterpret_cast<const unsigned char*>(decoded.c_str()), decoded.size());
  stfDecryptor.MessageEnd();

  // divide decryption into message and hash
  size_t findHash = decryption.find("TheHash:");
  string decryptNoHash = decryption.substr(0, findHash);
  string hash = decryption.substr(findHash + 8);

  // check the two hashes
  checkHash(decryptNoHash, hash);
  return decryptNoHash;
}

/*
***********************************************************************************
***********************************************************************************
***********************************************************************************
***********************************************************************************
***********************************************************************************
***********************************************************************************
***********************************************************************************
***********************************************************************************
***********************************************************************************
***********************************************************************************
***********************************************************************************
***********************************************************************************

RSA Functions
*/

RSAKeys genRSAKeys(){
  AutoSeededRandomPool rnd;
  InvertibleRSAFunction params;
  params.GenerateRandomWithKeySize(rnd, 16000);

  RSAKeys keys;
  keys.privateKey = new RSA::PrivateKey(params);
  keys.publicKey = new RSA::PublicKey(params);

  /*
  //Test code
  saveRSAPriKey(*(keys.privateKey), "private");
  saveRSAPubKey(*(keys.publicKey), "public");

  
  ifstream ipub("private");
  string pubKey;
  getline(ipub, pubKey, (char)ipub.eof());
  ipub.close();
  ofstream opub("private1");
  opub << pubKey;
  opub.close();

  RSA::PublicKey pubK;
  RSA::PrivateKey privK;
  loadRSAPubKey(pubK, "public");
  loadRSAPriKey(privK, "private1");

  string plain = "RSA Encryption";

  string cipher = RSAEncrypt(pubK, plain);
  cout << cipher << endl;
  string recovered = RSADecrypt(privK, cipher);
  cout << recovered << endl;
  */

  return keys;
}

void saveRSAPubKey(RSA::PublicKey& key, const char* filename){
  Base64Encoder publicKey(new FileSink(filename));
  key.DEREncode(publicKey);
  publicKey.MessageEnd();
}

void saveRSAPriKey(RSA::PrivateKey& key, const char* filename){
  Base64Encoder privateKey(new FileSink(filename));
  key.DEREncode(privateKey);
  privateKey.MessageEnd();
}

void loadRSAPubKey(RSA::PublicKey& key, const char* filename){
  ByteQueue byte;
  FileSource file(filename, true, new Base64Decoder);
  file.TransferTo(byte);
  byte.MessageEnd();
  key.Load(byte);
}

void loadRSAPriKey(RSA::PrivateKey& key, const char* filename){
  ByteQueue byte;
  FileSource file(filename, true, new Base64Decoder);
  file.TransferTo(byte);
  byte.MessageEnd();
  key.Load(byte);
}

string RSAEncrypt(RSA::PublicKey pubK, string& data){
  AutoSeededRandomPool rnd;
  string cipher;
  RSAES_OAEP_SHA_Encryptor e(pubK);
  StringSource ss(data, true,
    new PK_EncryptorFilter(rnd, e, 
      new StringSink(cipher)
    )
  );
  return cipher;
}

string RSADecrypt(RSA::PrivateKey privK, string& cipher){
  AutoSeededRandomPool rnd;
  string plaintext;
  RSAES_OAEP_SHA_Decryptor d(privK);
  StringSource ss(cipher, true,
    new PK_DecryptorFilter(rnd, d, 
      new StringSink(plaintext)
    )
  );
  return plaintext;
}

/*
***********************************************************************************
***********************************************************************************
***********************************************************************************
***********************************************************************************
***********************************************************************************
***********************************************************************************
***********************************************************************************
***********************************************************************************
***********************************************************************************
***********************************************************************************
***********************************************************************************
***********************************************************************************

Helper Functions
*/

int prompt(string& fileName) {
  bool chosen = false;
  int finalResponse;
  // user chooses whether they want to save a file or get contents of one
  while (!chosen) {
    cout << "Press 1 to save a file, 2 to retrieve a file or 3 to quit. ";
    int tempResponse;
    cin >> tempResponse;
    if (tempResponse == 1 || tempResponse == 2 || tempResponse == 3) {
      chosen = true;
      finalResponse = tempResponse;
    }
    else {
      cout << "Invalid response. Please try again.\n";
      cin.clear();
      cin.ignore(100, '\n');
    }
  }

  if (finalResponse != 3) {
    cout << "Enter in the file you wish to access: ";
    cin >> fileName;
  }
  return finalResponse;
}

// convert byte* into a readable string
string btos(byte* data, int len){
  stringstream ss;
  ss << hex;
  for (int i = 0; i < len; ++i)
    ss << (int)data[i];
  return ss.str();
}

string htos(string &hex){
  string str;
  HexDecoder decoder1(new StringSink(str));
  decoder1.Put((byte*)hex.data(), hex.size());
  decoder1.MessageEnd();
  return str;
}

string btoh(string &bytes){
  string hex;
  HexEncoder encoder(new StringSink(hex));
  encoder.Put((byte*)bytes.data(), bytes.size());
  encoder.MessageEnd();
  return hex;
}

string btoh(SecByteBlock& bytes){
  string hex;
  HexEncoder encoder(new StringSink(hex));
  encoder.Put((byte*)bytes.data(), bytes.size());
  encoder.MessageEnd();
  return hex;
}

//Reads in user input
void getInput(char *name, int size){
  //Read input from stdin
  int len = read(STDIN_FILENO, name, size);
  if (len == -1) { perror("Faile to get user input"); }
  //Remove newline character
  name[len - 1] = '\0';
}

//Reads in port number
int getPortNum(){
  char buf[BUF_SIZE];
  getInput(buf, BUF_SIZE);
  char *endptr;
  int portNum = strtol(buf, &endptr, 10);
  if (*endptr != '\0') { perror("Invalid input for port number"); }
  return portNum;
}

//Reads in packet of data including header and data
void readData(int connfd, char *buff, int size){
  //Extract header
  char header[8];
  int len = read(connfd, header, 8);
  if (len != 8) return;
  for (int i  = 0; i < 8; ++i) {
    if (header[i] == '-') {
      header[i] = '\0';
      break;
    }
  }
  //Read number of characters based on length provided by header
  int length = atoi(header);
  int i = 0;
  char tmp[1];
  while (i < length) {
    read(connfd, tmp, 1);
    buff[i] = tmp[0];
    ++i;
  }
  buff[i] = '\0';

  cout << "Received: " << header << buff << endl;
}

//Writes message with header and data
void writeData(int connfd, const char *buff, int size){
  //Add header to msg
  char msg[BUF_SIZE];
  snprintf(msg, 8, "%d", size);
  while (strlen(msg) != 8) {
    strcat(msg, "-");
  }
  strcat(msg, buff);

  int length = strlen(msg);
  if (length != write(connfd, msg, length)) {
    cout << "Write has failed\n";
  }
  cout << "Sent: " << msg << endl;
}

void getPublicKey(const char* name, const char *ip, int port){
  //Create socket
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd == -1) { perror("Failed to create socket fd"); }

  //Create sockaddr_in to store socket information
  struct sockaddr_in sockaddr;
  memset(&sockaddr, 0, sizeof(sockaddr));
  sockaddr.sin_family = AF_INET;

  //Convert dotted decimal address to network address structure and place in sockaddr
  int res = inet_pton(AF_INET, ip, &sockaddr.sin_addr);
  if (res == 0) { perror("Invalid network address"); }
  if (res == -1) { perror("Invalid address family"); }

  //Specify port used to connect to server
  sockaddr.sin_port = htons(port);

  //Connect to the server
  if (connect(fd, (struct sockaddr *) &sockaddr, sizeof(sockaddr)) == -1) {
    perror("Failed to connect to CA");
  }
  else { printf("Successfully connected to CA\n"); }

  /*
  RSA::PublicKey CAKey;
  loadRSAPubKey(CAKey, computeHash("CAKey").c_str());
  string msg(name);
  msg.append("\nclientKey");
  string cipher = RSAEncrypt(CAKey, msg);
  string request = btoh(cipher);

  //Request server public key from CA
  writeData(fd, request.c_str(), request.length());
  */
  sendRSAData(fd, "serverKey", "client", "CA");

  string message = rcvRSAData(fd);
  istringstream iss(message);
  string key;
  iss >> key >> key;

  //Store server public key in a file
  ofstream ofs(computeHash("serverKey"));
  ofs << key;
  ofs.close();
}

void sendRSAData(int fd, const char* buf, const char* sender, const char* rcvr){
  string keyName(rcvr);
  keyName.append("Key");
  RSA::PublicKey pubKey;
  loadRSAPubKey(pubKey, computeHash(keyName).c_str());
  string msg(sender);
  msg += "\n";
  msg.append(buf);
  string cipher = RSAEncrypt(pubKey, msg);
  string request = btoh(cipher);
  writeData(fd, request.c_str(), request.length());

}
string rcvRSAData(int fd){
  char buf[BUF_SIZE];
  readData(fd, buf, BUF_SIZE);

  string cipher(buf);
  RSA::PrivateKey privK;
  loadRSAPriKey(privK, computeHash("myKey").c_str());
  string bytes = htos(cipher);
  string plaintext = RSADecrypt(privK, bytes);
  return plaintext;
}

void sendPublicKey(int fd, const string& keyNeeded, const string& sender, const string& rcvr){
  ifstream ifs(computeHash(keyNeeded));
  string key;
  getline(ifs, key, (char)ifs.eof());

  sendRSAData(fd, key.c_str(), sender.c_str(), rcvr.c_str());

  writeData(fd, key.c_str(), key.length()); 
}