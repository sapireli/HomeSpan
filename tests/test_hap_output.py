#!/usr/bin/env python3
"""Exercise the production HAP output function with host socket/crypto stubs.

NetworkClient reports socket errors as zero bytes, so zero covers both cases.
Only flushBuffer is extracted; its implementation is not duplicated here.
"""
from pathlib import Path
import os
import shlex
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "src/HAP.cpp").read_text()
START = SOURCE.index("void HapOut::HapStreamBuffer::flushBuffer(){")
END = SOURCE.index("\n//////////////////////////////////////", START)
PREFIX = r'''

#include <sstream>
#include <vector>
#include <cstring>
#include <cstdio>
#include <cstdint>
using std::uint8_t;
struct { int getLogLevel(){return -1;} } homeSpan;
struct {void print(char*){}} Serial;
void printFormatted(char*,int,int){} void delay(int){} void mbedtls_sha512_update(void*,uint8_t*,int){}
int crypto_aead_chacha20poly1305_ietf_encrypt(uint8_t*out,void*,uint8_t*in,int n,uint8_t*,int,void*,uint8_t*nonce,uint8_t*){memcpy(out,in,n);memset(out+n,*nonce,16);return 0;}
struct Nonce {uint8_t n=0;uint8_t*get(){return &n;}void inc(){n++;}};
struct Client {std::vector<uint8_t> wire;int calls=0,stops=0;long result=-1;bool alive=true;bool connected(){return alive;}void stop(){alive=false;stops++;}size_t write(char*p,size_t n){return write(reinterpret_cast<uint8_t*>(p),n);}size_t write(uint8_t*p,size_t n){calls++;size_t sent=result<0?n:static_cast<size_t>(result);wire.insert(wire.end(),p,p+sent);return sent;}};
struct HAPClient {bool cPair=true;Client client;Nonce a2cNonce;uint8_t a2cKey[32]={};};
class HapOut {public: class HapStreamBuffer:public std::streambuf {public: char buffer[1024];uint8_t encBuf[1042];int byteCount=0,logLevel=2;bool enablePrettyPrint=false;void(*callBack)(char*,void*)=nullptr;void*callBackUserData=nullptr;void*ctx=nullptr;HAPClient*hapClient;HapStreamBuffer(HAPClient*c):hapClient(c){setp(buffer,buffer+1023);}void flushBuffer();};};
'''
SUFFIX = r'''

int main() {
  for(bool encrypted : {false,true}) {
    for(long result : {-1L,0L,1L,7L}) {
      HAPClient client;
      client.cPair=encrypted;
      client.client.result=result;
      HapOut::HapStreamBuffer buffer(&client);
      buffer.sputn("0123456789abcdef",16);
      buffer.flushBuffer();
      bool complete=result<0;
      if(client.client.calls!=1 || client.client.stops!=(!complete) ||
         client.a2cNonce.n!=(encrypted && complete))
        return 1;

      if(!complete) {
        buffer.sputn("next",4);
        buffer.flushBuffer();
        buffer.hapClient=&client;                 // another response selects the stopped client
        buffer.sputn("later",5);
        buffer.flushBuffer();
        if(client.client.calls!=1 || client.client.stops!=1 || client.a2cNonce.n)
          return 2;
      } else {
        buffer.sputn("next",4);
        buffer.flushBuffer();
        if(client.client.calls!=2 || client.a2cNonce.n!=(encrypted?2:0))
          return 3;
      }
      printf("%s %s write passed\n", encrypted?"encrypted":"plaintext",
             complete?"complete":result==0?"zero/error":"short");
    }
  }
}
'''
with tempfile.TemporaryDirectory(prefix="homespan-hap-output-") as directory:
    source = Path(directory) / "test.cpp"
    executable = Path(directory) / "test"
    source.write_text(PREFIX + SOURCE[START:END] + SUFFIX)
    subprocess.run([os.environ.get("CXX", "c++"), "-std=c++17", "-Wall", "-Wextra", *shlex.split(os.environ.get("CXXFLAGS", "")), str(source), "-o", str(executable)], check=True)
    subprocess.run([str(executable)], check=True)
