#!/usr/bin/env python3
"""Run production HAP input framing and dispatch over native localhost TCP.

Only cryptography and endpoint callbacks are stubbed. No device is contacted.
"""
from pathlib import Path
import os
import shlex
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SOURCE = Path(os.environ.get("HAP_TEST_SOURCE", ROOT / "src/HAP.cpp")).read_text()
def function(start):
    first = SOURCE.index(start)
    last = SOURCE.index("\n//////////////////////////////////////", first)
    return SOURCE[first:last]
PREFIX = r'''

#include <vector>
#include <string>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <algorithm>
void *testAllocate(size_t);
#define HAP_INPUT_MALLOC testAllocate
#include "HAPInput.h"
bool failAllocation=false;
size_t allocationPeak=0;
void *testAllocate(size_t count) {
 allocationPeak=std::max(allocationPeak,HAPInputBuffer::allocated+count);
 if(failAllocation){failAllocation=false;return nullptr;}
 return std::malloc(count);
}
uint32_t tick=1;uint32_t millis(){return tick;}
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <thread>
#include <chrono>
#define LOG0(...) ((void)0)
#define LOG2(...) ((void)0)
void delay(int){}
template<class T> struct TempBuffer {std::vector<T> v;TempBuffer(int n):v(n){}operator T*(){return v.data();}T*get(){return v.data();}size_t len(){return v.size();}T&operator[](int n){return v[n];}};
struct {struct {bool isEnabled=false;int check(char*){return -1;}}webLog;}homeSpan;
struct Nonce {uint8_t n=0;uint8_t*get(){return &n;}void inc(){n++;}};
int crypto_aead_chacha20poly1305_ietf_decrypt(uint8_t*out,void*,void*,uint8_t*in,size_t n,uint8_t*,int,uint8_t*,uint8_t*){if(n<16)return -1;for(size_t i=n-16;i<n;i++)if(in[i])return -1;memcpy(out,in,n-16);return 0;}
struct Client {
 size_t reads=0;int fd=-1,peer=-1;std::string tx;bool alive=true;
 int available(){int n=0;ioctl(fd,FIONREAD,&n);return n;}
 int read(uint8_t*p,size_t n){reads+=n;int got=recv(fd,p,n,MSG_DONTWAIT);return got<0?0:got;}
 void print(char*s){tx+=s;send(fd,s,strlen(s),0);}
 void stop(){alive=false;shutdown(fd,SHUT_RDWR);}
 void feed(const std::string &data){
  int listener=socket(AF_INET,SOCK_STREAM,0);sockaddr_in addr{};
  addr.sin_family=AF_INET;addr.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
  bind(listener,(sockaddr*)&addr,sizeof(addr));listen(listener,1);
  socklen_t size=sizeof(addr);getsockname(listener,(sockaddr*)&addr,&size);
  peer=socket(AF_INET,SOCK_STREAM,0);connect(peer,(sockaddr*)&addr,sizeof(addr));
  fd=accept(listener,nullptr,nullptr);close(listener);
  send(peer,data.data(),data.size(),0);
  for(int i=0;i<100 && available()!=static_cast<int>(data.size());i++)
   std::this_thread::sleep_for(std::chrono::milliseconds(1));
 }
 void more(const std::string &data){send(peer,data.data(),data.size(),0);for(int i=0;i<100 && available()<static_cast<int>(data.size());i++)std::this_thread::sleep_for(std::chrono::milliseconds(1));}
 ~Client(){if(fd>=0)close(fd);if(peer>=0)close(peer);}
};
struct HAPClient {static const int MAX_HTTP=8096;HAPInput input;Client client;void*cPair=nullptr;Nonce c2aNonce;uint8_t c2aKey[32]={};int dispatched=0;void processRequest();int receiveEncrypted(uint8_t*,int);int badRequestError();void notFoundError(){client.stop();}void postPairSetupURL(uint8_t*,int){dispatched++;}void postPairVerifyURL(uint8_t*,int){dispatched++;}void postPairingsURL(uint8_t*,int){dispatched++;}void putCharacteristicsURL(char*){dispatched++;}void putPrepareURL(char*){dispatched++;}void getAccessoriesURL(){dispatched++;}void getCharacteristicsURL(char*){dispatched++;}void getStatusURL(HAPClient*,void*,void*,int){dispatched++;}};
std::string record(std::string s){std::string r;r+=char(s.size()%256);r+=char(s.size()/256);return r+s+std::string(16,0);}
'''
SUFFIX = r'''
void check(bool good,const char*message){if(!good){fprintf(stderr,"FAIL %s\n",message);exit(1);}}
void drain(HAPClient &c,int expected){for(int i=0;i<20&&c.client.alive&&c.dispatched<expected;i++)c.processRequest();}
std::string request(size_t body){return "POST /pair-verify HTTP/1.1\r\nContent-Type: application/pairing+tlv8\r\nContent-Length: "+std::to_string(body)+"\r\n\r\n"+std::string(body,'x');}
std::string records(std::string data){std::string result;for(size_t p=0;p<data.size();p+=1024)result+=record(data.substr(p,1024));return result;}
int main(){
 std::string pv=request(37),get="GET /accessories HTTP/1.1\r\nHost: example\r\n\r\n";
 size_t splits=0;
 for(bool encrypted:{false,true}) {
  std::string wire=encrypted?records(pv):pv;
  for(size_t split=1;split<wire.size();split++) {
   HAPClient c;c.cPair=encrypted?&c:nullptr;c.client.feed(wire.substr(0,split));
   c.processRequest();check(c.client.alive&&c.dispatched==0,"partial input must remain pending");
   check(c.c2aNonce.n==0,"incomplete encrypted record must not advance nonce");
   c.client.more(wire.substr(split));drain(c,1);
   check(c.client.alive&&c.dispatched==1,"fragmented request dispatches once");
   check(c.c2aNonce.n==encrypted,"complete record advances nonce once");
   check(c.input.capacity()==0,"idle input releases allocations");splits++;
  }
  HAPClient c;c.cPair=encrypted?&c:nullptr;c.client.feed(encrypted?record(get+get):pv+pv);
  c.processRequest();check(c.dispatched==1&&c.client.alive,"first coalesced request");
  if(encrypted)check(c.client.available()==0,"coalesced encrypted bytes already drained from socket");
  c.processRequest();check(c.dispatched==2&&c.client.alive,"second coalesced request without new bytes");
 }
 printf("all %zu plaintext/encrypted TCP split points passed\n",splits);
 HAPClient zero;zero.cPair=&zero;zero.client.feed(record(""));zero.processRequest();
 check(zero.client.alive&&zero.dispatched==0&&zero.c2aNonce.n==1,"authenticated zero-length record");
 tick+=HAPInput::REQUEST_TIMEOUT;zero.processRequest();check(zero.client.alive,"empty record is not stale partial HTTP");
 zero.client.more(record(get));drain(zero,1);check(zero.dispatched==1&&zero.c2aNonce.n==2,"request after empty record");
 HAPClient lower;std::string lowerRequest=pv;lowerRequest.replace(lowerRequest.find("Content-Length"),14,"content-length");lower.client.feed(lowerRequest);lower.processRequest();check(lower.dispatched==1,"case-insensitive Content-Length retains body");
 HAPClient transition;transition.client.feed(pv+record(get));transition.processRequest();check(transition.dispatched==1,"plaintext pair-verify boundary");transition.cPair=&transition;transition.processRequest();check(transition.dispatched==2&&transition.c2aNonce.n==1,"following encrypted bytes use new pairing state");
 // HTTP spanning records, with a complete first record present before the rest arrives.
 std::string large=request(4000),wire=records(large);
 HAPClient multi;multi.cPair=&multi;multi.client.feed(wire.substr(0,1042));multi.processRequest();
 check(multi.client.alive&&multi.dispatched==0&&multi.c2aNonce.n==1,"complete record partial HTTP");
 multi.client.more(wire.substr(1042));drain(multi,1);
 check(multi.client.alive&&multi.dispatched==1&&multi.c2aNonce.n==4,"multi-record HTTP");
 // Maximum request, bounded per-poll reading, and demand-sized buffers.
 size_t maximumBody=HAPInput::MAX_HTTP;while(request(maximumBody).size()>HAPInput::MAX_HTTP)maximumBody--;
 HAPClient big;std::string max=request(maximumBody);check(max.size()==HAPInput::MAX_HTTP,"exact HTTP maximum fixture");big.client.feed(max);drain(big,1);
 check(big.dispatched==1&&big.client.reads<=8096,"large request within byte budget");
 check(big.input.capacity()==0,"large completed request releases memory");
 HAPClient budgeted,other;budgeted.cPair=&budgeted;budgeted.client.feed(records(max));other.client.feed(pv);
 budgeted.processRequest();check(budgeted.client.reads<=HAPInput::MAX_HTTP&&budgeted.dispatched==0,"encrypted work bounded per poll");
 check(budgeted.input.capacity()<=HAPInput::MAX_HTTP+1+1042,"active capacity bounded");
 other.processRequest();check(other.dispatched==1,"large encrypted input does not monopolize polling");
 drain(budgeted,1);check(budgeted.dispatched==1,"maximum encrypted HTTP eventually dispatches");
 HAPInput idle[8];for(auto &input:idle)check(input.capacity()==0,"idle allocation");
 HAPClient small;small.client.feed("GET /");small.processRequest();
 check(small.input.capacity()<=128,"small partial header stays small");
 tick+=HAPInput::REQUEST_TIMEOUT;small.processRequest();check(!small.client.alive,"idle partial request expires");
 for(const std::string &bad:{std::string("Content-Length: -1"),std::string("Content-Length: 99999999999999999999"),std::string("Content-Length: 3\r\nContent-Length: 3"),std::string("Content-Length: +3"),std::string("Content-Length: 3x"),std::string("Transfer-Encoding: chunked"),std::string("Content-Length: 8096")}){
  HAPClient c;c.client.feed("POST /pair-verify HTTP/1.1\r\n"+bad+"\r\n\r\n");c.processRequest();
  check(!c.client.alive&&c.dispatched==0,"invalid HTTP framing rejects without dispatch");
 }
 HAPClient tooLong;tooLong.client.feed(std::string(8097,'X'));tooLong.processRequest();tooLong.processRequest();
 check(!tooLong.client.alive&&tooLong.dispatched==0,"oversize header rejects");
 HAPClient oversized;oversized.cPair=&oversized;oversized.client.feed(std::string("\x01\x04",2));oversized.processRequest();
 check(!oversized.client.alive&&oversized.c2aNonce.n==0,"record >1024 rejects");
 HAPClient badTag;badTag.cPair=&badTag;std::string broken=record(get);broken.back()=1;badTag.client.feed(broken);badTag.processRequest();
 check(!badTag.client.alive&&badTag.dispatched==0&&badTag.c2aNonce.n==0,"invalid tag rejects without dispatch or nonce advance");
 HAPClient stalled,healthy;stalled.client.feed(pv.substr(0,20));healthy.client.feed(pv);stalled.processRequest();healthy.processRequest();
 check(stalled.client.alive&&stalled.dispatched==0&&healthy.dispatched==1,"partial peer does not block other client");
 size_t previousAllocation=HAPInputBuffer::allocated;
 {
  HAPClient pending[8];int rejected=0;
  std::string partial=request(maximumBody);partial.pop_back();
  for(auto &client:pending){
   client.client.feed(partial);
   for(int i=0;i<3&&client.client.alive&&client.client.available();i++)client.processRequest();
   if(!client.client.alive){rejected++;check(client.input.capacity()==0,"budget rejection frees input immediately");}
  }
  check(rejected>0,"concurrent pending requests hit shared budget");
  check(HAPInputBuffer::allocated<=HAPInputBuffer::BUDGET,"pending allocations stay bounded");
  HAPClient responsive;responsive.client.feed(pv);responsive.processRequest();
  check(responsive.dispatched==1,"healthy client works after budget rejection");
 }
 check(HAPInputBuffer::allocated==previousAllocation,"closing pending clients frees shared budget");
 HAPClient outOfMemory;outOfMemory.client.feed(pv);failAllocation=true;outOfMemory.processRequest();
 check(!outOfMemory.client.alive&&outOfMemory.dispatched==0&&outOfMemory.input.capacity()==0,"allocation failure closes without dispatch or leak");
 check(HAPInputBuffer::allocated==previousAllocation,"failed allocation preserves budget accounting");
 check(allocationPeak<=HAPInputBuffer::BUDGET,"transient old+replacement allocations fit budget");
 printf("coalescing, records, limits, timeout, memory, fairness, budget and allocation-failure checks passed\n");
}
'''
with tempfile.TemporaryDirectory(prefix="homespan-hap-input-") as directory:
    source = Path(directory) / "test.cpp"
    executable = Path(directory) / "test"
    legacy = function("int HAPClient::receiveEncrypted(") if "int HAPClient::receiveEncrypted(" in SOURCE else ""
    source.write_text(PREFIX + function("void HAPClient::processRequest(){") + legacy + function("int HAPClient::badRequestError(){") + SUFFIX)
    subprocess.run([os.environ.get("CXX", "c++"), "-std=c++17", *shlex.split(os.environ.get("CXXFLAGS", "")), "-I", str(ROOT / "src"), str(source), "-o", str(executable)], check=True)
    subprocess.run([str(executable)], check=True)
