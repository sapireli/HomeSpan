#pragma once

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <utility>

// Count old and replacement allocations together: resizing must also fit the
// shared budget. Allocation failure rejects input instead of throwing bad_alloc.
#ifndef HAP_INPUT_MALLOC
#define HAP_INPUT_MALLOC std::malloc
#endif
class HAPInputBuffer {
  uint8_t *bytes=nullptr;
  size_t used=0, reserved=0;
 public:
  static constexpr size_t BUDGET=32768;
  inline static size_t allocated=0;               // accessed only by the HomeSpan polling task
  HAPInputBuffer()=default;
  HAPInputBuffer(const HAPInputBuffer &)=delete;
  HAPInputBuffer &operator=(const HAPInputBuffer &)=delete;
  HAPInputBuffer(HAPInputBuffer &&other) noexcept { swap(other); }
  ~HAPInputBuffer() { clear(); }
  void swap(HAPInputBuffer &other) noexcept {
    std::swap(bytes,other.bytes);
    std::swap(used,other.used);
    std::swap(reserved,other.reserved);
  }
  bool reserve(size_t count) {
    if(count<=reserved)
      return true;
    if(count>BUDGET-allocated)
      return false;
    auto replacement=static_cast<uint8_t *>(HAP_INPUT_MALLOC(count));
    if(!replacement)
      return false;
    allocated+=count;
    if(used)
      memcpy(replacement,bytes,used);
    std::free(bytes);
    allocated-=reserved;
    bytes=replacement;
    reserved=count;
    return true;
  }
  bool resize(size_t count) {
    if(!reserve(count))
      return false;
    used=count;
    return true;
  }
  void push_back(uint8_t c) { bytes[used++]=c; }   // callers reserve before appending
  uint8_t *data() { return bytes; }
  const uint8_t *data() const { return bytes; }
  uint8_t &operator[](size_t pos) { return bytes[pos]; }
  size_t size() const { return used; }
  size_t capacity() const { return reserved; }
  bool empty() const { return used==0; }
  void clear() {
    std::free(bytes);
    allocated-=reserved;
    bytes=nullptr;
    used=reserved=0;
  }
};

// TCP availability is not an HTTP-message or encrypted-record boundary.
// Retain incomplete input without waiting inside the HomeSpan polling task.
class HAPInput {
 public:
  enum Result { PENDING, COMPLETE, INVALID };
  static constexpr size_t MAX_HTTP=8096;
  static constexpr size_t MAX_RECORD=1024;
  // Total incomplete-message clock from its first byte; TCP progress does not extend it.
  static constexpr uint32_t REQUEST_TIMEOUT=10000;

 private:
  HAPInputBuffer http, record;
  size_t headerSize=0, expected=0, bodySize=0;
  size_t recordSize=0, recordExpected=2, decodedPos=0, decodedEnd=0;
  uint32_t started=0;
  bool active=false;

  static bool equal(const uint8_t *text, size_t size, const char *name) {
    if(size!=strlen(name))
      return false;
    for(size_t i=0;i<size;i++) {
      uint8_t c=text[i];
      if(c>='A' && c<='Z')
        c+='a'-'A';
      if(c!=static_cast<uint8_t>(name[i]))
        return false;
    }
    return true;
  }

  bool parseHeaders() {
    bool foundLength=false;
    size_t line=0;
    while(line+2<headerSize) {
      size_t end=line;
      while(end+1<headerSize && !(http[end]=='\r' && http[end+1]=='\n'))
        end++;
      if(line!=0 && end!=line) {
        size_t colon=line;
        while(colon<end && http[colon]!=':')
          colon++;
        if(colon==end || http[line]==' ' || http[line]=='\t')
          return false;
        if(equal(http.data()+line,colon-line,"transfer-encoding"))
          return false;                         // HAP uses Content-Length framing
        if(equal(http.data()+line,colon-line,"content-length")) {
          if(foundLength)
            return false;
          foundLength=true;
          size_t p=colon+1;
          while(p<end && (http[p]==' ' || http[p]=='\t'))
            p++;
          size_t digits=p;
          while(p<end && http[p]>='0' && http[p]<='9') {
            unsigned digit=http[p++]-'0';
            if(bodySize>(MAX_HTTP-digit)/10)
              return false;
            bodySize=bodySize*10+digit;
          }
          if(p==digits)
            return false;
          while(p<end && (http[p]==' ' || http[p]=='\t'))
            p++;
          if(p!=end)
            return false;
        }
      }
      line=end+2;
    }
    if(bodySize>MAX_HTTP-headerSize)
      return false;
    expected=headerSize+bodySize;
    return true;
  }

  bool reserveHttp(size_t required) {
    // Always leave space for the dispatcher terminator, including at MAX_HTTP.
    if(required+1<=http.capacity())
      return true;
    return http.reserve(std::min(MAX_HTTP+1,std::max(required+1,std::max(size_t(128),http.capacity()*2))));
  }

  Result append(uint8_t c) {
    if(http.size()==MAX_HTTP || (!headerSize && c==0))
      return INVALID;
    if(!reserveHttp(http.size()+1))
      return INVALID;
    http.push_back(c);
    size_t n=http.size();
    if(!headerSize && n>=4 && !memcmp(http.data()+n-4,"\r\n\r\n",4)) {
      headerSize=n;
      if(!parseHeaders())
        return INVALID;
    }
    return expected && n==expected ? COMPLETE : PENDING;
  }

  void releaseRecord() {
    record.clear();
    recordSize=decodedPos=decodedEnd=0;
    recordExpected=2;
  }

 public:
  void reset() {
    http.clear();
    releaseRecord();
    headerSize=expected=bodySize=0;
    active=false;
  }

  const uint8_t *data() const { return http.data(); }
  size_t size() const { return http.size(); }
  size_t contentLength() const { return bodySize; }
  size_t capacity() const { return http.capacity()+record.capacity(); }
  bool pending() const { return active; }

  HAPInputBuffer take(uint32_t now) {
    http.push_back(0);                            // preserve the existing null-terminated dispatcher input
    HAPInputBuffer result;
    result.swap(http);
    headerSize=expected=bodySize=0;
    active=decodedPos<decodedEnd;
    started=now;
    if(!active)
      releaseRecord();
    return result;
  }

  template<class Client, class Decrypt>
  Result receive(Client &client, bool encrypted, uint32_t now, Decrypt decrypt) {
    if(active && static_cast<uint32_t>(now-started)>=REQUEST_TIMEOUT)
      return INVALID;
    size_t budget=MAX_HTTP;                       // bound work even for an always-readable peer
    while(budget) {
      if(decodedPos<decodedEnd) {
        budget--;
        Result result=append(record[decodedPos++]);
        if(result!=PENDING)
          return result;
        if(decodedPos==decodedEnd)
          releaseRecord();
        continue;
      }
      int available=client.available();
      if(available<=0)
        return PENDING;
      if(!active) {
        active=true;
        started=now;
      }
      if(!encrypted) {
        if(headerSize) {                          // read a known HTTP body in one bounded batch
          size_t count=std::min({static_cast<size_t>(available),expected-http.size(),budget});
          size_t previous=http.size();
          if(!reserveHttp(previous+count) || !http.resize(previous+count))
            return INVALID;
          int received=client.read(http.data()+previous,count);
          http.resize(previous+(received>0?received:0));
          if(received<=0)
            return PENDING;
          budget-=received;
          if(http.size()==expected)
            return COMPLETE;
          continue;
        }
        uint8_t c;
        if(client.read(&c,1)!=1)
          return PENDING;
        budget--;
        Result result=append(c);
        if(result!=PENDING)
          return result;
        continue;
      }
      if(record.empty() && !record.resize(2))
        return INVALID;
      size_t count=std::min({static_cast<size_t>(available),recordExpected-recordSize,budget});
      int received=client.read(record.data()+recordSize,count);
      if(received<=0)
        return PENDING;
      recordSize+=received;
      budget-=received;
      if(recordSize!=recordExpected)
        continue;
      if(recordExpected==2) {
        size_t length=record[0]+size_t(record[1])*256;
        if(length>MAX_RECORD)
          return INVALID;
        recordExpected=length+18;
        if(!record.resize(recordExpected))
          return INVALID;
        continue;
      }
      // Decrypt in place only after the whole authenticated record has arrived.
      if(!decrypt(record.data(),recordExpected))
        return INVALID;
      decodedPos=2;
      decodedEnd=recordExpected-16;
      if(decodedPos==decodedEnd) {
        releaseRecord();
        if(http.empty())
          active=false;                          // an authenticated empty record is not a partial HTTP request
      }
    }
    return PENDING;
  }
};
