#include "sha256.h"
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
int main(void) {
  assert(durak_sha256_selftest()==0);
  static const struct {size_t size;const char *hash;} cases[]={
  {0,"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
  {1,"ffe679bb831c95b67dc17819c63c5090d221aac6f4c7bf530f594ab43d21fa1e"},
  {3,"281b1449df500b9d64253ed8fd1c13a291b5c4afe850094e12ac1acfdb7422e7"},
  {55,"44cb7046a6225ff9ff5ed5bae3e3274c68d6d77b53bd512be64b0ff623047b54"},
  {56,"87535826792c4242e9b8ec88665347cc48167f7ac41162e45e9bc75e364c6057"},
  {63,"ec158dffda7701d514de0d84ad9f189f1c1c68e524f0e9e302d13e78481a3edb"},
  {64,"bb7d30cc3725cb327f99f56256cf4fe8e7d69155cbad113369e58ffe5dcddc85"},
  {65,"0f30b745a6589a725d1959d54dd231353ff286cdb5e8f41c803aa7bfae0ab676"},
  {127,"d5de78d3ae27de67e93064e3a89fafbcb2c7f4fae7727fe1269b6b200c61e55a"},
  {128,"1da9f1860f36da462b272e4f3f849871f3ba2bd9239feb68c8a5a7a47deaf4e1"},
  {129,"14cdf8079a998856c2394e961dd0504f0d854399168642d8d075f731cd5805f9"},
  {4097,"7aecdfc4d236df5b5e429b2d8a3f5cfd93cc25cca2bc16de8e5392bff015f3ca"},
  {1000000,"34971627bbb40e73af7e5e44822c781db685a0119179f7d88c84e1ae70523547"},
  };
  unsigned char *input=malloc(1000001);assert(input);
  for(size_t i=0;i<1000000;++i)input[i+1]=(unsigned char)(i*17+31);
  for(size_t i=0;i<sizeof(cases)/sizeof(cases[0]);++i) {
    unsigned char out[34];char hex[65];memset(out,0xa5,sizeof(out));
    durak_sha256(input+1,cases[i].size,out+1);
    assert(out[0]==0xa5 && out[33]==0xa5);
    durak_sha256_to_hex(out+1,hex);assert(!strcmp(hex,cases[i].hash));
  }
  free(input);puts("SHA256: PASS (known vectors, padding/block boundaries, unaligned buffers and guards)");return 0;
}
