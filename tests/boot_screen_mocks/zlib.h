#pragma once
typedef unsigned long uLongf;
#define Z_OK 0
#define Z_MEM_ERROR (-4)
#define Z_DATA_ERROR (-3)
int uncompress(unsigned char *, uLongf *, const unsigned char *, unsigned long);
