#include "WhiteBoxAES_tables.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include "../tigress/3.1/tigress.h"

void init_tigress() {}

#define ROTL8(x,shift) ((u8) ((x) << (shift)) | ((x) >> (8 - (shift))))

typedef unsigned char  u8;
typedef unsigned int   u32;

//u8 sbox[256];

static const u8 SBox[256] = {
  // 0     1     2     3     4     5     6     7     8     9     A     B     C     D     E     F
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

static const u8 rCon[11] = {
  0x8d, 0x01, 0x02, 0x04, 0x08, 0x10,
  0x20, 0x40, 0x80, 0x1b, 0x36
};
#define GETU32(pt) (\
        ((u32)(pt)[0] << 24) ^ ((u32)(pt)[1] << 16) ^\
        ((u32)(pt)[2] <<  8) ^ ((u32)(pt)[3]) )
        
#define PUTU32(ct, st) {\
        (ct)[0] = (u8)((st) >> 24); (ct)[1] = (u8)((st) >> 16);\
        (ct)[2] = (u8)((st) >>  8); (ct)[3] = (u8)(st); }


void mixColumns_table(u8 state[16]) {
  u8 out[16];
  u32 tmp;
    for (int j = 0; j < 4; j++)
    {
      tmp = TyiTables[0][state[4*j]] ^ TyiTables[1][state[4*j + 1]]
      ^ TyiTables[2][state[4*j + 2]] ^ TyiTables[3][state[4*j + 3]];
      out[4*j + 0] = (u8) (tmp >> 24);
      out[4*j + 1] = (u8) (tmp >> 16);
      out[4*j + 2] = (u8) (tmp >> 8);
      out[4*j + 3] = (u8) (tmp >> 0);
    }

  memcpy(state, out, sizeof(out));
}

void initialize_aes_sbox(u8 sbox[256]) {
  u8 p = 1, q = 1;
  
  /* loop invariant: p * q == 1 in the Galois field */
  do {
    /* multiply p by 3 */
    p = p ^ (p << 1) ^ (p & 0x80 ? 0x1B : 0);

    /* divide q by 3 (equals multiplication by 0xf6) */
    q ^= q << 1;
    q ^= q << 2;
    q ^= q << 4;
    q ^= q & 0x80 ? 0x09 : 0;

    /* compute the affine transformation */
    u8 xformed = q ^ ROTL8(q, 1) ^ ROTL8(q, 2) ^ ROTL8(q, 3) ^ ROTL8(q, 4);

    sbox[p] = xformed ^ 0x63;
  } while (p != 1);

  /* 0 is a special case since it has no inverse */
  sbox[0] = 0x63;
}

void printState (u8 in[16]) {
  for(int i=0; i < 4; i++) {
    printf("%.2X %.2X %.2X %.2X\n", in[i], in[i+4], in[i+8], in[i+12]);
  }
  printf("\n");
}

void subBytes (u8 state[16]) {
  for (int i = 0; i < 16; i++)
    state[i] = SBox[state[i]];
}


void shiftRows (u8 state[16]) {
  u8 out[16];
  int shiftTab[16] = {0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11};
  for (int i = 0; i < 16; i++) {
    out[i] = state[shiftTab[i]];
  }
  memcpy(state, out, sizeof(out));
}

void addRoundKey (u8 state[16], u8 roundKey[16]) {
  for (int i = 0; i < 16; i++)
    state[i] ^= roundKey[i];
}

u8 gMul (u8 a, u8 b) {
  u8 p = 0;
  u8 hi_bit_set;

  for (int i = 0; i < 8; i++) {
    if ((b & 1) == 1)
      p ^= a;
    hi_bit_set = (a & 0x80);
    a <<= 1;
    if (hi_bit_set == 0x80)
      a ^= 0x1b;
    b >>= 1;
  }
return p;
}
void mixColumns (u8 state[16]) {
  u8 out[16];
  for (int i = 0; i < 4; i++) {
    out[4*i] = gMul(2, state[4*i]) ^ gMul(3, state[4*i + 1]) ^ state[4*i + 2] ^ state[4*i + 3];
    out[4*i + 1] = state[4*i] ^ gMul(2, state[4*i + 1]) ^ gMul(3, state[4*i + 2]) ^ state[4*i + 3];
    out[4*i + 2] = state[4*i] ^ state[4*i + 1] ^ gMul(2, state[4*i + 2]) ^ gMul(3, state[4*i + 3]);
    out[4*i + 3] = gMul(3, state[4*i]) ^ state[4*i+1] ^ state[4*i + 2] ^ gMul(2, state[4*i + 3]);
  }
  
  memcpy(state, out, sizeof(out));
}

void expandKey (u8 key[16], u8 expandedKey[176]) {
  u8 tmp[4];
  int i = 0;

  for (i = 0; i < 4; i++) {
    expandedKey[4*i] = key[4*i];
    expandedKey[4*i + 1] = key[4*i + 1];
    expandedKey[4*i + 2] = key[4*i + 2];
    expandedKey[4*i + 3] = key[4*i + 3];
  }

  for (i = 4; i < 44; i++) {
    tmp[0] = expandedKey[4*(i-1)];
    tmp[1] = expandedKey[4*(i-1) + 1];
    tmp[2] = expandedKey[4*(i-1) + 2];
    tmp[3] = expandedKey[4*(i-1) + 3];

    if (i % 4 == 0) {
        int k = tmp[0];
        tmp[0] = SBox[tmp[1]] ^ rCon[i/4];
        tmp[1] = SBox[tmp[2]];
        tmp[2] = SBox[tmp[3]];
        tmp[3] = SBox[k];

    }
    expandedKey[4*i] = expandedKey[4*(i-4)] ^ tmp[0];
    expandedKey[4*i + 1] = expandedKey[4*(i-4) + 1] ^ tmp[1];
    expandedKey[4*i + 2] = expandedKey[4*(i-4) + 2] ^ tmp[2];
    expandedKey[4*i + 3] = expandedKey[4*(i-4) + 3] ^ tmp[3];
  }
}


void aes_128_encrypt (u8 input[16], u8 output[16]) {
  u8 expandedKey[176];
  u8 key[16] = {0};

  expandKey (key, expandedKey);

  for (int i = 0; i < 9; i++) {

    shiftRows (input); 
    shiftRows (expandedKey+16*i);
    addRoundKey (input, expandedKey + 16*i);
    subBytes (input);
    mixColumns (input);

  }

  shiftRows (input);
  shiftRows (expandedKey + 144);
  addRoundKey (input, expandedKey + 144);
  subBytes (input);
  addRoundKey (input, expandedKey + 160);

  for (int i = 0; i < 16; i++)
    output[i] = input[i];

}


void aes_128_table_encrypt (u8 input[16], u8 output[16]) {
  u32 a, b, c, d, aa, bb, cc, dd;
  for (int i = 0; i < 9; i++) {
    shiftRows (input);
 
    for (int j = 0; j < 4; j++)
    {
      a = TyiBoxes[i][4*j + 0][input[4*j + 0]];
      b = TyiBoxes[i][4*j + 1][input[4*j + 1]];
      c = TyiBoxes[i][4*j + 2][input[4*j + 2]];
      d = TyiBoxes[i][4*j + 3][input[4*j + 3]];

      aa = xorTable[i][24*j + 0][(a >> 28) & 0xf][(b >> 28) & 0xf];
      bb = xorTable[i][24*j + 1][(c >> 28) & 0xf][(d >> 28) & 0xf];
      cc = xorTable[i][24*j + 2][(a >> 24) & 0xf][(b >> 24) & 0xf];
      dd = xorTable[i][24*j + 3][(c >> 24) & 0xf][(d >> 24) & 0xf];
      input[4*j + 0] = (xorTable[i][24*j + 4][aa][bb] << 4) | xorTable[i][24*j + 5][cc][dd];

      aa = xorTable[i][24*j + 6][(a >> 20) & 0xf][(b >> 20) & 0xf];
      bb = xorTable[i][24*j + 7][(c >> 20) & 0xf][(d >> 20) & 0xf];
      cc = xorTable[i][24*j + 8][(a >> 16) & 0xf][(b >> 16) & 0xf];
      dd = xorTable[i][24*j + 9][(c >> 16) & 0xf][(d >> 16) & 0xf];
      input[4*j + 1] = (xorTable[i][24*j + 10][aa][bb] << 4) | xorTable[i][24*j + 11][cc][dd];

      aa = xorTable[i][24*j + 12][(a >> 12) & 0xf][(b >> 12) & 0xf];
      bb = xorTable[i][24*j + 13][(c >> 12) & 0xf][(d >> 12) & 0xf];
      cc = xorTable[i][24*j + 14][(a >>  8) & 0xf][(b >>  8) & 0xf];
      dd = xorTable[i][24*j + 15][(c >>  8) & 0xf][(d >>  8) & 0xf];
      input[4*j + 2] = (xorTable[i][24*j + 16][aa][bb] << 4) | xorTable[i][24*j + 17][cc][dd];

      aa = xorTable[i][24*j + 18][(a >>  4) & 0xf][(b >>  4) & 0xf];
      bb = xorTable[i][24*j + 19][(c >>  4) & 0xf][(d >>  4) & 0xf];
      cc = xorTable[i][24*j + 20][(a >>  0) & 0xf][(b >>  0) & 0xf];
      dd = xorTable[i][24*j + 21][(c >>  0) & 0xf][(d >>  0) & 0xf];
      input[4*j + 3] = (xorTable[i][24*j + 22][aa][bb] << 4) | xorTable[i][24*j + 23][cc][dd];


      a = mixBijOut[i][4*j + 0][input[4*j + 0]];
      b = mixBijOut[i][4*j + 1][input[4*j + 1]];
      c = mixBijOut[i][4*j + 2][input[4*j + 2]];
      d = mixBijOut[i][4*j + 3][input[4*j + 3]];

      aa = xorTable[i][24*j + 0][(a >> 28) & 0xf][(b >> 28) & 0xf];
      bb = xorTable[i][24*j + 1][(c >> 28) & 0xf][(d >> 28) & 0xf];
      cc = xorTable[i][24*j + 2][(a >> 24) & 0xf][(b >> 24) & 0xf];
      dd = xorTable[i][24*j + 3][(c >> 24) & 0xf][(d >> 24) & 0xf];
      input[4*j + 0] = (xorTable[i][24*j + 4][aa][bb] << 4) | xorTable[i][24*j + 5][cc][dd];

      aa = xorTable[i][24*j + 6][(a >> 20) & 0xf][(b >> 20) & 0xf];
      bb = xorTable[i][24*j + 7][(c >> 20) & 0xf][(d >> 20) & 0xf];
      cc = xorTable[i][24*j + 8][(a >> 16) & 0xf][(b >> 16) & 0xf];
      dd = xorTable[i][24*j + 9][(c >> 16) & 0xf][(d >> 16) & 0xf];
      input[4*j + 1] = (xorTable[i][24*j + 10][aa][bb] << 4) | xorTable[i][24*j + 11][cc][dd];

      aa = xorTable[i][24*j + 12][(a >> 12) & 0xf][(b >> 12) & 0xf];
      bb = xorTable[i][24*j + 13][(c >> 12) & 0xf][(d >> 12) & 0xf];
      cc = xorTable[i][24*j + 14][(a >>  8) & 0xf][(b >>  8) & 0xf];
      dd = xorTable[i][24*j + 15][(c >>  8) & 0xf][(d >>  8) & 0xf];
      input[4*j + 2] = (xorTable[i][24*j + 16][aa][bb] << 4) | xorTable[i][24*j + 17][cc][dd];

      aa = xorTable[i][24*j + 18][(a >>  4) & 0xf][(b >>  4) & 0xf];
      bb = xorTable[i][24*j + 19][(c >>  4) & 0xf][(d >>  4) & 0xf];
      cc = xorTable[i][24*j + 20][(a >>  0) & 0xf][(b >>  0) & 0xf];
      dd = xorTable[i][24*j + 21][(c >>  0) & 0xf][(d >>  0) & 0xf];
      input[4*j + 3] = (xorTable[i][24*j + 22][aa][bb] << 4) | xorTable[i][24*j + 23][cc][dd];
    }
  }
  shiftRows(input);
  for (int j = 0; j < 16; j++) {
    input[j] = TBoxes[9][j][input[j]];
  }

  for (int i = 0; i < 16; i++)
    output[i] = input[i];

}

void printstate(unsigned char * in){
        for(int i = 0; i < 16; i++) {
                printf("%.2X", in[i]);

        }
        printf("\n");

        return;
}

char ascii2hex(char in){
    char out;

    if (('0' <= in) && (in <= '9'))
        out = in - '0';

    if (('A' <= in) && (in <= 'F'))
        out = in - 'A' + 10;

    if (('a' <= in) && (in <= 'f'))
        out = in - 'a' + 10;

    return out;
}

void asciiStr2hex (char * in, char * out, int len){
    int j = 0;
    for (int i = 0; i < len; i += 2)
        out[j++]  = (ascii2hex(in[i ]) << 4) +  ascii2hex(in[i+1]);
}

int main(int argc, char * argv[]){
        unsigned char OUT[32];
        unsigned char IN[32];
        asciiStr2hex(argv[1], (char *)IN, 32);
        //unsigned char IN[32] = "00112233445566778899aabbccddeeff";
        printstate(IN);

        aes_128_table_encrypt(IN, OUT);

        printstate(OUT);

        return 0;
}
