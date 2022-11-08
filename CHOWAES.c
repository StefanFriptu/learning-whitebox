#include <stdio.h>


#include "common/tboxes.h"
#include "common/ty.h"
#include "common/txor.h"
#include "common/tyboxes.h"

void init_tigress() {}

void ShiftRows(unsigned char out[16])
{
    unsigned char tmp1, tmp2;

    // 8-bits left rotation of the second line
    tmp1 = out[1];
    out[1] = out[5];
    out[5] = out[9];
    out[9] = out[13];
    out[13] = tmp1;

    // 16-bits left rotation of the third line
    tmp1 = out[2];
    tmp2 = out[6];
    out[2] = out[10];
    out[6] = out[14];
    out[10] = tmp1;
    out[14] = tmp2;

    // 24-bits left rotation of the last line
    tmp1 = out[3];
    out[3] = out[15];
    out[15] = out[11];
    out[11] = out[7];
    out[7] = tmp1;
}



void aes128_enc_wb_final(unsigned char in[16], unsigned char out[16])
{
    unsigned char out2[16] = { 0 };
    int k;

    memcpy(out, in, 16);

    int i, j;

    /// Let's start the encryption process now
    for (i = 0; i < 9; ++i)
    {
        ShiftRows(out);

        for (j = 0; j < 4; ++j)
        {
            unsigned int aa = Tyboxes[i][j * 4 + 0][out[j * 4 + 0]];
            unsigned int bb = Tyboxes[i][j * 4 + 1][out[j * 4 + 1]];
            unsigned int cc = Tyboxes[i][j * 4 + 2][out[j * 4 + 2]];
            unsigned int dd = Tyboxes[i][j * 4 + 3][out[j * 4 + 3]];

            out[j * 4 + 0] = (Txor[Txor[(aa >>  0) & 0xf][(bb >>  0) & 0xf]][Txor[(cc >>  0) & 0xf][(dd >>  0) & 0xf]]) | ((Txor[Txor[(aa >>  4) & 0xf][(bb >>  4) & 0xf]][Txor[(cc >>  4) & 0xf][(dd >>  4) & 0xf]]) << 4);
            out[j * 4 + 1] = (Txor[Txor[(aa >>  8) & 0xf][(bb >>  8) & 0xf]][Txor[(cc >>  8) & 0xf][(dd >>  8) & 0xf]]) | ((Txor[Txor[(aa >> 12) & 0xf][(bb >> 12) & 0xf]][Txor[(cc >> 12) & 0xf][(dd >> 12) & 0xf]]) << 4);
            out[j * 4 + 2] = (Txor[Txor[(aa >> 16) & 0xf][(bb >> 16) & 0xf]][Txor[(cc >> 16) & 0xf][(dd >> 16) & 0xf]]) | ((Txor[Txor[(aa >> 20) & 0xf][(bb >> 20) & 0xf]][Txor[(cc >> 20) & 0xf][(dd >> 20) & 0xf]]) << 4);
            out[j * 4 + 3] = (Txor[Txor[(aa >> 24) & 0xf][(bb >> 24) & 0xf]][Txor[(cc >> 24) & 0xf][(dd >> 24) & 0xf]]) | ((Txor[Txor[(aa >> 28) & 0xf][(bb >> 28) & 0xf]][Txor[(cc >> 28) & 0xf][(dd >> 28) & 0xf]]) << 4);
        }
    }

    /// Last round which is a bit different
    ShiftRows(out);

    for ( j = 0; j < 16; ++j)
    {
        unsigned char x = Tboxes_[j][out[j]];
        out[j] = x;
    }
    memcpy(out2, out, 16);
}



int main(int argc, char *argv[])
{
	int i;
	unsigned char out[16] = { 0 };
    unsigned char out2[16] = { 0 };
    unsigned char plain[16];
    //= {0x77, 0x68, 0x61, 0x74, 0x64, 0x75, 0x70, 0x20, 0x66, 0x6F, 0x6C, 0x6B, 0x73, 0x3F, 0x3F, 0x3F};
    //= {0x74, 0x65, 0x74, 0x65, 0x74, 0x65, 0x74, 0x65, 0x74, 0x65, 0x74, 0x65, 0x74, 0x65, 0x74, 0x65};
    char *m ="7768617464757020666F6C6B733F3F3F";// "whatdup folks???";//"testtesttesttest";
    char *m2 ="4576A387563BDC8E47FA96B9E84D6F54";// "whatdup folks???";//"testtesttesttest";
    char *m3 ="74657465746574657465746574657465";// "tetetetetetetete"

	int count;


	if( argc == 2 ) {

		//assuming the input is always 32 characters representing 16 bytes
		m = argv[1];

	   }

	unsigned char val[16]; //assuming the input is 16 bytes

	char * pos= m; //copy the message to the buffer for processing (using sscanf because we were testing emulation of some methods) also because the input was provided as need to be transformed to a byte array.
    for(count = 0; count < 16; count++) {
        sscanf(pos, "%2hhx", &plain[count]);
        pos += 2;
    }

    /*char *pos = m3;
    for (count = 0; count < 16; count++) {
        if (count % 2 == 0){
            plain[count] = 0x74;
        }else{
            plain[count] = 0x65;
        }
    }*/

    //char *key = "30766572636C306B40646F6172652D65";//"0vercl0k@doare-e";//"The Key";




    aes128_enc_wb_final(plain, out);

    //char* output_str = "OUTPUT: ";
    //printf("%s", output_str);
    for (i = 0; i < 16; i++)
        //printf("%16X", out);
        printf("%02X", out[i]);
    //printf("\n");
    //int aux;
    /*for ( aux = 0; aux < 16; ++aux) {
        out2[aux] = out[aux];
    }*/
    return out;
}
