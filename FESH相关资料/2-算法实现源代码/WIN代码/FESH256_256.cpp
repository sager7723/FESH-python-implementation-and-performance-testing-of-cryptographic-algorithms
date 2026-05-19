/*
FESH-256-256-AVX.cpp
设计者：贾珂婷、董晓阳、魏淙洺、李铮、周海波、丛天硕
*/

//#include "pch.h"
#include<stdio.h> 
#include<stdlib.h> 
#include<time.h> 
#include<malloc.h>
#include<stdint.h>
#include <intrin.h>
//#include "timing.h"

/*KEYLENGTH为密钥长度字节数，r为轮数*/
#define r 24
#define KEYLENGTH 32
#define u8 unsigned char
#define u64 uint64_t
//循环移位
#define ROL64_r(x,a) (((x)<<(a))|((x)>>(64-(a))))
//循环移位AVX
#define ROL64(x,y,a)\
{\
	__m256i t1,t2;\
	t1 = _mm256_srli_epi64(x,64 - a);\
	t2 = _mm256_slli_epi64(x,a);\
	y = _mm256_or_si256(t1,t2);\
}
void char2u64(unsigned char *input, u64 *X, int j)
{
	X[0] = ((u64)input[j] << 56) | ((u64)input[j + 1] << 48) | ((u64)input[j + 2] << 40) | ((u64)input[j + 3] << 32) | ((u64)input[j + 4] << 24) | ((u64)input[j + 5] << 16) | ((u64)input[j + 6] << 8) | (u64)input[j + 7];
	X[1] = ((u64)input[j + 8] << 56) | ((u64)input[j + 9] << 48) | ((u64)input[j + 10] << 40) | ((u64)input[j + 11] << 32) | ((u64)input[j + 12] << 24) | ((u64)input[j + 13] << 16) | ((u64)input[j + 14] << 8) | (u64)input[j + 15];
	X[2] = ((u64)input[j + 16] << 56) | ((u64)input[j + 17] << 48) | ((u64)input[j + 18] << 40) | ((u64)input[j + 19] << 32) | ((u64)input[j + 20] << 24) | ((u64)input[j + 21] << 16) | ((u64)input[j + 22] << 8) | (u64)input[j + 23];
	X[3] = ((u64)input[j + 24] << 56) | ((u64)input[j + 25] << 48) | ((u64)input[j + 26] << 40) | ((u64)input[j + 27] << 32) | ((u64)input[j + 28] << 24) | ((u64)input[j + 29] << 16) | ((u64)input[j + 30] << 8) | (u64)input[j + 31];
}
void u642char(u64 *X, unsigned char *output, int j)
{
	output[j] = (X[0] >> 56) & 0xff;
	output[j + 1] = (X[0] >> 48) & 0xff;
	output[j + 2] = (X[0] >> 40) & 0xff;
	output[j + 3] = (X[0] >> 32) & 0xff;
	output[j + 4] = (X[0] >> 24) & 0xff;
	output[j + 5] = (X[0] >> 16) & 0xff;
	output[j + 6] = (X[0] >> 8) & 0xff;
	output[j + 7] = X[0] & 0xff;
	j += 8;
	output[j] = (X[1] >> 56) & 0xff;
	output[j + 1] = (X[1] >> 48) & 0xff;
	output[j + 2] = (X[1] >> 40) & 0xff;
	output[j + 3] = (X[1] >> 32) & 0xff;
	output[j + 4] = (X[1] >> 24) & 0xff;
	output[j + 5] = (X[1] >> 16) & 0xff;
	output[j + 6] = (X[1] >> 8) & 0xff;
	output[j + 7] = X[1] & 0xff;
	j += 8;
	output[j] = (X[2] >> 56) & 0xff;
	output[j + 1] = (X[2] >> 48) & 0xff;
	output[j + 2] = (X[2] >> 40) & 0xff;
	output[j + 3] = (X[2] >> 32) & 0xff;
	output[j + 4] = (X[2] >> 24) & 0xff;
	output[j + 5] = (X[2] >> 16) & 0xff;
	output[j + 6] = (X[2] >> 8) & 0xff;
	output[j + 7] = X[2] & 0xff;
	j += 8;
	output[j] = (X[3] >> 56) & 0xff;
	output[j + 1] = (X[3] >> 48) & 0xff;
	output[j + 2] = (X[3] >> 40) & 0xff;
	output[j + 3] = (X[3] >> 32) & 0xff;
	output[j + 4] = (X[3] >> 24) & 0xff;
	output[j + 5] = (X[3] >> 16) & 0xff;
	output[j + 6] = (X[3] >> 8) & 0xff;
	output[j + 7] = X[3] & 0xff;
}
//密钥生成中的S盒
void SubNibble_key(u64 X[4])
{
	u64 r0, r1, r2, r3;
	u64 r4;

	r0 = X[1];
	r1 = X[2];
	r2 = X[3];
	r3 = X[0];

	r1 = ~r1;
	r4 = r1 | r3;
	r2 = r2 ^ r4;
	r4 = r0 | r1;
	r3 = r3 ^ r4;
	r4 = ~r0;
	r4 = r4 & r2;
	r1 = r1 ^ r4;
	r4 = r2 & r3;
	r0 = r0 ^ r4;

	X[0] = r1;
	X[1] = r3;
	X[2] = r2;
	X[3] = r0;

}
//密钥生成中的置换
void MixWord_key(u64 *x)
{
	u64 y0, y1, y2, y3;

	y0 = x[0];
	y1 = x[1];
	y2 = x[2];
	y3 = x[3];

	y0 = y0 ^ ROL64_r(y1, 1);
	y1 = y1 ^ ROL64_r(y0, 50);
	y3 = y3 ^ ROL64_r(y2, 18);
	y2 = y2 ^ ROL64_r(y3, 24);

	x[0] = y2;
	x[1] = y0;
	x[2] = y3;
	x[3] = y1;

}

//加密使用的S盒
void SubNibble_Enc(u64 X[4])
{
	u64 r0, r1, r2, r3;
	u64 r4;

	r0 = X[1];
	r1 = X[2];
	r2 = X[0];
	r3 = X[3];

	r4 = r0 | r2;
	r1 = r1 ^ r4;
	r4 = r3 | r1;
	r2 = r2 ^ r4;
	r1 = r1 ^ r3;
	r4 = r0 & r2;
	r3 = r3 ^ r4;
	r2 = r2 ^ r0;
	r0 = r0 ^ r1;
	r4 = ~r2;
	r4 = r4 | r3;
	r1 = r1 ^ r4;
	r4 = ~r0;
	r4 = r4 | r1;
	r3 = r3 ^ r4;

	X[0] = r2;
	X[1] = r0;
	X[2] = r1;
	X[3] = r3;
}
//加密使用的线性层
void MixWord_Enc(u64 X[4])
{

	u64 y0, y1, y2, y3;

	y0 = X[0];
	y1 = X[1];
	y2 = X[2];
	y3 = X[3];

	y0 = y0 ^ ROL64_r(y1, 58);
	y1 = y1 ^ ROL64_r(y0, 8);
	y3 = y3 ^ ROL64_r(y2, 33);
	y2 = y2 ^ ROL64_r(y3, 1);
	y0 = y0 ^ ROL64_r(y2, 17);
	y2 = y2 ^ ROL64_r(y0, 5);
	y3 = y3 ^ ROL64_r(y1, 44);
	y1 = y1 ^ ROL64_r(y3, 9);

	X[0] = y0;
	X[1] = y1;
	X[2] = y2;
	X[3] = y3;
}
//解密使用的S盒
void SubNibble_Dec(u64 X[4])
{
	u64 r0, r1, r2, r3;
	u64 r4;

	r0 = X[0];
	r1 = X[1];
	r2 = X[3];
	r3 = X[2];

	r0 = r0 ^ r1;
	r1 = r1 ^ r3;
	r4 = r0 | r1;
	r2 = r2 ^ r4;
	r1 = r1 ^ r2;
	r1 = r1 ^ r3;
	r4 = r1 & r3;
	r0 = r0 ^ r4;
	r4 = r3 ^ r2;
	r3 = ~r4;
	r2 = r2 ^ r0;
	r4 = r1 | r2;
	r3 = r3 ^ r4;
	r4 = r0 & r3;
	r2 = r2 ^ r4;

	X[0] = r0;
	X[1] = r3;
	X[2] = r2;
	X[3] = r1;
}
//解密使用的线性层
void MixWord_Dec(u64 X[4])
{
	u64 y0, y1, y2, y3;

	y0 = X[0];
	y1 = X[1];
	y2 = X[2];
	y3 = X[3];

	y1 = y1 ^ ROL64_r(y3, 9);
	y3 = y3 ^ ROL64_r(y1, 44);
	y2 = y2 ^ ROL64_r(y0, 5);
	y0 = y0 ^ ROL64_r(y2, 17);
	y2 = y2 ^ ROL64_r(y3, 1);
	y3 = y3 ^ ROL64_r(y2, 33);
	y1 = y1 ^ ROL64_r(y0, 8);
	y0 = y0 ^ ROL64_r(y1, 58);

	X[0] = y0;
	X[1] = y1;
	X[2] = y2;
	X[3] = y3;
}
//加密使用的轮函数
void RoundFunction_Enc(__m256i &M0, __m256i &M1, __m256i &M2, __m256i &M3)
{
	__m256i M4;

	M4 = _mm256_or_si256(M1, M0);
	M2 = _mm256_xor_si256(M2, M4);
	M4 = _mm256_or_si256(M3, M2);
	M0 = _mm256_xor_si256(M0, M4);
	M2 = _mm256_xor_si256(M2, M3);
	M4 = _mm256_and_si256(M1, M0);
	M3 = _mm256_xor_si256(M3, M4);
	M0 = _mm256_xor_si256(M0, M1);
	M1 = _mm256_xor_si256(M1, M2);
	M4 = _mm256_set1_epi32(0xffffffff);
	M4 = _mm256_xor_si256(M0, M4);
	M4 = _mm256_or_si256(M4, M3);
	M2 = _mm256_xor_si256(M2, M4);
	M4 = _mm256_set1_epi32(0xffffffff);
	M4 = _mm256_xor_si256(M1, M4);
	M4 = _mm256_or_si256(M4, M2);
	M3 = _mm256_xor_si256(M3, M4);

	//r2=r2^ROL64(r0,58);
	ROL64(M1, M4, 58);
	M0 = _mm256_xor_si256(M0, M4);
	//r0=r0^ROL64(r2,8);
	ROL64(M0, M4, 8);
	M1 = _mm256_xor_si256(M1, M4);
	//r3=r3^ROL64(r1,33);
	ROL64(M2, M4, 33);
	M3 = _mm256_xor_si256(M3, M4);
	//r1=r1^ROL64(r3,1);
	ROL64(M3, M4, 1);
	M2 = _mm256_xor_si256(M2, M4);
	//r2=r2^ROL64(r1,17);
	ROL64(M2, M4, 17);
	M0 = _mm256_xor_si256(M0, M4);
	//r1=r1^ROL64(r2,5);
	ROL64(M0, M4, 5);
	M2 = _mm256_xor_si256(M2, M4);
	//r3=r3^ROL64(r0,44);
	ROL64(M1, M4, 44);
	M3 = _mm256_xor_si256(M3, M4);
	//r0=r0^ROL64(r3,9);
	ROL64(M3, M4, 9);
	M1 = _mm256_xor_si256(M1, M4);
}
//解密使用的轮函数
void RoundFunction_Dec(__m256i &M0, __m256i &M1, __m256i &M2, __m256i &M3)
{
	__m256i M4;

	ROL64(M3, M4, 9);
	M1 = _mm256_xor_si256(M1, M4);
	ROL64(M1, M4, 44);
	M3 = _mm256_xor_si256(M3, M4);
	ROL64(M0, M4, 5);
	M2 = _mm256_xor_si256(M2, M4);
	ROL64(M2, M4, 17);
	M0 = _mm256_xor_si256(M0, M4);
	ROL64(M3, M4, 1);
	M2 = _mm256_xor_si256(M2, M4);
	ROL64(M2, M4, 33);
	M3 = _mm256_xor_si256(M3, M4);
	ROL64(M0, M4, 8);
	M1 = _mm256_xor_si256(M1, M4);
	ROL64(M1, M4, 58);
	M0 = _mm256_xor_si256(M0, M4);

	M0 = _mm256_xor_si256(M0, M1);
	M1 = _mm256_xor_si256(M1, M2);
	M4 = _mm256_or_si256(M0, M1);
	M3 = _mm256_xor_si256(M3, M4);
	M1 = _mm256_xor_si256(M1, M3);
	M1 = _mm256_xor_si256(M1, M2);
	M4 = _mm256_and_si256(M1, M2);
	M0 = _mm256_xor_si256(M0, M4);
	M4 = _mm256_xor_si256(M2, M3);
	M2 = _mm256_set1_epi32(0xffffffff);
	M2 = _mm256_xor_si256(M2, M4);
	M3 = _mm256_xor_si256(M3, M0);
	M4 = _mm256_or_si256(M1, M3);
	M2 = _mm256_xor_si256(M2, M4);
	M4 = _mm256_and_si256(M0, M2);
	M3 = _mm256_xor_si256(M3, M4);

	M4 = M1;
	M1 = M2;
	M2 = M3;
	M3 = M4;
}
/*
密钥生成函数，生成u64型密钥
Seedkey为初始密钥
KeyLen为初始密钥长度，单位为字节（8bit），KeyLen = KEYLENGTH正常执行，函数返回0，否则返回-1
Direction为0生成加密密钥，1生成解密密钥
SK为生成密钥，长度为4*(r+1)字（4*(r+1)*64 bit）
*/
int Key_Schedule_u(u8 *Seedkey, int KeyLen, int Direction, u64 *SK)
{
	int i, j, k;
	u64 X[4];

	if (KeyLen == KEYLENGTH)
	{
		static const u64 Cst_0 = 0x03707344A4093822;
		u64 Cst;

		if (Direction == 0)
			j = 0;
		else
			j = r << 2;
		char2u64(Seedkey, X, 0);
		for (k = 0; k < 4; k++)
			SK[j + k] = X[k];

		for (i = 1;i <= r;i++)
		{
			Cst = ROL64_r(Cst_0, i - 1);
			X[0] ^= Cst;
			SubNibble_key(X);
			MixWord_key(X);
			if (Direction == 0)
				j = i << 2;
			else
				j = (r - i) << 2;
			for (k = 0; k < 4; k++)
				SK[j + k] = X[k];
		}
	}
	else
		return -1;
	return 0;
}
/*
密钥生成函数，生成char型密钥
Seedkey为初始密钥
KeyLen为初始密钥长度，单位为字节（8bit），KeyLen = KEYLENGTH正常执行，函数返回0，否则返回-1
Direction为0生成加密密钥，1生成解密密钥
Subkey为生成密钥，长度为32*(r+1)字节（32*(r+1)*8 bit）
*/
int Key_Schedule(u8 *Seedkey, int KeyLen, int Direction, u8 *Subkey)
{
	int i, j, k;
	u64 X[4];
	u64 SK[(r + 1) << 2];

	if (KeyLen == KEYLENGTH)
	{
		static const u64 Cst_0 = 0x03707344A4093822;
		u64 Cst;

		if (Direction == 0)
			j = 0;
		else
			j = r << 2;
		char2u64(Seedkey, X, 0);
		for (k = 0; k < 4; k++)
			SK[j + k] = X[k];
		u642char(X, Subkey, j << 3);

		for (i = 1; i <= r; i++)
		{
			Cst = ROL64_r(Cst_0, i - 1);
			X[0] ^= Cst;
			SubNibble_key(X);
			MixWord_key(X);
			if (Direction == 0)
				j = i << 2;
			else
				j = (r - i) << 2;
			for (k = 0; k < 4; k++)
				SK[j + k] = X[k];
			u642char(X, Subkey, j << 3);
		}
	}
	else
		return -1;
	return 0;
}
/*
逐轮加密函数
X为输入明文，采用u64表示
Subkey输入Key_Schedule_u_u生成的加密密钥，长度为4*(r+1)字（4*(r+1)*64 bit）
CryptRound为加密轮数，CryptRound <= r
*/
void Crypt_Enc_CBC(u64 X[4], u64 *Subkey, int CryptRound)
{
	int j, k;

	X[0] = X[0] ^ Subkey[0];
	X[1] = X[1] ^ Subkey[1];
	X[2] = X[2] ^ Subkey[2];
	X[3] = X[3] ^ Subkey[3];

	for (j = 1; j <= CryptRound; j++)
	{
		k = j << 2;

		SubNibble_Enc(X);
		MixWord_Enc(X);

		X[0] = X[0] ^ Subkey[k];
		X[1] = X[1] ^ Subkey[k + 1];
		X[2] = X[2] ^ Subkey[k + 2];
		X[3] = X[3] ^ Subkey[k + 3];
	}
}

/*
逐轮加密函数
X为输入明文，采用u64表示
Subkey输入Key_Schedule_u生成的加密密钥，长度为4*(r+1)字（4*(r+1)*64 bit）
CryptRound为加密轮数，CryptRound <= r
*/
void Crypt_Enc(u64 X[4], u64 *Subkey, int CryptRound)
{
	int j, k;

	X[0] = X[0] ^ Subkey[0];
	X[1] = X[1] ^ Subkey[1];
	X[2] = X[2] ^ Subkey[2];
	X[3] = X[3] ^ Subkey[3];

	for (j = 1; j <= CryptRound; j++)
	{
		k = j << 2;

		SubNibble_Enc(X);
		MixWord_Enc(X);

		X[0] = X[0] ^ Subkey[k];
		X[1] = X[1] ^ Subkey[k + 1];
		X[2] = X[2] ^ Subkey[k + 2];
		X[3] = X[3] ^ Subkey[k + 3];
	}
}
/*
解密函数
X为输入密文，采用u64表示
Subkey输入Key_Schedule_u生成的解密密钥，长度为4*(r+1)字（4*(r+1)*64 bit）
*/
void Crypt_Dec(u64 X[4], u64 *Subkey)
{
	int j, k;

	X[0] = X[0] ^ Subkey[0];
	X[1] = X[1] ^ Subkey[1];
	X[2] = X[2] ^ Subkey[2];
	X[3] = X[3] ^ Subkey[3];

	for (j = 1; j <= r; j++)
	{
		k = j << 2;

		MixWord_Dec(X);
		SubNibble_Dec(X);

		X[0] = X[0] ^ Subkey[k];
		X[1] = X[1] ^ Subkey[k + 1];
		X[2] = X[2] ^ Subkey[k + 2];
		X[3] = X[3] ^ Subkey[k + 3];
	}
}
/*
ECB加密实现，采用256 bit分组，数据流不满足分组长度的部分直接丢弃
input为输入数据流，采用u8格式
in_len为输入数据长度，单位为字节（8bit），数据长度应不小于32， 否则返回-1
output为输出数据流，采用u8格式
out_len为输出数据长度，单位为字节（8bit），数据长度为32的倍数
key为初始密钥，采用u8格式
keylen为初始密钥长度，单位为字节（8bit），应为KEYLENGTH，否则返回-2
*/
int  Crypt_Enc_Block_One(u8 *input, int in_len, u8 *output, int *out_len, u8 *key, int keylen)
{
	u64 SK[(r + 1) << 2];
	u64 X[4];
	int blocknum = in_len >> 5;
	int i, j;

	if (in_len < 32)
	{
		printf("The in_len of data less than 32, exit");
		return -1;
	}
	if ((keylen < KEYLENGTH) || (keylen > KEYLENGTH))
	{
		printf("The keylen of key is wrong, exit");
		return -2;
	}
	Key_Schedule_u(key, keylen, 0, SK);

	for (i = 0; i < blocknum; i++)
	{
		j = i << 5;
		char2u64(input, X, j);

		Crypt_Enc(X, SK, r);

		u642char(X, output, j);

	}

	*out_len = (in_len>>5)<<5;
	return 0;
}
/*
ECB解密实现，采用256 bit分组，数据流不满足分组长度的部分直接丢弃
input为输入数据流，采用u8格式
in_len为输入数据长度，单位为字节（8bit），数据长度应不小于32， 否则返回-1
output为输出数据流，采用u8格式
out_len为输出数据长度，单位为字节（8bit），out_len为32的倍数
key为初始密钥，采用u8格式
keylen为初始密钥长度，单位为字节（8bit），keylen应为KEYLENGTH，否则返回-2
*/
int Crypt_Dec_Block_One(u8 *input, int in_len, u8 *output, int *out_len, u8 *key, int keylen)
{
	u64 SK[(r + 1) << 2];
	u64 X[4];
	int blocknum = in_len >> 5;
	int i, j;

	if (in_len < 32)
	{
		printf("The in_len of data less than 32, exit");
		return -1;
	}
	if ((keylen < KEYLENGTH) || (keylen > KEYLENGTH))
	{
		printf("The keylen of key is wrong, exit");
		return -2;
	}

	Key_Schedule_u(key, keylen, 1, SK);

	for (i = 0; i < blocknum; i++)
	{
		j = i << 5;
		char2u64(input, X, j);

		Crypt_Dec(X, SK);

		u642char(X, output, j);

	}

	*out_len = (in_len >> 5) << 5;;
	return 0;
}
/*
ECB分轮加密函数，采用256 bit分组，数据流不满足分组长度的部分直接丢弃
input为输入数据流，采用u8格式
in_len为输入数据长度，单位为字节（8bit），数据长度应不小于32， 否则返回-1
output为输出数据流，采用u8格式
out_len为输出数据长度，单位为字节（8bit），数据长度为32的倍数
key为初始密钥，采用u8格式
keylen为初始密钥长度，单位为字节（8bit），应为KEYLENGTH，否则返回-2
CryptRound为加密轮数，CryptRound <= r
*/
int Crypt_Enc_Block_Round_One(u8 *input, int in_len, u8 *output, int *out_len, u8 *key, int keylen, int CryptRound)
{
	u64 SK[(r + 1) << 2];
	u64 X[4];
	int blocknum = in_len >> 5;
	int i, j;

	if (in_len < 32)
	{
		printf("The in_len of data less than 32, exit");
		return -1;
	}
	if ((keylen < KEYLENGTH) || (keylen > KEYLENGTH))
	{
		printf("The keylen of key is wrong, exit");
		return -2;
	}

	Key_Schedule_u(key, keylen, 0, SK);

	for (i = 0; i < blocknum; i++)
	{
		j = i << 5;
		char2u64(input, X, j);

		Crypt_Enc(X, SK, CryptRound);

		u642char(X, output, j);

	}

	*out_len = (in_len >> 5) << 5;
	return 0;
}
/*
ECB加密实现，采用4*256 bit分组，数据流不满足分组长度的部分调用一个分组加密的，对于小于1个分组的直接丢弃
input为输入数据流，采用u8格式
in_len为输入数据长度，单位为字节（8bit），数据长度应不小于128， 否则返回-1
output为输出数据流，采用u8格式
out_len为输出数据长度，单位为字节（8bit），数据长度为128的倍数
key为初始密钥，采用u8格式
keylen为初始密钥长度，单位为字节（8bit），应为KEYLENGTH，否则返回-2
*/
int Crypt_Enc_Block(u8 *input, int in_len, u8 *output, int *out_len, u8 *key, int keylen)
{
	u64 SK[(r + 1) << 2];
	int blocknum = in_len >> 7;
	int left_inlen = in_len & 0x7f;
	int i, j, k, l;

	if (in_len < 32)//
	{
		printf("The length of data less than 32, exit");
		return -1;
	}

	if ((keylen < KEYLENGTH) || (keylen > KEYLENGTH))
	{
		printf("The keylen of key is wrong, exit");
		return -2;
	}

	Key_Schedule_u(key, keylen, 0, SK);

	for (i = 0; i < blocknum; i++)
	{
		u8 mm0[32] = { 0 }, mm1[32] = { 0 }, mm2[32] = { 0 }, mm3[32] = { 0 };

		j = i << 7;
		for (k = 0; k < 4; k++)
		{
			for (l = 0; l < 8; l++)
			{
				mm0[k * 8 + l] = input[j + (7 - l) + 32 * k];
				mm1[k * 8 + l] = input[j + (15 - l) + 32 * k];
				mm2[k * 8 + l] = input[j + (23 - l) + 32 * k];
				mm3[k * 8 + l] = input[j + (31 - l) + 32 * k];
			}
		}

		__m256i M0, M1, M2, M3;
		__m256i K0, K1, K2, K3;

		M0 = _mm256_loadu_si256((__m256i*)mm0);
		M1 = _mm256_loadu_si256((__m256i*)mm1);
		M2 = _mm256_loadu_si256((__m256i*)mm2);
		M3 = _mm256_loadu_si256((__m256i*)mm3);

		K0 = _mm256_set1_epi64x(SK[0]);
		K1 = _mm256_set1_epi64x(SK[1]);
		K2 = _mm256_set1_epi64x(SK[2]);
		K3 = _mm256_set1_epi64x(SK[3]);

		M0 = _mm256_xor_si256(M0, K0);
		M1 = _mm256_xor_si256(M1, K1);
		M2 = _mm256_xor_si256(M2, K2);
		M3 = _mm256_xor_si256(M3, K3);

		for (int m = 1;m <= r;m++)
		{
			k = m << 2;

			RoundFunction_Enc(M0, M1, M2, M3);

			K0 = _mm256_set1_epi64x(SK[k]);
			K1 = _mm256_set1_epi64x(SK[k + 1]);
			K2 = _mm256_set1_epi64x(SK[k + 2]);
			K3 = _mm256_set1_epi64x(SK[k + 3]);

			M0 = _mm256_xor_si256(M0, K0);
			M1 = _mm256_xor_si256(M1, K1);
			M2 = _mm256_xor_si256(M2, K2);
			M3 = _mm256_xor_si256(M3, K3);
		}

		_mm256_storeu_si256((__m256i*)mm0, M0);
		_mm256_storeu_si256((__m256i*)mm1, M1);
		_mm256_storeu_si256((__m256i*)mm2, M2);
		_mm256_storeu_si256((__m256i*)mm3, M3);

		for (k = 0; k < 4; k++)
		{
			for (l = 0; l < 8; l++)
			{
				output[j + (7 - l) + 32 * k] = mm0[k * 8 + l];
				output[j + (15 - l) + 32 * k] = mm1[k * 8 + l];
				output[j + (23 - l) + 32 * k] = mm2[k * 8 + l];
				output[j + (31 - l) + 32 * k] = mm3[k * 8 + l];
			}
		}
	}
	int left_outlen;
	if (left_inlen >= 32)
		Crypt_Enc_Block_One(&input[blocknum << 7], left_inlen, &output[blocknum << 7], &left_outlen, key, keylen);

	*out_len = (in_len >> 5) << 5;
	return 0;
}
/*
ECB解密实现，采用4*256 bit分组，数据流不满足分组长度的部分直接丢弃
input为输入数据流，采用u8格式
in_len为输入数据长度，单位为字节（8bit），数据长度应不小于128， 否则返回-1
output为输出数据流，采用u8格式
out_len为输出数据长度，单位为字节（8bit），out_len为128的倍数
key为初始密钥，采用u8格式
keylen为初始密钥长度，单位为字节（8bit），keylen应为KEYLENGTH，否则返回-2
*/
int Crypt_Dec_Block(u8 *input, int in_len, u8 *output, int *out_len, u8 *key, int keylen)
{
	u64 SK[(r + 1) << 2];
	int blocknum = in_len >> 7;
	int i, j, k, l;

	if (in_len < 32)
	{
		printf("The length of data less than 32 bytes, exit");
		return -1;
	}
	if ((keylen < KEYLENGTH) || (keylen > KEYLENGTH))
	{
		printf("The keylen of key is wrong, exit");
		return -2;
	}

	Key_Schedule_u(key, keylen, 1, SK);

	for (i = 0; i < blocknum; i++)
	{
		u8 mm0[32] = { 0 }, mm1[32] = { 0 }, mm2[32] = { 0 }, mm3[32] = { 0 };

		j = i << 7;
		for (k = 0; k < 4; k++)
		{
			for (l = 0; l < 8; l++)
			{
				mm0[k * 8 + l] = input[j + (7 - l) + 32 * k];
				mm1[k * 8 + l] = input[j + (15 - l) + 32 * k];
				mm2[k * 8 + l] = input[j + (23 - l) + 32 * k];
				mm3[k * 8 + l] = input[j + (31 - l) + 32 * k];
			}
		}

		__m256i M0, M1, M2, M3;
		__m256i K0, K1, K2, K3;

		M0 = _mm256_loadu_si256((__m256i*)mm0);
		M1 = _mm256_loadu_si256((__m256i*)mm1);
		M2 = _mm256_loadu_si256((__m256i*)mm2);
		M3 = _mm256_loadu_si256((__m256i*)mm3);

		K0 = _mm256_set1_epi64x(SK[0]);
		K1 = _mm256_set1_epi64x(SK[1]);
		K2 = _mm256_set1_epi64x(SK[2]);
		K3 = _mm256_set1_epi64x(SK[3]);

		M0 = _mm256_xor_si256(M0, K0);
		M1 = _mm256_xor_si256(M1, K1);
		M2 = _mm256_xor_si256(M2, K2);
		M3 = _mm256_xor_si256(M3, K3);

		for (int m = 1;m <= r;m++)
		{
			k = m << 2;

			RoundFunction_Dec(M0, M1, M2, M3);

			K0 = _mm256_set1_epi64x(SK[k]);
			K1 = _mm256_set1_epi64x(SK[k + 1]);
			K2 = _mm256_set1_epi64x(SK[k + 2]);
			K3 = _mm256_set1_epi64x(SK[k + 3]);

			M0 = _mm256_xor_si256(M0, K0);
			M1 = _mm256_xor_si256(M1, K1);
			M2 = _mm256_xor_si256(M2, K2);
			M3 = _mm256_xor_si256(M3, K3);
		}

		_mm256_storeu_si256((__m256i*)mm0, M0);
		_mm256_storeu_si256((__m256i*)mm1, M1);
		_mm256_storeu_si256((__m256i*)mm2, M2);
		_mm256_storeu_si256((__m256i*)mm3, M3);

		for (k = 0; k < 4; k++)
		{
			for (l = 0; l < 8; l++)
			{
				output[j + (7 - l) + 32 * k] = mm0[k * 8 + l];
				output[j + (15 - l) + 32 * k] = mm1[k * 8 + l];
				output[j + (23 - l) + 32 * k] = mm2[k * 8 + l];
				output[j + (31 - l) + 32 * k] = mm3[k * 8 + l];
			}
		}
	}
	int left_outlen;
	int left_inlen = in_len & 0x7f;
	if (left_inlen >= 32)
		Crypt_Dec_Block_One(&input[blocknum << 7], left_inlen, &output[blocknum << 7], &left_outlen, key, keylen);

	*out_len = (in_len >> 5) << 5;
	return 0;
}
/*
ECB分轮加密实现，采用4*256 bit分组，数据流不满足分组长度的部分直接丢弃
input为输入数据流，采用u8格式
in_len为输入数据长度，单位为字节（8bit），数据长度应不小于128， 否则返回-1
output为输出数据流，采用u8格式
out_len为输出数据长度，单位为字节（8bit），数据长度为128的倍数
key为初始密钥，采用u8格式
keylen为初始密钥长度，单位为字节（8bit），应为KEYLENGTH，否则返回-2
*/
int Crypt_Enc_Block_Round(u8 *input, int in_len, u8 *output, int *out_len, u8 *key, int keylen, int CryptRound)
{
	u64 SK[(r + 1) << 2];
	int blocknum = in_len >> 7;
	int i, j, k, l;

	if (in_len < 32)
	{
		printf("The length of data less than 32 bytes, exit");
		return -1;
	}
	if ((keylen < KEYLENGTH) || (keylen > KEYLENGTH))
	{
		printf("The keylen of key is wrong, exit");
		return -2;
	}

	Key_Schedule_u(key, keylen, 0, SK);

	for (i = 0; i < blocknum; i++)
	{
		u8 mm0[32] = { 0 }, mm1[32] = { 0 }, mm2[32] = { 0 }, mm3[32] = { 0 };

		j = i << 7;
		for (k = 0; k < 4; k++)
		{
			for (l = 0; l < 8; l++)
			{
				mm0[k * 8 + l] = input[j + (7 - l) + 32 * k];
				mm1[k * 8 + l] = input[j + (15 - l) + 32 * k];
				mm2[k * 8 + l] = input[j + (23 - l) + 32 * k];
				mm3[k * 8 + l] = input[j + (31 - l) + 32 * k];
			}
		}

		__m256i M0, M1, M2, M3;
		__m256i K0, K1, K2, K3;

		M0 = _mm256_loadu_si256((__m256i*)mm0);
		M1 = _mm256_loadu_si256((__m256i*)mm1);
		M2 = _mm256_loadu_si256((__m256i*)mm2);
		M3 = _mm256_loadu_si256((__m256i*)mm3);

		K0 = _mm256_set1_epi64x(SK[0]);
		K1 = _mm256_set1_epi64x(SK[1]);
		K2 = _mm256_set1_epi64x(SK[2]);
		K3 = _mm256_set1_epi64x(SK[3]);

		M0 = _mm256_xor_si256(M0, K0);
		M1 = _mm256_xor_si256(M1, K1);
		M2 = _mm256_xor_si256(M2, K2);
		M3 = _mm256_xor_si256(M3, K3);

		for (int m = 1;m <= CryptRound;m++)
		{
			k = m << 2;

			RoundFunction_Enc(M0, M1, M2, M3);

			K0 = _mm256_set1_epi64x(SK[k]);
			K1 = _mm256_set1_epi64x(SK[k + 1]);
			K2 = _mm256_set1_epi64x(SK[k + 2]);
			K3 = _mm256_set1_epi64x(SK[k + 3]);

			M0 = _mm256_xor_si256(M0, K0);
			M1 = _mm256_xor_si256(M1, K1);
			M2 = _mm256_xor_si256(M2, K2);
			M3 = _mm256_xor_si256(M3, K3);
		}

		_mm256_storeu_si256((__m256i*)mm0, M0);
		_mm256_storeu_si256((__m256i*)mm1, M1);
		_mm256_storeu_si256((__m256i*)mm2, M2);
		_mm256_storeu_si256((__m256i*)mm3, M3);

		for (k = 0; k < 4; k++)
		{
			for (l = 0; l < 8; l++)
			{
				output[j + (7 - l) + 32 * k] = mm0[k * 8 + l];
				output[j + (15 - l) + 32 * k] = mm1[k * 8 + l];
				output[j + (23 - l) + 32 * k] = mm2[k * 8 + l];
				output[j + (31 - l) + 32 * k] = mm3[k * 8 + l];
			}
		}
	}

	int left_outlen;
	int left_inlen = in_len & 0x7f;
	if (left_inlen >= 32)
		Crypt_Enc_Block_Round_One(&input[blocknum << 7], left_inlen, &output[blocknum << 7], &left_outlen, key, keylen, CryptRound);

	*out_len = (in_len >> 5) << 5;
	return 0;
}
/*
CBC加密实现，采用256 bit分组，数据流不满足分组长度的部分直接丢弃
input为输入数据流，采用u8格式
in_len为输入数据长度，单位为字节（8bit），数据长度应不小于32， 否则返回-1
output为输出数据流，采用u8格式
out_len为输出数据长度，单位为字节（8bit），数据长度为32的倍数
key为初始密钥，采用u8格式
keylen为初始密钥长度，单位为字节（8bit），应为KEYLENGTH，否则返回-2
*/
int  Crypt_Enc_Block_CBC(u8 *input, int in_len, u8 *output, int *out_len, u8 *key, int keylen)
{
	u64 SK[(r + 1) << 2];
	u64 X[4];
	u64 Y[4] = { 0,0,0,0 };
	int blocknum = in_len >> 5;
	int i, j;

	if (in_len < 32)
	{
		printf("The in_len of data less than 32, exit");
		return -1;
	}
	if ((keylen < KEYLENGTH) || (keylen > KEYLENGTH))
	{
		printf("The keylen of key is wrong, exit");
		return -2;
	}
	Key_Schedule_u(key, keylen, 0, SK);

	for (i = 0; i < blocknum; i++)
	{
		j = i << 5;
		char2u64(input, X, j);

		Y[0] = X[0] ^ Y[0];
		Y[1] = X[1] ^ Y[1];
		Y[2] = X[2] ^ Y[2];
		Y[3] = X[3] ^ Y[3];
		Crypt_Enc_CBC(Y, SK, r);

		u642char(Y, output, j);

	}

	*out_len = blocknum << 5;
	return 0;
}
/*
CBC解密实现，采用256 bit分组，数据流不满足分组长度的部分直接丢弃
input为输入数据流，采用u8格式
in_len为输入数据长度，单位为字节（8bit），数据长度应不小于32， 否则返回-1
output为输出数据流，采用u8格式
out_len为输出数据长度，单位为字节（8bit），out_len为32的倍数
key为初始密钥，采用u8格式
keylen为初始密钥长度，单位为字节（8bit），keylen应为KEYLENGTH，否则返回-2
*/
int Crypt_Dec_Block_CBC_One(u8 *input, int in_len, u8 *output, int *out_len, u8 *key, int keylen)
{
	u64 SK[(r + 1) << 2];
	u64 X[4];
	u64 Y[4] = { 0,0,0,0 };
	u64 Z[4];
	int blocknum = in_len >> 5;
	int i, j;

	if (in_len < 32)
	{
		printf("The in_len of data less than 32, exit");
		return -1;
	}
	if ((keylen < KEYLENGTH) || (keylen > KEYLENGTH))
	{
		printf("The keylen of key is wrong, exit");
		return -2;
	}

	Key_Schedule_u(key, keylen, 1, SK);

	for (i = 0; i < blocknum; i++)
	{
		j = i << 5;
		char2u64(input, X, j);

		Z[0] = X[0];
		Z[1] = X[1];
		Z[2] = X[2];
		Z[3] = X[3];

		Crypt_Dec(X, SK);
		X[0] = X[0] ^ Y[0];
		X[1] = X[1] ^ Y[1];
		X[2] = X[2] ^ Y[2];
		X[3] = X[3] ^ Y[3];

		Y[0] = Z[0];
		Y[1] = Z[1];
		Y[2] = Z[2];
		Y[3] = Z[3];

		u642char(X, output, j);

	}

	*out_len = blocknum << 5;
	return 0;
}
/*
CBC解密实现，采用4*256 bit分组，数据流不满足分组长度的部分直接丢弃
input为输入数据流，采用u8格式
in_len为输入数据长度，单位为字节（8bit），数据长度应不小于128， 否则返回-1
output为输出数据流，采用u8格式
out_len为输出数据长度，单位为字节（8bit），out_len为128的倍数
key为初始密钥，采用u8格式
keylen为初始密钥长度，单位为字节（8bit），keylen应为KEYLENGTH，否则返回-2
*/
int Crypt_Dec_Block_CBC(u8 *input, int in_len, u8 *output, int *out_len, u8 *key, int keylen)
{
	u64 SK[(r + 1) << 2];
	int blocknum = in_len >> 7;
	int lef_inlen = in_len & 0x7f;
	int i, j, k, l;

	if (in_len < 32)
	{
		printf("The length of data less than 32, exit");
		return -1;
	}
	if ((keylen < KEYLENGTH) || (keylen > KEYLENGTH))
	{
		printf("The keylen of key is wrong, exit");
		return -2;
	}

	Key_Schedule_u(key, keylen, 1, SK);

	for (i = 0; i < blocknum; i++)
	{

		u8 mm0[40] = { 0 }, mm1[40] = { 0 }, mm2[40] = { 0 }, mm3[40] = { 0 };

		j = (i << 7);
		for (k = 0; k < 4; k++)
		{
			for (l = 0; l < 8; l++)
			{
				mm0[8 + k * 8 + l] = input[j + (7 - l) + 32 * k];
				mm1[8 + k * 8 + l] = input[j + (15 - l) + 32 * k];
				mm2[8 + k * 8 + l] = input[j + (23 - l) + 32 * k];
				mm3[8 + k * 8 + l] = input[j + (31 - l) + 32 * k];
			}
		}
		if (i != 0)
		{

			for (l = 0; l < 8; l++)
			{
				mm0[l] = input[j - 32 + (7 - l)];
				mm1[l] = input[j - 32 + (15 - l)];
				mm2[l] = input[j - 32 + (23 - l)];
				mm3[l] = input[j - 32 + (31 - l)];
			}

		}

		__m256i M0, M1, M2, M3;
		__m256i K0, K1, K2, K3;
		__m256i M4, M5, M6, M7;

		M0 = _mm256_loadu_si256((__m256i*)&mm0[8]);
		M1 = _mm256_loadu_si256((__m256i*)&mm1[8]);
		M2 = _mm256_loadu_si256((__m256i*)&mm2[8]);
		M3 = _mm256_loadu_si256((__m256i*)&mm3[8]);

		M4 = _mm256_loadu_si256((__m256i*)mm0);
		M5 = _mm256_loadu_si256((__m256i*)mm1);
		M6 = _mm256_loadu_si256((__m256i*)mm2);
		M7 = _mm256_loadu_si256((__m256i*)mm3);

		K0 = _mm256_set1_epi64x(SK[0]);
		K1 = _mm256_set1_epi64x(SK[1]);
		K2 = _mm256_set1_epi64x(SK[2]);
		K3 = _mm256_set1_epi64x(SK[3]);

		M0 = _mm256_xor_si256(M0, K0);
		M1 = _mm256_xor_si256(M1, K1);
		M2 = _mm256_xor_si256(M2, K2);
		M3 = _mm256_xor_si256(M3, K3);

		for (int m = 1;m <= r;m++)
		{
			k = m << 2;

			RoundFunction_Dec(M0, M1, M2, M3);

			K0 = _mm256_set1_epi64x(SK[k]);
			K1 = _mm256_set1_epi64x(SK[k + 1]);
			K2 = _mm256_set1_epi64x(SK[k + 2]);
			K3 = _mm256_set1_epi64x(SK[k + 3]);

			M0 = _mm256_xor_si256(M0, K0);
			M1 = _mm256_xor_si256(M1, K1);
			M2 = _mm256_xor_si256(M2, K2);
			M3 = _mm256_xor_si256(M3, K3);
		}

		M0 = _mm256_xor_si256(M0, M4);
		M1 = _mm256_xor_si256(M1, M5);
		M2 = _mm256_xor_si256(M2, M6);
		M3 = _mm256_xor_si256(M3, M7);

		_mm256_storeu_si256((__m256i*)mm0, M0);
		_mm256_storeu_si256((__m256i*)mm1, M1);
		_mm256_storeu_si256((__m256i*)mm2, M2);
		_mm256_storeu_si256((__m256i*)mm3, M3);

		for (k = 0; k < 4; k++)
		{
			for (l = 0; l < 8; l++)
			{
				output[j + (7 - l) + 32 * k] = mm0[k * 8 + l];
				output[j + (15 - l) + 32 * k] = mm1[k * 8 + l];
				output[j + (23 - l) + 32 * k] = mm2[k * 8 + l];
				output[j + (31 - l) + 32 * k] = mm3[k * 8 + l];
			}
		}
	}
	if (lef_inlen >= 32)
	{
		u64 X[4];
		u64 Y[4] = { 0,0,0,0 };
		u64 Z[4];
		if (blocknum >= 1)
			char2u64(&input[(blocknum << 7) - 32], Y, 0);
		for (i = 0; i < lef_inlen / 32; i++)
		{
			j = i << 5;
			char2u64(&input[blocknum << 7], X, j);

			Z[0] = X[0];
			Z[1] = X[1];
			Z[2] = X[2];
			Z[3] = X[3];

			Crypt_Dec(X, SK);
			X[0] = X[0] ^ Y[0];
			X[1] = X[1] ^ Y[1];
			X[2] = X[2] ^ Y[2];
			X[3] = X[3] ^ Y[3];

			Y[0] = Z[0];
			Y[1] = Z[1];
			Y[2] = Z[2];
			Y[3] = Z[3];

			u642char(X, &output[blocknum << 7], j);

		}

	}
	//Crypt_Dec_Block_CBC_One()
	*out_len = (in_len >> 5) << 5;
	return 0;
}


void verify_CBC_256_256()
{
	u8 * in;
	u8 * output;
	u8* in2;
	u8 key[32] = { 1, 2, 3, 4, 5, 6, 7, 8, 0xa, 0xd, 3, 8, 2, 6, 3, 9, 3, 2, 7, 0xa, 0xe, 0x5, 0x1, 0x8, 0x8, 0x9, 0xd, 0x8, 3, 1, 2, 8 };
	int N_array[10] = { 256, 512, 1024, 2048, 5 * 1024, 10 * 1024, 20 * 1024, 100 * 1024, 500 * 1024, 1024 * 1024 };
	FILE *fp;
	int out_len;
	int i, j;

	for (j = 0; j < 1; j++)
	{
		int N = N_array[j];
		in = (u8 *)malloc(sizeof(u8)*N);
		output = (u8 *)malloc(sizeof(u8)*N);
		in2 = (u8 *)malloc(sizeof(u8)*N);
		for (i = 0; i < N; i++)
		{
			in[i] ^= (u8)i;
		}
		char s[100];
		sprintf_s(s, "p.dat", j + 1);
		fopen_s(&fp, s, "w");
		for (i = 0; i < N; i++)
		{
			fprintf(fp, "%02x", in[i]);
		}
		fclose(fp);

		for (i = 0; i < 32; i++)
		{
			key[i] ^= 0xa1 ^ (u8)j;
		}
		sprintf_s(s, "key.dat", j + 1);
		fopen_s(&fp, s, "w");
		for (i = 0; i < 32; i++)
		{
			fprintf(fp, "%02x", key[i]);
		}
		fprintf(fp, "\n");
		fclose(fp);

		Crypt_Enc_Block_CBC(in, N, output, &out_len, key, 32);

		sprintf_s(s, "c.dat", j + 1);
		fopen_s(&fp, s, "w");
		for (i = 0; i < N; i++)
		{
			fprintf(fp, "%02x", output[i]);
		}
		fprintf(fp, "\n");
		fclose(fp);

		Crypt_Dec_Block_CBC(output, N, in2, &out_len, key, 32);

		sprintf_s(s, "p2.dat", j + 1);
		fopen_s(&fp, s, "w");
		for (i = 0; i < N; i++)
		{
			fprintf(fp, "%02x", in2[i]);
		}
		fprintf(fp, "\n");
		fclose(fp);

		free(in);
		free(output);

	}

}


int main()
{

	//FILE *fp;

	verify_CBC_256_256();
	//testspeed();
	//testspeed_cycle();
}