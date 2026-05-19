/*
FESH-128-192-SSE.cpp
设计者：贾珂婷、董晓阳、魏淙洺、李铮、周海波、丛天硕
*/
//#include "pch.h"
#include<stdio.h> 
#include<stdlib.h> 
#include<time.h> 
#include<malloc.h>
#include <intrin.h>
//#include "timing.h"

#define r 20
#define KEYLENGTH 32
#define u8 unsigned char
#define u32 unsigned int
//循环移位
#define ROL32_r(x,a) (((x)<<(a))|((x)>>(32-(a))))
#define ROL32_AVX(x,y,a)\
{\
	__m256i t1,t2;\
	t1 = _mm256_srli_epi32(x,32 - a);\
	t2 = _mm256_slli_epi32(x,a);\
	y = _mm256_or_si256(t1,t2);\
}
void char2u32(u8 *input, u32 X[4], int j)
{
	X[0] = (input[j + 0] << 24) | (input[j + 1] << 16) | (input[j + 2] << 8) | input[j + 3];
	X[1] = (input[j + 4] << 24) | (input[j + 5] << 16) | (input[j + 6] << 8) | input[j + 7];
	X[2] = (input[j + 8] << 24) | (input[j + 9] << 16) | (input[j + 10] << 8) | input[j + 11];
	X[3] = (input[j + 12] << 24) | (input[j + 13] << 16) | (input[j + 14] << 8) | input[j + 15];
}

void u322char(u32 X[4], u8 *output, int j)
{
	output[j] = (X[0] >> 24) & 0xff;
	output[j + 1] = (X[0] >> 16) & 0xff;
	output[j + 2] = (X[0] >> 8) & 0xff;
	output[j + 3] = X[0] & 0xff;
	output[j + 4] = (X[1] >> 24) & 0xff;
	output[j + 5] = (X[1] >> 16) & 0xff;
	output[j + 6] = (X[1] >> 8) & 0xff;
	output[j + 7] = X[1] & 0xff;
	output[j + 8] = (X[2] >> 24) & 0xff;
	output[j + 9] = (X[2] >> 16) & 0xff;
	output[j + 10] = (X[2] >> 8) & 0xff;
	output[j + 11] = X[2] & 0xff;
	output[j + 12] = (X[3] >> 24) & 0xff;
	output[j + 13] = (X[3] >> 16) & 0xff;
	output[j + 14] = (X[3] >> 8) & 0xff;
	output[j + 15] = X[3] & 0xff;
}
//密钥生成中的S盒
void SubNibble_key(u32 X[4])
{
	u32 r0, r1, r2, r3;
	u32 r4;

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
void MixWord_key(u32 *x)
{
	u32 y0, y1, y2, y3;

	y0 = x[0];
	y1 = x[1];
	y2 = x[2];
	y3 = x[3];

	y0 = y0 ^ ROL32_r(y1, 24);
	y1 = y1 ^ ROL32_r(y0, 7);
	y3 = y3 ^ ROL32_r(y2, 30);
	y2 = y2 ^ ROL32_r(y3, 18);

	x[0] = y2;
	x[1] = y0;
	x[2] = y3;
	x[3] = y1;

}
//加密使用的S盒
void SubNibble_Enc(u32 X[4])
{
	u32 r0, r1, r2, r3;
	u32 r4;

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
void MixWord_Enc(u32 X[4])
{
	u32 y0, y1, y2, y3;

	y0 = X[0];
	y1 = X[1];
	y2 = X[2];
	y3 = X[3];

	y0 = y0 ^ ROL32_r(y1, 29);
	y1 = y1 ^ ROL32_r(y0, 4);
	y3 = y3 ^ ROL32_r(y2, 13);
	y2 = y2 ^ ROL32_r(y3, 21);
	y0 = y0 ^ ROL32_r(y2, 15);
	y2 = y2 ^ ROL32_r(y0, 25);
	y3 = y3 ^ ROL32_r(y1, 19);
	y1 = y1 ^ ROL32_r(y3, 6);

	X[0] = y0;
	X[1] = y1;
	X[2] = y2;
	X[3] = y3;


}
//解密使用的S盒
void SubNibble_Dec(u32 X[4])
{
	u32 r0, r1, r2, r3;
	u32 r4;

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
void MixWord_Dec(u32 X[4])
{
	u32 y0, y1, y2, y3;

	y0 = X[0];
	y1 = X[1];
	y2 = X[2];
	y3 = X[3];

	y1 = y1 ^ ROL32_r(y3, 6);
	y3 = y3 ^ ROL32_r(y1, 19);
	y2 = y2 ^ ROL32_r(y0, 25);
	y0 = y0 ^ ROL32_r(y2, 15);
	y2 = y2 ^ ROL32_r(y3, 21);
	y3 = y3 ^ ROL32_r(y2, 13);
	y1 = y1 ^ ROL32_r(y0, 4);
	y0 = y0 ^ ROL32_r(y1, 29);

	X[0] = y0;
	X[1] = y1;
	X[2] = y2;
	X[3] = y3;
}
//加密使用的轮函数
void RoundFunction_Enc_AVX(__m256i &M0, __m256i &M1, __m256i &M2, __m256i &M3)
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

	ROL32_AVX(M1, M4, 29);
	M0 = _mm256_xor_si256(M0, M4);
	ROL32_AVX(M0, M4, 4);
	M1 = _mm256_xor_si256(M1, M4);
	ROL32_AVX(M2, M4, 13);
	M3 = _mm256_xor_si256(M3, M4);
	ROL32_AVX(M3, M4, 21);
	M2 = _mm256_xor_si256(M2, M4);
	ROL32_AVX(M2, M4, 15);
	M0 = _mm256_xor_si256(M0, M4);
	ROL32_AVX(M0, M4, 25);
	M2 = _mm256_xor_si256(M2, M4);
	ROL32_AVX(M1, M4, 19);
	M3 = _mm256_xor_si256(M3, M4);
	ROL32_AVX(M3, M4, 6);
	M1 = _mm256_xor_si256(M1, M4);

}
//解密使用的轮函数
void RoundFunction_Dec_AVX(__m256i &M0, __m256i &M1, __m256i &M2, __m256i &M3)
{
	__m256i M4;

	ROL32_AVX(M3, M4, 6);
	M1 = _mm256_xor_si256(M1, M4);
	ROL32_AVX(M1, M4, 19);
	M3 = _mm256_xor_si256(M3, M4);
	ROL32_AVX(M0, M4, 25);
	M2 = _mm256_xor_si256(M2, M4);
	ROL32_AVX(M2, M4, 15);
	M0 = _mm256_xor_si256(M0, M4);
	ROL32_AVX(M3, M4, 21);
	M2 = _mm256_xor_si256(M2, M4);
	ROL32_AVX(M2, M4, 13);
	M3 = _mm256_xor_si256(M3, M4);
	ROL32_AVX(M0, M4, 4);
	M1 = _mm256_xor_si256(M1, M4);
	ROL32_AVX(M1, M4, 29);
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
密钥生成函数，生成u32型密钥
Seedkey为初始密钥
KeyLen为初始密钥长度，单位为字节（8bit），KeyLen = KEYLENGTH正常执行，函数返回0，否则返回-1
Direction为0生成加密密钥，1生成解密密钥
SK为生成密钥，长度为4*(r+1)字（4*(r+1)*32 bit）
*/
int Key_Schedule_u(u8 *Seedkey, int KeyLen, int Direction, u32 *SK)
{
	int i, j, k;
	u32 X[4];

	if (KeyLen == KEYLENGTH)
	{
		static const u32 Cst_0 = 0x13198A2E;
		u32 Cst;

		if (Direction == 0)
		{
			char2u32(Seedkey, X, 0);
			for (k = 0; k < 4; k++)
				SK[k] = X[k];
			char2u32(Seedkey, X, 16);
			for (k = 0; k < 4; k++)
				SK[4 + k] = X[k];
		}
		else
		{
			j = r << 2;
			char2u32(Seedkey, X, 0);
			for (k = 0; k < 4; k++)
				SK[j + k] = X[k];
			char2u32(Seedkey, X, 16);
			j = (r - 1) << 2;
			for (k = 0; k < 4; k++)
				SK[j + k] = X[k];
		}

		for (i = 1;i < r;i++)
		{
			Cst = ROL32_r(Cst_0, i - 1);
			X[0] ^= Cst;
			SubNibble_key(X);
			MixWord_key(X);

			if (Direction == 0)
				j = (i - 1) << 2;
			else
				j = (r - i + 1) << 2;

			X[0] ^= SK[j];
			X[1] ^= SK[j + 1];
			X[2] ^= SK[j + 2];
			X[3] ^= SK[j + 3];

			if (Direction == 0)
				j = (i + 1) << 2;
			else
				j = (r - i - 1) << 2;
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
Subkey为生成密钥，长度为16*(r+1)字节（16*(r+1)*8 bit）
*/
int Key_Schedule(u8 *Seedkey, int KeyLen, u8 Direction, u8 *Subkey)
{
	int i, j, k;
	u32 X[4];
	u32 SK[(r + 1) << 2];

	if (KeyLen == KEYLENGTH)
	{
		const u32 Cst_0 = 0x13198A2E;

		u32 Cst;

		if (Direction == 0)
		{
			char2u32(Seedkey, X, 0);
			for (k = 0; k < 4; k++)
				SK[k] = X[k];
			u322char(X, Subkey, 0);
			char2u32(Seedkey, X, 16);
			for (k = 0; k < 4; k++)
				SK[4 + k] = X[k];
			u322char(X, Subkey, 16);
		}
		else
		{
			j = r << 2;
			char2u32(Seedkey, X, 0);
			for (k = 0; k < 4; k++)
				SK[j + k] = X[k];
			u322char(X, Subkey, j << 2);
			char2u32(Seedkey, X, 16);
			j = (r - 1) << 2;
			for (k = 0; k < 4; k++)
				SK[j + k] = X[k];
			u322char(X, Subkey, j << 2);
		}

		for (i = 1;i < r;i++)
		{
			Cst = ROL32_r(Cst_0, i - 1);
			X[0] ^= Cst;
			SubNibble_key(X);
			MixWord_key(X);

			if (Direction == 0)
				j = (i - 1) << 2;
			else
				j = (r - i + 1) << 2;

			X[0] ^= SK[j];
			X[1] ^= SK[j + 1];
			X[2] ^= SK[j + 2];
			X[3] ^= SK[j + 3];

			if (Direction == 0)
				j = (i + 1) << 2;
			else
				j = (r - i - 1) << 2;
			for (k = 0; k < 4; k++)
				SK[j + k] = X[k];
			u322char(X, Subkey, j << 2);
		}
	}
	else
		return -1;
	return 0;
}
/*
逐轮加密函数
X为输入明文，采用u32表示
Subkey输入Key_Schedule_u生成的加密密钥，长度为4*(r+1)字（4*(r+1)*32 bit）
CryptRound为加密轮数，CryptRound <= r
*/
void Crypt_Enc(u32 X[4], u32 *Subkey, int CryptRound)
{
	int j, k;

	X[0] = X[0] ^ Subkey[0];
	X[1] = X[1] ^ Subkey[1];
	X[2] = X[2] ^ Subkey[2];
	X[3] = X[3] ^ Subkey[3];

	for (j = 1;j <= CryptRound;j++)
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
X为输入密文，采用u32表示
Subkey输入Key_Schedule_u生成的解密密钥，长度为4*(r+1)字（4*(r+1)*32 bit）
*/
void Crypt_Dec(u32 X[4], u32 *Subkey)
{
	int j, k;

	X[0] = X[0] ^ Subkey[0];
	X[1] = X[1] ^ Subkey[1];
	X[2] = X[2] ^ Subkey[2];
	X[3] = X[3] ^ Subkey[3];

	for (j = 1;j <= r;j++)
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
ECB加密实现，采用8*128 bit分组，数据流不满足分组长度的部分直接丢弃
input为输入数据流，采用u8格式
in_len为输入数据长度，单位为字节（8bit），数据长度应不小于64， 否则返回-1
output为输出数据流，采用u8格式
out_len为输出数据长度，单位为字节（8bit），数据长度为64的倍数
key为初始密钥，采用u8格式
keylen为初始密钥长度，单位为字节（8bit），应为KEYLENGTH，否则返回-2
*/
int Crypt_Enc_Block(u8 *input, int in_len, u8 *output, int *out_len, u8 *key, int keylen)
{
	u32 SK[(r + 1) << 2];
	u32 X[4];
	int blocknum = in_len >> 7;
	int i, j, k;

	if (in_len < 16)
	{
		printf("The length of data less than 16 bytes, exit");
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
		int start = i << 7;
		int iv_pos = 0;
		u8 X[4][32];//按照256的字进行转换

		__m256i M0, M1, M2, M3;
		__m256i K0, K1, K2, K3;

		for (int k = 0; k < 8; k++)
		{
			for (int j = 0; j < 4; j++)
			{
				X[0][k * 4 + j] = input[start + (3 - j) + 16 * k];
				X[1][k * 4 + j] = input[start + (7 - j) + 16 * k];
				X[2][k * 4 + j] = input[start + (11 - j) + 16 * k];
				X[3][k * 4 + j] = input[start + (15 - j) + 16 * k];
			}
		}
		M0 = _mm256_loadu_si256((__m256i*)X[0]);
		M1 = _mm256_loadu_si256((__m256i*)X[1]);
		M2 = _mm256_loadu_si256((__m256i*)X[2]);
		M3 = _mm256_loadu_si256((__m256i*)X[3]);

		K0 = _mm256_set1_epi32(SK[0]);
		K1 = _mm256_set1_epi32(SK[1]);
		K2 = _mm256_set1_epi32(SK[2]);
		K3 = _mm256_set1_epi32(SK[3]);

		M0 = _mm256_xor_si256(M0, K0);
		M1 = _mm256_xor_si256(M1, K1);
		M2 = _mm256_xor_si256(M2, K2);
		M3 = _mm256_xor_si256(M3, K3);

		for (j = 1; j <= r; j++)
		{
			k = j << 2;

			RoundFunction_Enc_AVX(M0, M1, M2, M3);

			K0 = _mm256_set1_epi32(SK[k]);
			K1 = _mm256_set1_epi32(SK[k + 1]);
			K2 = _mm256_set1_epi32(SK[k + 2]);
			K3 = _mm256_set1_epi32(SK[k + 3]);

			M0 = _mm256_xor_si256(M0, K0);
			M1 = _mm256_xor_si256(M1, K1);
			M2 = _mm256_xor_si256(M2, K2);
			M3 = _mm256_xor_si256(M3, K3);
		}

		_mm256_storeu_si256((__m256i*)X[0], M0);
		_mm256_storeu_si256((__m256i*)X[1], M1);
		_mm256_storeu_si256((__m256i*)X[2], M2);
		_mm256_storeu_si256((__m256i*)X[3], M3);

		//输出转换
		for (int k = 0; k < 8; k++)
		{
			for (int j = 0; j < 4; j++)
			{
				output[start + (3 - j) + 16 * k] = X[0][k * 4 + j];
				output[start + (7 - j) + 16 * k] = X[1][k * 4 + j];
				output[start + (11 - j) + 16 * k] = X[2][k * 4 + j];
				output[start + (15 - j) + 16 * k] = X[3][k * 4 + j];
			}
		}
	}
	for (i = blocknum << 3; i < (in_len >> 4); i++)
	{
		j = i << 4;
		char2u32(input, X, j);

		Crypt_Enc(X, SK, r);

		u322char(X, output, j);
	}
	*out_len = (in_len >> 4)<<4;
	return 0;
}
/*
ECB解密实现，采用8*128 bit分组，数据流不满足分组长度的部分直接丢弃
input为输入数据流，采用u8格式
in_len为输入数据长度，单位为字节（8bit），数据长度应不小于64， 否则返回-1
output为输出数据流，采用u8格式
out_len为输出数据长度，单位为字节（8bit），out_len为64的倍数
key为初始密钥，采用u8格式
keylen为初始密钥长度，单位为字节（8bit），keylen应为KEYLENGTH，否则返回-2
*/
int Crypt_Dec_Block(u8 *input, int in_len, u8 *output, int *out_len, u8 *key, int keylen)
{
	u32 SK[(r + 1) << 2];
	u32 X[4];
	int blocknum = in_len >> 7;
	int i, j, k;

	if (in_len < 16)
	{
		printf("The length of data less than 16 bytes, exit");
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
		int start = i << 7;
		int iv_pos = 0;
		u8 X[4][32];//按照256的字进行转换

		__m256i M0, M1, M2, M3;
		__m256i K0, K1, K2, K3;

		for (int k = 0; k < 8; k++)
		{
			for (int j = 0; j < 4; j++)
			{
				X[0][k * 4 + j] = input[start + (3 - j) + 16 * k];
				X[1][k * 4 + j] = input[start + (7 - j) + 16 * k];
				X[2][k * 4 + j] = input[start + (11 - j) + 16 * k];
				X[3][k * 4 + j] = input[start + (15 - j) + 16 * k];
			}
		}
		M0 = _mm256_loadu_si256((__m256i*)X[0]);
		M1 = _mm256_loadu_si256((__m256i*)X[1]);
		M2 = _mm256_loadu_si256((__m256i*)X[2]);
		M3 = _mm256_loadu_si256((__m256i*)X[3]);

		K0 = _mm256_set1_epi32(SK[0]);
		K1 = _mm256_set1_epi32(SK[1]);
		K2 = _mm256_set1_epi32(SK[2]);
		K3 = _mm256_set1_epi32(SK[3]);

		M0 = _mm256_xor_si256(M0, K0);
		M1 = _mm256_xor_si256(M1, K1);
		M2 = _mm256_xor_si256(M2, K2);
		M3 = _mm256_xor_si256(M3, K3);

		for (j = 1; j <= r; j++)
		{
			k = j << 2;

			RoundFunction_Dec_AVX(M0, M1, M2, M3);

			K0 = _mm256_set1_epi32(SK[k]);
			K1 = _mm256_set1_epi32(SK[k + 1]);
			K2 = _mm256_set1_epi32(SK[k + 2]);
			K3 = _mm256_set1_epi32(SK[k + 3]);

			M0 = _mm256_xor_si256(M0, K0);
			M1 = _mm256_xor_si256(M1, K1);
			M2 = _mm256_xor_si256(M2, K2);
			M3 = _mm256_xor_si256(M3, K3);
		}

		_mm256_storeu_si256((__m256i*)X[0], M0);
		_mm256_storeu_si256((__m256i*)X[1], M1);
		_mm256_storeu_si256((__m256i*)X[2], M2);
		_mm256_storeu_si256((__m256i*)X[3], M3);

		//输出转换
		for (int k = 0; k < 8; k++)
		{
			for (int j = 0; j < 4; j++)
			{
				output[start + (3 - j) + 16 * k] = X[0][k * 4 + j];
				output[start + (7 - j) + 16 * k] = X[1][k * 4 + j];
				output[start + (11 - j) + 16 * k] = X[2][k * 4 + j];
				output[start + (15 - j) + 16 * k] = X[3][k * 4 + j];
			}
		}
	}
	for (i = blocknum << 3; i < (in_len >> 4); i++)
	{
		j = i << 4;
		char2u32(input, X, j);

		Crypt_Dec(X, SK);

		u322char(X, output, j);
	}

	*out_len = (in_len >> 4) << 4;
	return 0;
}
/*
ECB加密实现，采用8*128 bit分组，数据流不满足分组长度的部分直接丢弃
input为输入数据流，采用u8格式
in_len为输入数据长度，单位为字节（8bit），数据长度应不小于64， 否则返回-1
output为输出数据流，采用u8格式
out_len为输出数据长度，单位为字节（8bit），数据长度为64的倍数
key为初始密钥，采用u8格式
keylen为初始密钥长度，单位为字节（8bit），应为KEYLENGTH，否则返回-2
*/
int Crypt_Enc_Block_Round(u8 *input, int in_len, u8 *output, int *out_len, u8 *key, int keylen, int CryptRound)
{
	u32 SK[(r + 1) << 2];
	u32 X[4];
	int blocknum = in_len >> 7;
	int i, j, k;

	if (in_len < 16)
	{
		printf("The length of data less than 16 bytes, exit");
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
		int start = i << 7;
		int iv_pos = 0;
		u8 X[4][32];//按照256的字进行转换

		__m256i M0, M1, M2, M3;
		__m256i K0, K1, K2, K3;

		for (int k = 0; k < 8; k++)
		{
			for (int j = 0; j < 4; j++)
			{
				X[0][k * 4 + j] = input[start + (3 - j) + 16 * k];
				X[1][k * 4 + j] = input[start + (7 - j) + 16 * k];
				X[2][k * 4 + j] = input[start + (11 - j) + 16 * k];
				X[3][k * 4 + j] = input[start + (15 - j) + 16 * k];
			}
		}
		M0 = _mm256_loadu_si256((__m256i*)X[0]);
		M1 = _mm256_loadu_si256((__m256i*)X[1]);
		M2 = _mm256_loadu_si256((__m256i*)X[2]);
		M3 = _mm256_loadu_si256((__m256i*)X[3]);

		K0 = _mm256_set1_epi32(SK[0]);
		K1 = _mm256_set1_epi32(SK[1]);
		K2 = _mm256_set1_epi32(SK[2]);
		K3 = _mm256_set1_epi32(SK[3]);

		M0 = _mm256_xor_si256(M0, K0);
		M1 = _mm256_xor_si256(M1, K1);
		M2 = _mm256_xor_si256(M2, K2);
		M3 = _mm256_xor_si256(M3, K3);

		for (j = 1; j <= CryptRound; j++)
		{
			k = j << 2;

			RoundFunction_Enc_AVX(M0, M1, M2, M3);

			K0 = _mm256_set1_epi32(SK[k]);
			K1 = _mm256_set1_epi32(SK[k + 1]);
			K2 = _mm256_set1_epi32(SK[k + 2]);
			K3 = _mm256_set1_epi32(SK[k + 3]);

			M0 = _mm256_xor_si256(M0, K0);
			M1 = _mm256_xor_si256(M1, K1);
			M2 = _mm256_xor_si256(M2, K2);
			M3 = _mm256_xor_si256(M3, K3);
		}

		_mm256_storeu_si256((__m256i*)X[0], M0);
		_mm256_storeu_si256((__m256i*)X[1], M1);
		_mm256_storeu_si256((__m256i*)X[2], M2);
		_mm256_storeu_si256((__m256i*)X[3], M3);

		//输出转换
		for (int k = 0; k < 8; k++)
		{
			for (int j = 0; j < 4; j++)
			{
				output[start + (3 - j) + 16 * k] = X[0][k * 4 + j];
				output[start + (7 - j) + 16 * k] = X[1][k * 4 + j];
				output[start + (11 - j) + 16 * k] = X[2][k * 4 + j];
				output[start + (15 - j) + 16 * k] = X[3][k * 4 + j];
			}
		}
	}

	for (i = blocknum << 3; i < (in_len >> 4); i++)
	{
		j = i << 4;
		char2u32(input, X, j);

		Crypt_Enc(X, SK, CryptRound);

		u322char(X, output, j);
	}

	*out_len = (in_len >> 4) << 4;
	return 0;
}
/*
CBC加密实现，采用128 bit分组，数据流不满足分组长度的部分直接丢弃
input为输入数据流，采用u8格式
in_len为输入数据长度，单位为字节（8bit），数据长度应不小于16， 否则返回-1
output为输出数据流，采用u8格式
out_len为输出数据长度，单位为字节（8bit），数据长度为16的倍数
key为初始密钥，采用u8格式
keylen为初始密钥长度，单位为字节（8bit），应为KEYLENGTH，否则返回-2
*/
int Crypt_Enc_Block_CBC(u8 *input, int in_len, u8 *output, int *out_len, u8 *key, int keylen)
{
	u32 X[4];
	u32 Y[4] = { 0,0,0,0 };
	u32 SK[(r + 1) << 2];
	int blocknum = in_len >> 4;
	int i, j;

	if (in_len < 16)
	{
		printf("The in_len of data less than 16, exit");
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
		j = i << 4;
		char2u32(input, X, j);

		Y[0] = X[0] ^ Y[0];
		Y[1] = X[1] ^ Y[1];
		Y[2] = X[2] ^ Y[2];
		Y[3] = X[3] ^ Y[3];
		Crypt_Enc(Y, SK, r);

		u322char(Y, output, j);
	}

	*out_len = (in_len >> 4) << 4;
	return 0;
}
/*
CBC解密实现，采用8*128 bit分组，数据流不满足分组长度的部分直接丢弃
input为输入数据流，采用u8格式
in_len为输入数据长度，单位为字节（8bit），数据长度应不小于64， 否则返回-1
output为输出数据流，采用u8格式
out_len为输出数据长度，单位为字节（8bit），out_len为64的倍数
key为初始密钥，采用u8格式
keylen为初始密钥长度，单位为字节（8bit），keylen应为KEYLENGTH，否则返回-2
*/
int Crypt_Dec_Block_CBC(u8 *input, int in_len, u8 *output, int *out_len, u8 *key, int keylen)
{
	u32 SK[(r + 1) << 2];
	u32 X[4];
	u32 Y[4] = { 0,0,0,0 };
	u32 Z[4];
	int blocknum = in_len >> 7;
	int i, j, k;

	if (in_len < 16)
	{
		printf("The length of data less than 16 bytes, exit");
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
		int start = i << 7;
		int iv_pos = 0;
		u8 X[4][40];

		__m256i M0, M1, M2, M3;
		__m256i K0, K1, K2, K3;
		__m256i M4, M5, M6, M7;

		if (i == 0)
		{
			//初始IV 
			for (int j = 0; j < 4; j++)
			{
				X[0][j] = 0;
				X[1][j] = 0;
				X[2][j] = 0;
				X[3][j] = 0;
			}
			iv_pos = 0;
			for (int k = 0; k < 8; k++)
			{
				for (int j = 0; j < 4; j++)
				{
					X[0][4 + k * 4 + j] = input[iv_pos + (3 - j) + 16 * k];
					X[1][4 + k * 4 + j] = input[iv_pos + (7 - j) + 16 * k];
					X[2][4 + k * 4 + j] = input[iv_pos + (11 - j) + 16 * k];
					X[3][4 + k * 4 + j] = input[iv_pos + (15 - j) + 16 * k];
				}
			}
		}
		else
		{
			iv_pos = (i << 7) - 16;
			for (int k = 0; k < 9; k++)
			{
				for (int j = 0; j < 4; j++)
				{
					X[0][k * 4 + j] = input[iv_pos + (3 - j) + 16 * k];
					X[1][k * 4 + j] = input[iv_pos + (7 - j) + 16 * k];
					X[2][k * 4 + j] = input[iv_pos + (11 - j) + 16 * k];
					X[3][k * 4 + j] = input[iv_pos + (15 - j) + 16 * k];
				}
			}
		}

		M0 = _mm256_loadu_si256((__m256i*)(X[0] + 4));
		M1 = _mm256_loadu_si256((__m256i*)(X[1] + 4));
		M2 = _mm256_loadu_si256((__m256i*)(X[2] + 4));
		M3 = _mm256_loadu_si256((__m256i*)(X[3] + 4));
		M4 = _mm256_loadu_si256((__m256i*)X[0]);
		M5 = _mm256_loadu_si256((__m256i*)X[1]);
		M6 = _mm256_loadu_si256((__m256i*)X[2]);
		M7 = _mm256_loadu_si256((__m256i*)X[3]);

		K0 = _mm256_set1_epi32(SK[0]);
		K1 = _mm256_set1_epi32(SK[1]);
		K2 = _mm256_set1_epi32(SK[2]);
		K3 = _mm256_set1_epi32(SK[3]);

		M0 = _mm256_xor_si256(M0, K0);
		M1 = _mm256_xor_si256(M1, K1);
		M2 = _mm256_xor_si256(M2, K2);
		M3 = _mm256_xor_si256(M3, K3);

		for (j = 1; j <= r; j++)
		{
			k = j << 2;

			RoundFunction_Dec_AVX(M0, M1, M2, M3);

			K0 = _mm256_set1_epi32(SK[k]);
			K1 = _mm256_set1_epi32(SK[k + 1]);
			K2 = _mm256_set1_epi32(SK[k + 2]);
			K3 = _mm256_set1_epi32(SK[k + 3]);

			M0 = _mm256_xor_si256(M0, K0);
			M1 = _mm256_xor_si256(M1, K1);
			M2 = _mm256_xor_si256(M2, K2);
			M3 = _mm256_xor_si256(M3, K3);
		}

		M0 = _mm256_xor_si256(M0, M4);
		M1 = _mm256_xor_si256(M1, M5);
		M2 = _mm256_xor_si256(M2, M6);
		M3 = _mm256_xor_si256(M3, M7);

		_mm256_storeu_si256((__m256i*)X[0], M0);
		_mm256_storeu_si256((__m256i*)X[1], M1);
		_mm256_storeu_si256((__m256i*)X[2], M2);
		_mm256_storeu_si256((__m256i*)X[3], M3);

		//输出转换
		for (int k = 0; k < 8; k++)
		{
			for (int j = 0; j < 4; j++)
			{
				output[start + (3 - j) + 16 * k] = X[0][k * 4 + j];
				output[start + (7 - j) + 16 * k] = X[1][k * 4 + j];
				output[start + (11 - j) + 16 * k] = X[2][k * 4 + j];
				output[start + (15 - j) + 16 * k] = X[3][k * 4 + j];
			}
		}
	}
	if (i > 0)
		char2u32(input, Y, (blocknum << 7) - 16);
	for (i = blocknum << 3; i < (in_len >> 4); i++)
	{
		j = i << 4;
		char2u32(input, X, j);
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

		u322char(X, output, j);
	}
	*out_len = (in_len >> 4) << 4;
	return 0;
}

void verify_CBC_128_256()
{
	u8 * in;
	u8 * in2;
	u8 * output;
	u8 key[32] = { 1, 2, 3, 4, 5, 6, 7, 8, 0xa, 0xd, 3, 8, 2, 6, 3, 9 };
	int N_array[10] = { 272, 512, 1024, 2048, 5 * 1024, 10 * 1024, 20 * 1024, 100 * 1024, 500 * 1024, 1024 * 1024 };
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
	verify_CBC_128_256();
//	testspeed();
	//testspeed_cycle();
}