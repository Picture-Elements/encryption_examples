/*
 * Copyright (c) 2015 Picture Elements, Inc.
 *    Stephen Williams (steve@icarus.com)
 *

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.
    * Neither the name of the <organization> nor the
      names of its contributors may be used to endorse or promote products
      derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS

*/

# include  <inttypes.h>
# include  <stdio.h>
# include  <string.h>
# include  <openssl/evp.h>
# include  <openssl/pem.h>
# include  <assert.h>

/*
 * In PDFRaster public key encryption, the AES-256-CBC symmetric
 * cipher is used to do the bulk encryption of data. The data is
 * encrypted with a session key that is randomized, then encrypted
 * using a public key cipher. The receiver uses the private key to
 * recover the session key, which is in turn used to decrypt the bulk
 * data.
 *
 * The public key cipher is not used directly to encrypt the bulk
 * stream because it is not well suited (computationally) to
 * encrypting large amounts of data. Also, if we want to target
 * multiple recipients, we can encrypt the session key for each
 * recipient, instead of encrypting the entire document for each
 * recipient.
 */

/*
 * The AES256 symmetric cipher uses a 256bit "key" and a 128bit
 * initialization vector.
 *
 * The initialization vector is as random as possible for each
 * session. When used, it doesn't need to be kept secret, and in fact
 * for the PDF standard, the ivec (16 bytes) is prepended to the
 * encrypted byte array and sent along as is.
 *
 * All the secrecy is in the 256/8==32byte ckey. This key is what is
 * calculated from the session key. It is either generated from the
 * password, or from the public keys and a session key.
 */
struct AES256_Key {
      unsigned char ckey[32];
      unsigned char ivec[16];
};

struct Enveloped_Data {
      uint8_t seed[20];
      uint32_t permissions;
};

/*
 * Here is an AES-256-CBC encryption of an input data stream. The
 * input is the source data and the session key, and the output is the
 * cipher text. Note that the cipher text may be a bit bigger (up to a
 * block) then the plain text.
 */
static int encrypt_data(unsigned char*dst, size_t ndst, const unsigned char*src, size_t nsrc, const struct AES256_Key*key)
{

	/* Initialize the encryption engine, selecting the encryption
	   mode and the encryption key. */
      EVP_CIPHER_CTX ctx;
      EVP_EncryptInit(&ctx,EVP_aes_256_cbc(), key->ckey, key->ivec);

	/* Encrypt data. The data can be encrypted in one shot, or by
	   repeated calls, eachadding more src data until done. */
      assert(ndst >= (nsrc + EVP_CIPHER_CTX_block_size(&ctx) - 1));
      int cur_out = 0;
      EVP_EncryptUpdate(&ctx, dst, &cur_out, src, nsrc);

	/* Wrap it up. This will cause any tail data to be emitted to
	   complete the encryption stream. */
      int final_out = 0;
      EVP_EncryptFinal(&ctx, dst+cur_out, &final_out);

	/* Our output byte count. */
      int total_out = cur_out + final_out;
      assert(total_out <= ndst);

      return total_out;
}

/*
 * Here is an AES-256-CBC decryption of cipher text back to the input
 * plain text. The and initialization vector must be identical to
 * those used to encrypt the data in the first place. In a PDF stream,
 * the initialization vector can be pulled off the front of the
 * encrypted data, but for our test we simply remembered it from before.
 */
static int decrypt_data(unsigned char*dst, size_t ndst, const unsigned char*src, size_t nsrc, const struct AES256_Key*key)
{
	/* Initialize the decryption engine, selecting the encryption
	   mode and the decryption key. */
      EVP_CIPHER_CTX ctx;
      EVP_DecryptInit(&ctx,EVP_aes_256_cbc(), key->ckey, key->ivec);

	/* Decrypt data. The data can be decrypted in one shot, or by
	   repeated calls, adding more src data until done. */
      assert(ndst >= nsrc);
      int cur_out = 0;
      EVP_DecryptUpdate(&ctx, dst, &cur_out, src, nsrc);

	/* Wrap it up. This will cause any tail data to be emitted to
	   complete the decryption stream. */
      int final_out = 0;
      EVP_DecryptFinal(&ctx, dst+cur_out, &final_out);

	/* Our output byte count. */
      int total_out = cur_out + final_out;
      assert(total_out <= ndst);

      return total_out;
}

/*
 * The "enveloped data" is the payload of the PKCS#7 objects that hold
 * encrypted keys. The "seed" part is as random as possible and is,
 * essentially, the session key for this document. All the recipients
 * identified in a PKCS#7 object have the same permissions, so the
 * enveloped data includes a permissions word. The Enveloped data is
 * stored in the PKCS#7 packet encrypted by AES-256-CBC using yet
 * another key.
 *
 * If there are multiple PKCS#7 packets in the PDF file, they all have
 * their own enveloped data (24 bytes) but they must have the
 * identical seed data, because that is what's used to decrypt the
 * document.
 */
static void generate_enveloped_data(struct Enveloped_Data*data, uint32_t perms)
{
      data->permissions = perms;

      int idx;
      for (idx = 0 ; idx < sizeof data->seed ; idx += 1)
	    data->seed[idx] = random() % 256;

}

/*
 * The AES-256-CBC key is generated from the seed that all the PKCS#7
 * objects carry in their enveloped data, and the bytes of all the
 * PKCS#7 objects. This forces the document to be broken if any of the
 * PKCS#7 objects are tampered with, added, or removed.
 *
 * [NOTE: The PDF-32000-1:2008 book says to use SHA-1 to digest the
 * components to generate the session key, but SHA-1 only returns 20
 * bytes where we need 32 bytes. Don't they mean to use SHA256 here?]
 */
static void generate_aes256_key(struct AES256_Key*key, const uint8_t seed[20])
{
      SHA256_CTX sha;
      SHA256_Init(&sha);

	/* Include the seed... */
      SHA256_Update(&sha, seed, 20);

	/* Include all the PKCS#7 objects... */

	/* [This is where we include the byte encodings of all the
	   PKCS#7 objects.] */

	/* Done */
      uint8_t digest [SHA256_DIGEST_LENGTH];
      SHA256_Final(digest, &sha);

      assert(sizeof digest >= sizeof key->ckey);
      memcpy(key->ckey, digest, sizeof key->ckey);

	/* This is assuming we are on the encryption side, so we
	   generate a completely random initialization vector. On the
	   decryption side, we actually get the initialization vector
	   from the cipher stream, transmitted as plain text. */
      int idx;
      for (idx = 0 ; idx < sizeof key->ivec ; idx += 1)
	    key->ivec[idx] = random() % 256;
}

/*
 * The receiver recovers the AES-256-CBC key from the enveloped data
 * and the initialization. In particular, the enveloped data contains
 * a 20 byte seed and the first 16 bytes of the cipher text are the
 * initialization vector. Those, along with all the PCKS#7 objects in
 * order, are sufficient to reciver the AES keys.
 */
static void recover_aes256_key(struct AES256_Key*key, const uint8_t seed[20], const uint8_t*ivec)
{
      SHA256_CTX sha;
      SHA256_Init(&sha);

	/* Include the seed... */
      SHA256_Update(&sha, seed, 20);

	/* Include all the PKCS#7 objects... */

	/* [This is where we include the byte encodings of all the
	   PKCS#7 objects.] */

	/* Done */
      uint8_t digest [SHA256_DIGEST_LENGTH];
      SHA256_Final(digest, &sha);

      assert(sizeof digest >= sizeof key->ckey);
      memcpy(key->ckey, digest, sizeof key->ckey);

      memcpy(key->ivec, ivec, sizeof key->ivec);
}

int main(int argc, char*argv[])
{
#if 0
      if (argc != 2) {
	    fprintf(stderr, "Usage: %s <keys>.pem\n", argv[0]);
	    return -1;
      }
#endif

	/* Generate the Enveloped_Data from the intended
	   permissions. Each PKCS#7 object gets a single enveloped
	   object. But note that if we were really to create multiple
	   PKCS#7 objects, and thus multiple Enveloped_Data objects,
	   they all should have the same seed. */
      struct Enveloped_Data enveloped_data;
      generate_enveloped_data(&enveloped_data, 0x00000000);

	/* Make a PKCS#7 object from the recipient public key. In a
	   proper system we would be able to make a PKCS#7 object from
	   multiple recipients. */
	/* XXXX NOT IMPLEMENTED XXXX */

	/* Use the PKCS#7 objects and the seed to generate the
	   AES-256-CBC key. */
      struct AES256_Key key;
      generate_aes256_key(&key, enveloped_data.seed);


	/* Make some fake plain-text data. */
      unsigned char src[256];
      memset(src, 'a', sizeof src);

	/* Encrypt the data. Note that the cipher stream may be up to
	   128 bits (16 bytes) longer then the input, and will be
	   prepended with the 16 bytes of the initiazation vector. */
      unsigned char crpt[16+sizeof src+16];
      memcpy(crpt, key.ivec, 16);
      int ncrpt = encrypt_data(crpt+16, sizeof crpt - 16, src, sizeof src, &key);
      printf("encrypt_data returned %d, stream is %d bytes\n", ncrpt, ncrpt+16);
      ncrpt += 16;

	/* At this point, the crpt array contains the encrypted
	   stream, including the initialization vector. This is what
	   is written into the file.  The enveloped data is wrapped
	   into PKCS#7 objects that are delivered as meta-data in the
	   PDF file. */


	/* Now for the decrypt side. We first get the PKCS#7 objects
	   from the PDF headers, and based on the recipient, select
	   the correct one. The PKCS#7 objects contain the
	   Enveloped_Data. Use that and the first 16 bytes of the
	   cipher text to recover the AES256 key. */
      recover_aes256_key(&key, enveloped_data.seed, crpt);


	/* Decrypt the data. Note that the plain text will be no
	   longer than the cipher text, less the 16 bytes of
	   initialization vector. */
      unsigned char dst[sizeof crpt - 16];

      int ndst = decrypt_data(dst, sizeof dst, crpt+16, ncrpt-16, &key);
      printf("decrypt_data returned %d\n", ndst);

      assert(ndst == sizeof src);
      if (memcmp(src, dst, ndst) == 0) {
	    printf("Hooray, data is decrypted!\n");
      } else {
	    printf("Boo, data mismatch:-(\n");
      }

      return 0;
}
