/*
 * Copyright (C) 2012 Jeremy Kerr <jeremy.kerr@canonical.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 3
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,
 * USA.
 *
 * In addition, as a special exception, the copyright holders give
 * permission to link the code of portions of this program with the OpenSSL
 * library under certain conditions as described in each individual source file,
 * and distribute linked combinations including the two.
 *
 * You must obey the GNU General Public License in all respects for all
 * of the code used other than OpenSSL. If you modify file(s) with this
 * exception, you may extend this exception to your version of the
 * file(s), but you are not obligated to do so. If you do not wish to do
 * so, delete this exception statement from your version. If you delete
 * this exception statement from all source files in the program, then
 * also delete it here.
 */
#include <stdint.h>
#include <string.h>
#include <openssl/asn1t.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/pkcs7.h>
#include <openssl/x509.h>
#include <openssl/ec.h>

#include <ccan/talloc/talloc.h>

#include "idc.h"

typedef struct idc_type_value {
	ASN1_OBJECT		*type;
	ASN1_TYPE		*value;
} IDC_TYPE_VALUE;

ASN1_SEQUENCE(IDC_TYPE_VALUE) = {
	ASN1_SIMPLE(IDC_TYPE_VALUE, type, ASN1_OBJECT),
	ASN1_OPT(IDC_TYPE_VALUE, value, ASN1_ANY),
} ASN1_SEQUENCE_END(IDC_TYPE_VALUE);

IMPLEMENT_ASN1_FUNCTIONS(IDC_TYPE_VALUE);

typedef struct idc_string {
	int type;
	union {
		ASN1_BMPSTRING	*unicode;
		ASN1_IA5STRING	*ascii;
	} value;
} IDC_STRING;

ASN1_CHOICE(IDC_STRING) = {
	ASN1_IMP(IDC_STRING, value.unicode, ASN1_BMPSTRING, 0),
	ASN1_IMP(IDC_STRING, value.ascii, ASN1_IA5STRING, 1),
} ASN1_CHOICE_END(IDC_STRING);

IMPLEMENT_ASN1_FUNCTIONS(IDC_STRING);

typedef struct idc_link {
	int type;
	union {
		ASN1_NULL	*url;
		ASN1_NULL	*moniker;
		IDC_STRING	*file;
	} value;
} IDC_LINK;

ASN1_CHOICE(IDC_LINK) = {
	ASN1_IMP(IDC_LINK, value.url, ASN1_NULL, 0),
	ASN1_IMP(IDC_LINK, value.moniker, ASN1_NULL, 1),
	ASN1_EXP(IDC_LINK, value.file, IDC_STRING, 2),
} ASN1_CHOICE_END(IDC_LINK);

IMPLEMENT_ASN1_FUNCTIONS(IDC_LINK);

typedef struct idc_pe_image_data {
        ASN1_BIT_STRING		*flags;
        IDC_LINK		*file;
} IDC_PEID;

ASN1_SEQUENCE(IDC_PEID) = {
        ASN1_SIMPLE(IDC_PEID, flags, ASN1_BIT_STRING),
        ASN1_EXP(IDC_PEID, file, IDC_LINK, 0),
} ASN1_SEQUENCE_END(IDC_PEID);

IMPLEMENT_ASN1_FUNCTIONS(IDC_PEID);

typedef struct idc_digest {
        X509_ALGOR              *alg;
        ASN1_OCTET_STRING       *digest;
} IDC_DIGEST;

ASN1_SEQUENCE(IDC_DIGEST) = {
        ASN1_SIMPLE(IDC_DIGEST, alg, X509_ALGOR),
        ASN1_SIMPLE(IDC_DIGEST, digest, ASN1_OCTET_STRING),
} ASN1_SEQUENCE_END(IDC_DIGEST)

IMPLEMENT_ASN1_FUNCTIONS(IDC_DIGEST)

typedef struct idc {
        IDC_TYPE_VALUE  *data;
        IDC_DIGEST      *digest;
} IDC;

ASN1_SEQUENCE(IDC) = {
        ASN1_SIMPLE(IDC, data, IDC_TYPE_VALUE),
        ASN1_SIMPLE(IDC, digest, IDC_DIGEST),
} ASN1_SEQUENCE_END(IDC)

IMPLEMENT_ASN1_FUNCTIONS(IDC)

#define DEFAULT_DIGEST_LENGTH 32

static int type_set_sequence(void *ctx, ASN1_TYPE *type,
		void *s, const ASN1_ITEM *it)
{
	uint8_t *seq_data, *tmp;
	ASN1_OCTET_STRING *os;
	ASN1_STRING *seq = s;
	int len;

	os = ASN1_STRING_new();

	len = ASN1_item_i2d((ASN1_VALUE *)seq, NULL, it);
	tmp = seq_data = talloc_array(ctx, uint8_t, len);
	ASN1_item_i2d((ASN1_VALUE *)seq, &tmp, it);

	ASN1_STRING_set(os, seq_data, len);
	ASN1_TYPE_set(type, V_ASN1_SEQUENCE, os);
	return 0;
}

const char obsolete[] = {
	0x00, 0x3c, 0x00, 0x3c, 0x00, 0x3c, 0x00, 0x4f, 0x00, 0x62,
	0x00, 0x73, 0x00, 0x6f, 0x00, 0x6c, 0x00, 0x65, 0x00, 0x74,
	0x00, 0x65, 0x00, 0x3e, 0x00, 0x3e, 0x00, 0x3e
};


static int PKCS7_type_is_other(PKCS7 *p7)
{
	int isOther = 1;

	int nid = OBJ_obj2nid(p7->type);

	switch (nid) {
	case NID_pkcs7_data:
	case NID_pkcs7_signed:
	case NID_pkcs7_enveloped:
	case NID_pkcs7_signedAndEnveloped:
	case NID_pkcs7_digest:
	case NID_pkcs7_encrypted:
		isOther = 0;
		break;
	default:
		isOther = 1;
	}

	return isOther;
};

static ASN1_OCTET_STRING *PKCS7_get_octet_string(PKCS7 *p7)
{
	if (PKCS7_type_is_data(p7))
		return p7->d.data;
	if (PKCS7_type_is_other(p7) && p7->d.other && (p7->d.other->type == V_ASN1_OCTET_STRING))
		return p7->d.other->value.octet_string;
	return NULL;
};

const char *hash_str(const uint8_t *hash)
{
	static char s[DEFAULT_DIGEST_LENGTH * 2 + 1];
	int i;

	for (i = 0; i < DEFAULT_DIGEST_LENGTH; i++)
		snprintf(s + i * 2, 3, "%02x", hash[i]);

	return s;
}

static unsigned char* sha256_data(char* data, int data_size)
{
	unsigned char digest[SHA256_DIGEST_LENGTH] = {};

	SHA256_CTX sc;
	SHA256_Init(&sc);
	SHA256_Update(&sc, data, data_size);
	SHA256_Final(digest, &sc);

	char *ret = calloc(SHA256_DIGEST_LENGTH, sizeof(char));
	memcpy(ret, digest, SHA256_DIGEST_LENGTH);
	return ret;
}

static unsigned char* sm3_data(char* data, int data_size)
{
	unsigned char digest[32] = {};

	EVP_MD_CTX *md_ctx;
	const EVP_MD *md;
	md = EVP_sm3();
	md_ctx = EVP_MD_CTX_new();
	EVP_DigestInit_ex(md_ctx,md,NULL);
	EVP_DigestUpdate(md_ctx,data,data_size);
	EVP_DigestFinal_ex(md_ctx,digest,NULL);

	char *ret = calloc(32, sizeof(char));
	memcpy(ret, digest, 32);
	return ret;
}

int rsa_sign_it(const unsigned char *msg,int msg_len, EVP_PKEY *pkey,
                       unsigned char **sig_data, int *slen) {

	EVP_MD_CTX *mdctx = NULL;
	*sig_data = NULL;
	*slen = 0;

	if (!(mdctx = EVP_MD_CTX_create()))
		goto err;

	if (!EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, pkey))
		goto err;

	if (!EVP_DigestSignUpdate(mdctx, msg, msg_len))
		goto err;

	if (!EVP_DigestSignFinal(mdctx, NULL, slen))
		goto err;

	unsigned char *tmp;
	if (!(tmp = OPENSSL_malloc(sizeof(unsigned char) * (*slen)))) {
		printf("malloc failed\n");
		goto err;
	}

	if (!EVP_DigestSignFinal(mdctx, tmp, slen))
		goto err;

	*sig_data = tmp;
	EVP_MD_CTX_free(mdctx);
	return 1;
err:
	if (mdctx !=NULL)
		EVP_MD_CTX_free(mdctx);
	if (tmp !=NULL)
		free(tmp);
	return -1;
}

int sm2_sign_it(const unsigned char *msg,int msg_len, EVP_PKEY *pkey,
                       unsigned char **sig_data, int *slen) {

	*sig_data = NULL;
	*slen = 0;

	if (!EVP_PKEY_set_alias_type(pkey, EVP_PKEY_SM2))
	{
		printf("EVP_PKEY_set_alias_type() fail!!\n");
		goto err;
	}

	EVP_MD_CTX *md_sign_ctx = EVP_MD_CTX_new();
	if (md_sign_ctx ==NULL){
		printf("md_sign_ctx fail!!\n");
		goto err;
	}
	EVP_MD_CTX_init(md_sign_ctx);
	if(!EVP_SignInit_ex(md_sign_ctx, EVP_sm3(),NULL))
	{
		printf("EVP_SignInit_ex() fail!!\n");
		goto err;
	}

	if(!EVP_SignUpdate(md_sign_ctx,msg,msg_len))
	{
		printf("EVP_SignUpdate() fail!!\n");
		goto err;
	}
	if(!EVP_SignFinal(md_sign_ctx,NULL,slen,pkey)){
		printf("EVP_SignFinal() fail!!\n");
		goto err;
	}

	unsigned char *sig_tmp = NULL;
	if (!(sig_tmp = (unsigned char *)malloc(*slen)))
	{
		goto err;
	}

	if(!EVP_SignFinal(md_sign_ctx,sig_tmp,slen,pkey)){
		printf("EVP_SignFinal() fail!!\n");
		goto err;
	}
	*sig_data = sig_tmp;

	EVP_MD_CTX_free(md_sign_ctx);
	return 1;
err:
	if (md_sign_ctx !=NULL)
		EVP_PKEY_CTX_free(md_sign_ctx);
	if (sig_tmp !=NULL)
		free(sig_tmp);

	return -1;
}

int IDC_set(PKCS7 *p7, PKCS7_SIGNER_INFO *si, struct image *image)
{
	uint8_t *buf, *tmp, sha[DEFAULT_DIGEST_LENGTH];
	int idc_nid, peid_nid, len, rc;
	IDC_PEID *peid;
	ASN1_STRING *s;
	ASN1_TYPE *t;
	BIO *sigbio;
	IDC *idc;

	idc_nid = OBJ_create("1.3.6.1.4.1.311.2.1.4",
			"spcIndirectDataContext",
			"Indirect Data Context");
	peid_nid = OBJ_create("1.3.6.1.4.1.311.2.1.15",
			"spcPEImageData",
			"PE Image Data");

	if (OBJ_obj2nid(si->digest_alg->algorithm)==NID_sha256){
		image_hash_sha256(image, sha);
	}
	else if (OBJ_obj2nid(si->digest_alg->algorithm) == NID_sm3){
		image_hash_sm3(image, sha);
	}
	else{
		fprintf(stderr, "Invalid signature algorithm type\n");
		return -1;
	}

	idc = IDC_new();
	peid = IDC_PEID_new();

	peid->file = IDC_LINK_new();
	peid->file->type = 2;
	peid->file->value.file = IDC_STRING_new();
	peid->file->value.file->type = 0;
	peid->file->value.file->value.unicode = ASN1_STRING_new();
	ASN1_STRING_set(peid->file->value.file->value.unicode,
			obsolete, sizeof(obsolete));

	idc->data->type = OBJ_nid2obj(peid_nid);
	idc->data->value = ASN1_TYPE_new();
	type_set_sequence(image, idc->data->value, peid, &IDC_PEID_it);

        idc->digest->alg->parameter = ASN1_TYPE_new();
        idc->digest->alg->algorithm =  si->digest_alg->algorithm;
        idc->digest->alg->parameter->type = V_ASN1_NULL;
        ASN1_OCTET_STRING_set(idc->digest->digest, sha, sizeof(sha));

	len = i2d_IDC(idc, NULL);
	tmp = buf = talloc_array(image, uint8_t, len);
	i2d_IDC(idc, &tmp);

	/* Add the contentType authenticated attribute */
	PKCS7_add_signed_attribute(si, NID_pkcs9_contentType, V_ASN1_OBJECT,
						OBJ_nid2obj(idc_nid));

	/* Because the PKCS7 lib has a hard time dealing with non-standard
	 * data types, we create a temporary BIO to hold the signed data, so
	 * that the top-level PKCS7 object calculates the correct hash...
	 */
	// sigbio = PKCS7_dataInit(p7, NULL);
	// BIO_write(sigbio, buf+2, len-2);

	// /* ... then we finalise the p7 content, which does the actual
	//  * signing ... */
	// rc = PKCS7_dataFinal(p7, sigbio);
	// if (!rc) {
	// 	fprintf(stderr, "dataFinal failed\n");
	// 	ERR_print_errors_fp(stderr);
	// 	return -1;
	// }

	/* pkey_sm2_ctrl不支持EVP_PKEY_CTRL_PKCS7_SIGN类型，无法通过
	 EVP_PKEY_CTX_ctrl调用，不能使用PKCS7_dataFinal来gm签名*/

	if (!PKCS7_get_signed_attribute(si,NID_pkcs9_signingTime)){
		PKCS7_add0_attrib_signing_time(si, NULL);
	}

	unsigned char *msg_digest = NULL;
	if (OBJ_obj2nid(si->digest_alg->algorithm)==NID_sha256){
		msg_digest = sha256_data((char *)(buf + 2), len - 2);
	}
	else if (OBJ_obj2nid(si->digest_alg->algorithm)==NID_sm3){
		msg_digest = sm3_data((char *)(buf + 2), len - 2);
	}
	PKCS7_add1_attrib_digest(si,msg_digest,DEFAULT_DIGEST_LENGTH);
	free(msg_digest);

	unsigned char *aattr_buf = NULL;
	int aattr_buflen = ASN1_item_i2d((ASN1_VALUE *)(si->auth_attr), &aattr_buf, ASN1_ITEM_rptr(PKCS7_ATTR_SIGN));

	unsigned char *enc_digest = NULL;
	int enc_len;
	if (OBJ_obj2nid(si->digest_alg->algorithm)==NID_sha256 && si->pkey != NULL){
		rc=rsa_sign_it(aattr_buf,aattr_buflen, si->pkey, &enc_digest, &enc_len);
	}else if (OBJ_obj2nid(si->digest_alg->algorithm)==NID_sm3 && si->pkey != NULL){
		rc=sm2_sign_it(aattr_buf,aattr_buflen, si->pkey, &enc_digest, &enc_len);
	}
	if (rc <= 0){
		printf("sign fail!!\n");
		return -1;
	}
	ASN1_STRING_set0(si->enc_digest,enc_digest,enc_len);

	ASN1_OCTET_STRING *sign_contents = PKCS7_get_octet_string(p7->d.sign->contents);
	if (!PKCS7_is_detached(p7) && !(sign_contents->flags & ASN1_STRING_FLAG_NDEF)){
		ASN1_STRING_set0(sign_contents, (buf+2), len-2);
	}

	/* ... and we replace the content with the actual IDC ASN type. */
	t = ASN1_TYPE_new();
	s = ASN1_STRING_new();
	ASN1_STRING_set(s, buf, len);
	ASN1_TYPE_set(t, V_ASN1_SEQUENCE, s);
	PKCS7_set0_type_other(p7->d.sign->contents, idc_nid, t);

	return 0;
}

struct idc *IDC_get(PKCS7 *p7, BIO *bio)
{
	const unsigned char *buf, *idcbuf;
	ASN1_STRING *str;
	IDC *idc;

	/* extract the idc from the signed PKCS7 'other' data */
	str = p7->d.sign->contents->d.other->value.asn1_string;
#if OPENSSL_VERSION_NUMBER < 0x10100000L
	idcbuf = buf = ASN1_STRING_data(str);
#else
	idcbuf = buf = ASN1_STRING_get0_data(str);
#endif
	idc = d2i_IDC(NULL, &buf, ASN1_STRING_length(str));

	/* If we were passed a BIO, write the idc data, minus type and length,
	 * to the BIO. This can be used to PKCS7_verify the idc */
	if (bio) {
		uint32_t idclen;
		uint8_t tmp;

		tmp = idcbuf[1];

		if (!(tmp & 0x80)) {
			idclen = tmp & 0x7f;
			idcbuf += 2;
		} else if ((tmp & 0x82) == 0x82) {
			idclen = (idcbuf[2] << 8) +
				 idcbuf[3];
			idcbuf += 4;
		} else {
			fprintf(stderr, "Invalid ASN.1 data in "
					"IndirectDataContext?\n");
			return NULL;
		}

		BIO_write(bio, idcbuf, idclen);
	}

	return idc;
}

int IDC_check_hash(struct idc *idc, struct image *image)
{
	unsigned char sha[DEFAULT_DIGEST_LENGTH];
	const unsigned char *buf;
	ASN1_STRING *str;

	image_hash_sha256(image, sha);

	/* check hash algorithm sanity */
	int alg_nid = OBJ_obj2nid(idc->digest->alg->algorithm);
	if (alg_nid == NID_sm3){
		image_hash_sm3(image, sha);
	}else if (alg_nid == NID_sha256){
		image_hash_sha256(image, sha);
	}else{
		fprintf(stderr, "Invalid algorithm type\n");
		return -1;
	}

	str = idc->digest->digest;
	if (ASN1_STRING_length(str) != sizeof(sha)) {
		fprintf(stderr, "Invalid algorithm length\n");
		return -1;
	}

	/* check hash against the one we calculated from the image */
#if OPENSSL_VERSION_NUMBER < 0x10100000L
	buf = ASN1_STRING_data(str);
#else
	buf = ASN1_STRING_get0_data(str);
#endif
	if (memcmp(buf, sha, sizeof(sha))) {
		fprintf(stderr, "Hash doesn't match image\n");
		fprintf(stderr, " got:       %s\n", hash_str(buf));
		fprintf(stderr, " expecting: %s\n", hash_str(sha));
		return -1;
	}

	return 0;
}
