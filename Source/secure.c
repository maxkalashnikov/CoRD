/* -*- c-basic-offset: 8 -*-
   rdesktop: A Remote Desktop Protocol client.
   Protocol services - RDP encryption and licensing
   Copyright (C) Matthew Chapman <matthewc.unsw.edu.au> 1999-2008
   Copyright 2005-2011 Peter Astrand <astrand@cendio.se> for Cendio AB
   Copyright 2017 Henrik Andersson <hean01@cendio.se> for Cendio AB

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#import "rdesktop.h"
#import "ssl.h"
#import <iconv.h>

int g_width = 800;
int g_height = 600;
int g_dpi = 0;			/* device DPI: default not set */
unsigned int g_keylayout = 0x409;	/* Defaults to US keyboard layout */
int g_keyboard_type = 0x4;	/* Defaults to US keyboard layout */
int g_keyboard_subtype = 0x0;	/* Defaults to US keyboard layout */
int g_keyboard_functionkeys = 0xc;	/* Defaults to US keyboard layout */
uint32 g_redirect_session_id = 0;
char g_codepage[16] = "";

#define SEC_EXCHANGE_PKT	0x0001
#define RDP_40		0x00080001	/* RDP 4.0 clients */
#define RDP_50		0x00080004	/* RDP 5.0, 5.1, 5.2, 6.0, 6.1, 7.0, 7.1, 8.0, and 8.1 clients */

#define RNS_UD_COLOR_4BPP	0xCA00
#define RNS_UD_COLOR_8BPP	0xCA01
#define RNS_UD_COLOR_16BPP_555	0xCA02
#define RNS_UD_COLOR_16BPP_565	0xCA03
#define RNS_UD_COLOR_24BPP	0xCA04
#define RNS_UD_SAS_DEL		0xAA03
#define RNS_UD_CS_SUPPORT_ERRINFO_PDU		0x0001
#define RNS_UD_24BPP_SUPPORT	0x0001
#define RNS_UD_16BPP_SUPPORT	0x0002
#define RNS_UD_15BPP_SUPPORT	0x0004
#define RNS_UD_32BPP_SUPPORT	0x0008
/* earlyCapabilityFlags, [MS-RDPBCGR] 2.2.1.3.2 */
#define RNS_UD_CS_SUPPORT_ERRINFO_PDU		0x0001
#define RNS_UD_CS_WANT_32BPP_SESSION		0x0002
#define RNS_UD_CS_SUPPORT_STATUSINFO_PDU	0x0004
#define RNS_UD_CS_STRONG_ASYMMETRIC_KEYS	0x0008
#define RNS_UD_CS_UNUSED			0x0010
#define RNS_UD_CS_VALID_CONNECTION_TYPE		0x0020
#define RNS_UD_CS_SUPPORT_MONITOR_LAYOUT_PDU	0x0040
#define RNS_UD_CS_SUPPORT_NETCHAR_AUTODETECT	0x0080
#define RNS_UD_CS_SUPPORT_DYNVC_GFX_PROTOCOL	0x0100
#define RNS_UD_CS_SUPPORT_DYNAMIC_TIME_ZONE	0x0200
#define RNS_UD_CS_SUPPORT_HEARTBEAT_PDU		0x0400

#define CS_CORE			0xc001
#define CS_SECURITY		0xc002
#define CS_NET			0xc003
#define CS_CLUSTER		0xc004
/* desktop orientation */
enum RDP_DESKTOP_ORIENTATION
{
	ORIENTATION_LANDSCAPE = 0,
	ORIENTATION_PORTRAIT = 90,
	ORIENTATION_LANDSCAPE_FLIPPED = 180,
	ORIENTATION_PORTRAIT_FLIPPED = 270
};
/* Client cluster constants */
#define SEC_CC_REDIRECTION_SUPPORTED          0x00000001
#define SEC_CC_REDIRECT_SESSIONID_FIELD_VALID 0x00000002
#define SEC_CC_REDIRECTED_SMARTCARD           0x00000040
#define SEC_CC_REDIRECT_VERSION_MASK          0x0000003c

#define SEC_CC_REDIRECT_VERSION_3             0x02
#define SEC_CC_REDIRECT_VERSION_4             0x03
#define SEC_CC_REDIRECT_VERSION_5             0x04
#define SEC_CC_REDIRECT_VERSION_6             0x05
/* TS_SECURITY_HEADER.flags */
#define SEC_LICENSE_PKT		0x0080
#define SEC_REDIRECTION_PKT	0x0400

#define WINDOWS_CODEPAGE	"UTF-16LE"
#define s_left(s)               ((s)->size - ((s)->p - (s)->data))

/*
 * I believe this is based on SSLv3 with the following differences:
 *  MAC algorithm (5.2.3.1) uses only 32-bit length in place of seq_num/type/length fields
 *  MAC algorithm uses SHA1 and MD5 for the two hash functions instead of one or other
 *  key_block algorithm (6.2.2) uses 'X', 'YY', 'ZZZ' instead of 'A', 'BB', 'CCC'
 *  key_block partitioning is different (16 bytes each: MAC secret, decrypt key, encrypt key)
 *  encryption/decryption keys updated every 4096 packets
 * See http://wp.netscape.com/eng/ssl3/draft302.txt
 */

/*
 * 48-byte transformation used to generate master secret (6.1) and key material (6.2.2).
 * Both SHA1 and MD5 algorithms are used.
 */
void
sec_hash_48(uint8 * out, uint8 * in, uint8 * salt1, uint8 * salt2, uint8 salt)
{
	uint8 shasig[20];
	uint8 pad[4];
	SHA_CTX sha;
	MD5_CTX md5;
	int i;

	for (i = 0; i < 3; i++)
	{
		memset(pad, salt + i, i + 1);

		SHA1_Init(&sha);
		SHA1_Update(&sha, pad, i + 1);
		SHA1_Update(&sha, in, 48);
		SHA1_Update(&sha, salt1, 32);
		SHA1_Update(&sha, salt2, 32);
		SHA1_Final(shasig, &sha);

		MD5_Init(&md5);
		MD5_Update(&md5, in, 48);
		MD5_Update(&md5, shasig, 20);
		MD5_Final(&out[i * 16], &md5);
	}
}

/*
 * 16-byte transformation used to generate export keys (6.2.2).
 */
void
sec_hash_16(uint8 * out, uint8 * in, uint8 * salt1, uint8 * salt2)
{
	MD5_CTX md5;

	MD5_Init(&md5);
	MD5_Update(&md5, in, 16);
	MD5_Update(&md5, salt1, 32);
	MD5_Update(&md5, salt2, 32);
	MD5_Final(out, &md5);
}

/*
 * 16-byte sha1 hash
 */
void
sec_hash_sha1_16(uint8 * out, uint8 * in, uint8 * salt1)
{
	SHA_CTX sha1;
	SHA1_Init(&sha1);
	SHA1_Update(&sha1, in, 16);
	SHA1_Update(&sha1, salt1, 16);
	SHA1_Final(out, &sha1);
}

/* create string from hash */
void
sec_hash_to_string(char *out, int out_size, uint8 * in, int in_size)
{
	int k;
	memset(out, 0, out_size);
	for (k = 0; k < in_size; k++, out += 2)
	{
		sprintf(out, "%.2x", in[k]);
	}
}

/* Reduce key entropy from 64 to 40 bits */
static void
sec_make_40bit(uint8 * key)
{
	key[0] = 0xd1;
	key[1] = 0x26;
	key[2] = 0x9e;
}

/* Generate encryption keys given client and server randoms */
static void
sec_generate_keys(RDConnectionRef conn, uint8 * client_random, uint8 * server_random, int rc4_key_size)
{
	uint8 pre_master_secret[48];
	uint8 master_secret[48];
	uint8 key_block[48];

	/* Construct pre-master secret */
	memcpy(pre_master_secret, client_random, 24);
	memcpy(pre_master_secret + 24, server_random, 24);

	/* Generate master secret and then key material */
	sec_hash_48(master_secret, pre_master_secret, client_random, server_random, 'A');
	sec_hash_48(key_block, master_secret, client_random, server_random, 'X');

	/* First 16 bytes of key material is MAC secret */
	memcpy(conn->secSignKey, key_block, 16);

	/* Generate export keys from next two blocks of 16 bytes */
	sec_hash_16(conn->secDecryptKey, &key_block[16], client_random, server_random);
	sec_hash_16(conn->secEncryptKey, &key_block[32], client_random, server_random);

	if (rc4_key_size == 1)
	{
		DEBUG(("sec_generate_keys(), 40-bit encryption enabled"));
		sec_make_40bit(conn->secSignKey);
		sec_make_40bit(conn->secDecryptKey);
		sec_make_40bit(conn->secEncryptKey);
		conn->rc4KeyLen = 8;
	}
	else
	{
		DEBUG(("sec_generate_key(), rc_4_key_size == %d, 128-bit encryption enabled", rc4_key_size));
		conn->rc4KeyLen = 16;
	}

	/* Save initial RC4 keys as update keys */
	memcpy(conn->secDecryptUpdateKey, conn->secDecryptKey, 16);
	memcpy(conn->secEncryptUpdateKey, conn->secEncryptKey, 16);

	/* Initialise RC4 state arrays */
	RC4_set_key(&conn->rc4DecryptKey, conn->rc4KeyLen, conn->secDecryptKey);
	RC4_set_key(&conn->rc4EncryptKey, conn->rc4KeyLen, conn->secEncryptKey);
}

static uint8 pad_54[40] = {
	54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54,
	54, 54, 54,
	54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54,
	54, 54, 54
};

static uint8 pad_92[48] = {
	92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92,
	92, 92, 92, 92, 92, 92, 92,
	92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92, 92,
	92, 92, 92, 92, 92, 92, 92
};

/* Output a uint32 into a buffer (little-endian) */
void
buf_out_uint32(uint8 * buffer, uint32 value)
{
	buffer[0] = (value) & 0xff;
	buffer[1] = (value >> 8) & 0xff;
	buffer[2] = (value >> 16) & 0xff;
	buffer[3] = (value >> 24) & 0xff;
}

/* Generate a MAC hash (5.2.3.1), using a combination of SHA1 and MD5 */
void
sec_sign(uint8 * signature, int siglen, uint8 * session_key, int keylen, uint8 * data, int datalen)
{
	uint8 shasig[20];
	uint8 md5sig[16];
	uint8 lenhdr[4];
	SHA_CTX sha;
	MD5_CTX md5;

	buf_out_uint32(lenhdr, datalen);

	SHA1_Init(&sha);
	SHA1_Update(&sha, session_key, keylen);
	SHA1_Update(&sha, pad_54, 40);
	SHA1_Update(&sha, lenhdr, 4);
	SHA1_Update(&sha, data, datalen);
	SHA1_Final(shasig, &sha);

	MD5_Init(&md5);
	MD5_Update(&md5, session_key, keylen);
	MD5_Update(&md5, pad_92, 48);
	MD5_Update(&md5, shasig, 20);
	MD5_Final(md5sig, &md5);

	memcpy(signature, md5sig, siglen);
}

/* Update an encryption key */
static void
sec_update(RDConnectionRef conn, uint8 * key, uint8 * update_key)
{
	uint8 shasig[20];
	SHA_CTX sha;
	MD5_CTX md5;
	RC4_KEY update;

	SHA1_Init(&sha);
	SHA1_Update(&sha, update_key, conn->rc4KeyLen);
	SHA1_Update(&sha, pad_54, 40);
	SHA1_Update(&sha, key, conn->rc4KeyLen);
	SHA1_Final(shasig, &sha);

	MD5_Init(&md5);
	MD5_Update(&md5, update_key, conn->rc4KeyLen);
	MD5_Update(&md5, pad_92, 48);
	MD5_Update(&md5, shasig, 20);
	MD5_Final(key, &md5);

	RC4_set_key(&update, conn->rc4KeyLen, key);
	RC4(&update, conn->rc4KeyLen, key, key);

	if (conn->rc4KeyLen == 8)
		sec_make_40bit(key);
}

/* Encrypt data using RC4 */
static void
sec_encrypt(RDConnectionRef conn, uint8 * data, int length)
{
	if (conn->secEncryptUseCount == 4096)
	{
		sec_update(conn, conn->secEncryptKey, conn->secEncryptUpdateKey);
		RC4_set_key(&conn->rc4EncryptKey, conn->rc4KeyLen, conn->secEncryptKey);
		conn->secEncryptUseCount = 0;
	}

	RC4(&conn->rc4EncryptKey, length, data, data);
	conn->secEncryptUseCount++;
}

/* Decrypt data using RC4 */
void
sec_decrypt(RDConnectionRef conn, uint8 * data, int length)
{
	if (conn->secDecryptUseCount == 4096)
	{
		sec_update(conn, conn->secDecryptKey, conn->secDecryptUpdateKey);
		RC4_set_key(&conn->rc4DecryptKey, conn->rc4KeyLen, conn->secDecryptKey);
		conn->secDecryptUseCount = 0;
	}

	RC4(&conn->rc4DecryptKey, length, data, data);
	conn->secDecryptUseCount++;
}

static void
reverse(uint8 * p, int len)
{
	int i, j;
	uint8 temp;

	for (i = 0, j = len - 1; i < j; i++, j--)
	{
		temp = p[i];
		p[i] = p[j];
		p[j] = temp;
	}
}

/* Perform an RSA public key encryption operation */
static void
sec_rsa_encrypt(uint8 * out, uint8 * in, int len, uint32 modulus_size, uint8 * modulus,
		uint8 * exponent)
{
	BN_CTX *ctx;
	BIGNUM mod, exp, x, y;
	uint8 inr[SEC_MAX_MODULUS_SIZE];
	int outlen;

	reverse(modulus, modulus_size);
	reverse(exponent, SEC_EXPONENT_SIZE);
	memcpy(inr, in, len);
	reverse(inr, len);

	ctx = BN_CTX_new();
	BN_init(&mod);
	BN_init(&exp);
	BN_init(&x);
	BN_init(&y);

	BN_bin2bn(modulus, modulus_size, &mod);
	BN_bin2bn(exponent, SEC_EXPONENT_SIZE, &exp);
	BN_bin2bn(inr, len, &x);
	BN_mod_exp(&y, &x, &exp, &mod, ctx);
	outlen = BN_bn2bin(&y, out);
	reverse(out, outlen);
	if (outlen < (int) modulus_size)
		memset(out + outlen, 0, modulus_size - outlen);

	BN_free(&y);
	BN_clear_free(&x);
	BN_free(&exp);
	BN_free(&mod);
	BN_CTX_free(ctx);
}

/* Initialise secure transport packet */
RDStreamRef
sec_init(RDConnectionRef conn, uint32 flags, int maxlen)
{
	int hdrlen;
	RDStreamRef s;

	if (!conn->licenseIssued)
		hdrlen = (flags & SEC_ENCRYPT) ? 12 : 4;
	else
		hdrlen = (flags & SEC_ENCRYPT) ? 12 : 0;
	s = mcs_init(conn, maxlen + hdrlen);
	s_push_layer(s, sec_hdr, hdrlen);

	return s;
}

/* Transmit secure transport packet over specified channel */
void
sec_send_to_channel(RDConnectionRef conn, RDStreamRef s, uint32 flags, uint16 channel)
{
	int datalen;

	s_pop_layer(s, sec_hdr);
	if (!conn->licenseIssued || (flags & SEC_ENCRYPT))
		out_uint32_le(s, flags);

	if (flags & SEC_ENCRYPT)
	{
		flags &= ~SEC_ENCRYPT;
		datalen = s->end - s->p - 8;

#if WITH_DEBUG_NETWORK
		DEBUG(("Sending encrypted packet:\n"));
		hexdump(s->p + 8, datalen);
#endif

		sec_sign(s->p, 8, conn->secSignKey, conn->rc4KeyLen, s->p + 8, datalen);
		sec_encrypt(conn, s->p + 8, datalen);
	}

	mcs_send_to_channel(conn, s, channel);
}

/* Transmit secure transport packet */

void
sec_send(RDConnectionRef conn, RDStreamRef s, uint32 flags)
{
	sec_send_to_channel(conn, s, flags, MCS_GLOBAL_CHANNEL);
}


/* Transfer the client random to the server */
static void
sec_establish_key(RDConnectionRef conn)
{
	uint32 length = conn->serverPublicKeyLen + SEC_PADDING_SIZE;
	uint32 flags = SEC_EXCHANGE_PKT;
	RDStreamRef s;

	s = sec_init(conn, flags, length + 4);

	out_uint32_le(s, length);
	out_uint8p(s, conn->secCryptedRandom, conn->serverPublicKeyLen);
	out_uint8s(s, SEC_PADDING_SIZE);

	s_mark_end(s);
	sec_send(conn, s, flags);
}

static iconv_t
local_to_utf16()
{
  iconv_t icv;
  icv = iconv_open(WINDOWS_CODEPAGE, g_codepage);
  if (icv == (iconv_t) - 1)
  {
	  error("locale_to_utf16(), iconv_open[%s -> %s] fail %p",g_codepage, WINDOWS_CODEPAGE, icv);
    abort();
  }
  return icv;
}

/* Output connect initial data blob */
static void
sec_out_mcs_connect_initial_pdu(RDConnectionRef conn, RDStreamRef s, uint32 selected_protocol)
{
	int length = 162 + 76 + 12 + 4 + (g_dpi > 0 ? 18 : 0);
	unsigned int i;
	uint32 rdpversion = RDP_40;
	uint16 capflags = RNS_UD_CS_SUPPORT_ERRINFO_PDU;
	uint16 colorsupport = RNS_UD_24BPP_SUPPORT | RNS_UD_16BPP_SUPPORT | RNS_UD_32BPP_SUPPORT;

	if (conn->useRdp5 >= RDP_V5)
		rdpversion = RDP_50;

	if (conn->numChannels > 0)
		length += conn->numChannels * 12 + 8;

	/* Generic Conference Control (T.124) ConferenceCreateRequest */
	out_uint16_be(s, 5);
	out_uint16_be(s, 0x14);
	out_uint8(s, 0x7c);
	out_uint16_be(s, 1);

	out_uint16_be(s, (length | 0x8000));	/* remaining length */

	out_uint16_be(s, 8);	/* length? */
	out_uint16_be(s, 16);
	out_uint8(s, 0);
	out_uint16_le(s, 0xc001);
	out_uint8(s, 0);

	out_uint32_le(s, 0x61637544);	/* OEM ID: "Duca", as in Ducati. */
	out_uint16_be(s, ((length - 14) | 0x8000));	/* remaining length */

	/* Client information (TS_UD_CS_CORE) */
	out_uint16_le(s, CS_CORE);		/* type */
	out_uint16_le(s, 216 + (g_dpi > 0 ? 18 : 0));	/* length */
	out_uint32_le(s, rdpversion);           /* version */
	out_uint16_le(s, g_width);		/* desktopWidth */
	out_uint16_le(s, g_height);		/* desktopHeight */
	out_uint16_le(s, RNS_UD_COLOR_8BPP);	/* colorDepth */
	out_uint16_le(s, RNS_UD_SAS_DEL);	/* SASSequence */
	out_uint32_le(s, g_keylayout);		/* keyboardLayout */
	out_uint32_le(s, 2600);			/* Client build. We are now 2600 compatible :-) */

	/* Unicode name of client, padded to 32 bytes */
	/*out_utf16s_padded(s, conn->hostname, 32, 0x00);*/
	size_t j;

	/*bl = _out_utf16s(s, 32 - 2, conn->hostname);*/

        static iconv_t icv_local_to_utf16;
	size_t bl, ibl, obl;
	const char *pin;
	char *pout;

	if (conn->hostname == NULL)
		bl = 0;

	if (!icv_local_to_utf16)
    	{
      	icv_local_to_utf16 = local_to_utf16();
    	}

	ibl = strlen(conn->hostname);
	obl = 30 ? 30 : (size_t)s_left(s);
  	pin = conn->hostname;
        pout = (char *) s->p;

	if (iconv(icv_local_to_utf16, (char **) &pin, &ibl, &pout, &obl) == (size_t) - 1)
	{
		error("out_utf16s(), iconv(2) fail, errno %d", errno);
		abort();
    	}
	bl = (unsigned char*)pout - s->p;
	s->p = (unsigned char *)pout;	


	// append utf16 null termination
	out_uint16(s, 0);
	bl += 2;

	for (j = 0; j < (length - bl); j++)
    	out_uint8(s, 0x00);

	out_uint32_le(s, g_keyboard_type);	/* keyboardType */
	out_uint32_le(s, g_keyboard_subtype);	/* keyboardSubtype */
	out_uint32_le(s, g_keyboard_functionkeys); /* keyboardFunctionKey */
	out_uint8s(s, 64);			/* imeFileName */
	out_uint16_le(s, RNS_UD_COLOR_8BPP);	/* postBeta2ColorDepth (overrides colorDepth) */
	out_uint16_le(s, 1);			/* clientProductId (should be 1) */
	out_uint32_le(s, 0);			/* serialNumber (should be 0) */

	/* highColorDepth (overrides postBeta2ColorDepth). Capped at 24BPP.
	   To get 32BPP sessions, we need to set a capability flag. */
	out_uint16_le(s, MIN(conn->serverBpp, 24));
	if (conn->serverBpp == 32)
		capflags |= RNS_UD_CS_WANT_32BPP_SESSION;

	out_uint16_le(s, colorsupport);		/* supportedColorDepths */
	out_uint16_le(s, capflags);		/* earlyCapabilityFlags */
	out_uint8s(s, 64);			/* clientDigProductId */
	out_uint8(s, 0);			/* connectionType */
	out_uint8(s, 0);			/* pad */
	out_uint32_le(s, selected_protocol);	/* serverSelectedProtocol */
	if (g_dpi > 0)
	{
		/* Extended client info describing monitor geometry */
		out_uint32_le(s, g_width * 254 / (g_dpi * 10)); /* desktop physical width */
		out_uint32_le(s, g_height * 254 / (g_dpi * 10)); /* desktop physical height */
		out_uint16_le(s, ORIENTATION_LANDSCAPE);
		out_uint32_le(s, g_dpi < 96 ? 100 : (g_dpi * 100 + 48) / 96); /* desktop scale factor */
		/* the spec calls this out as being valid for range 100-500 but I doubt the upper range is accurate */
		out_uint32_le(s, g_dpi < 134 ? 100 : (g_dpi < 173 ? 140 : 180)); /* device scale factor */
		/* the only allowed values for device scale factor are 100, 140, and 180. */
	}

	/* Write a Client Cluster Data (TS_UD_CS_CLUSTER) */
	uint32 cluster_flags = 0;
	out_uint16_le(s, CS_CLUSTER);	/* header.type */
	out_uint16_le(s, 12);	/* length */

	cluster_flags |= SEC_CC_REDIRECTION_SUPPORTED;
	cluster_flags |= (SEC_CC_REDIRECT_VERSION_3 << 2);

	if (conn->consoleSession || g_redirect_session_id != 0)
		cluster_flags |= SEC_CC_REDIRECT_SESSIONID_FIELD_VALID;

	out_uint32_le(s, cluster_flags);
	out_uint32(s, g_redirect_session_id);

	/* Client encryption settings (TS_UD_CS_SEC) */
	out_uint16_le(s, CS_SECURITY);			/* type */
	out_uint16_le(s, 12);				/* length */
	out_uint32_le(s, conn->useEncryption ? 0x3 : 0);	/* encryptionMethods */
	out_uint32(s, 0);				/* extEncryptionMethods */

	/* Channel definitions (TS_UD_CS_NET) */
	DEBUG(("sec_out_mcs_data(), conn->numChannels is %d", conn->numChannels));
	if (conn->numChannels > 0)
	{
		out_uint16_le(s, CS_NET);			/* type */
		out_uint16_le(s, conn->numChannels * 12 + 8);	/* length */
		out_uint32_le(s, conn->numChannels);	/* number of virtual channels */
		for (i = 0; i < conn->numChannels; i++)
		{
			DEBUG(("sec_out_mcs_data(), requesting channel %s",
				conn->channels[i].name));
			out_uint8a(s, conn->channels[i].name, 8);
			out_uint32_be(s, conn->channels[i].flags);
		}
	}

	s_mark_end(s);
}

/* Parse a public key structure */
static RD_BOOL
sec_parse_public_key(RDConnectionRef conn, RDStreamRef s, uint8 * modulus, uint8 * exponent)
{
	uint32 magic, modulus_len;

	in_uint32_le(s, magic);
	if (magic != SEC_RSA_MAGIC)
	{
		error("sec_parse_public_key(), magic (0x%x) != SEC_RSA_MAGIC", magic);
		return False;
	}

	in_uint32_le(s, modulus_len);
	modulus_len -= SEC_PADDING_SIZE;
	if ((modulus_len < SEC_MODULUS_SIZE) || (modulus_len > SEC_MAX_MODULUS_SIZE))
	{
		error("sec_parse_public_key(), invalid public key size (%u bits) from server", modulus_len * 8);
		return False;
	}

	in_uint8s(s, 8);	/* modulus_bits, unknown */
	in_uint8p(s, exponent, SEC_EXPONENT_SIZE);
	in_uint8p(s, modulus, modulus_len);
	in_uint8s(s, SEC_PADDING_SIZE);
	conn->serverPublicKeyLen = modulus_len;

	return s_check(s);
}

/* Parse a public signature structure */
static RD_BOOL
sec_parse_public_sig(RDConnectionRef conn, RDStreamRef s, uint32 len, uint8 * modulus, uint8 * exponent)
{
	uint8 signature[SEC_MAX_MODULUS_SIZE];
	uint32 sig_len;

	if (len != 72)
	{
		return True;
	}
	memset(signature, 0, sizeof(signature));
	sig_len = len - 8;
	in_uint8a(s, signature, sig_len);
	return ssl_sig_ok(exponent, SEC_EXPONENT_SIZE, modulus, conn->serverPublicKeyLen,
			    signature, sig_len);
}

/* Parse a crypto information structure */
static RD_BOOL
sec_parse_crypt_info(RDConnectionRef conn, RDStreamRef s, uint32 * rc4_key_size,
		     uint8 ** server_random, uint8 * modulus, uint8 * exponent)
{
	uint32 crypt_level, random_len, rsa_info_len;
	uint32 cacert_len, cert_len, flags;
	X509 *cacert, *server_cert;
	SSL_RKEY *server_public_key;
	uint16 tag, length;
	uint8 *next_tag, *end;

	in_uint32_le(s, *rc4_key_size);	/* 1 = 40-bit, 2 = 128-bit */
	in_uint32_le(s, crypt_level);	/* 1 = low, 2 = medium, 3 = high */
	if (crypt_level == 0)  /* no encryption */
	{
		/* no encryption */
		DEBUG(( "sec_parse_crypt_info(), got ENCRYPTION_LEVEL_NONE"));
		return False;
	}

	in_uint32_le(s, random_len);
	in_uint32_le(s, rsa_info_len);

	if (random_len != SEC_RANDOM_SIZE)
	{
		error("sec_parse_crypt_info(), got random len %d, expected %d", random_len, SEC_RANDOM_SIZE);
		return False;
	}

	in_uint8p(s, *server_random, random_len);

	/* RSA info */
	end = s->p + rsa_info_len;
	if (end > s->end)
	{
		error("sec_parse_crypt_info(), end > s->end");
		return False;
	}

	in_uint32_le(s, flags);	/* 1 = RDP4-style, 0x80000002 = X.509 */
	if (flags & 1)
	{
		DEBUG_RDP5(("sec_parse_crypt_info(), We're going for the RDP4-style encryption"));
		in_uint8s(s, 8);	/* unknown */

		while (s->p < end)
		{
			in_uint16_le(s, tag);
			in_uint16_le(s, length);

			next_tag = s->p + length;

			switch (tag)
			{
				case SEC_TAG_PUBKEY:
					if (!sec_parse_public_key(conn, s, modulus, exponent))
					{
						error("sec_parse_crypt_info(), invalid public key");
						return False;
					}
					DEBUG_RDP5(("sec_parse_crypt_info(), got public key"));

					break;

				case SEC_TAG_KEYSIG:
					if (!sec_parse_public_sig(conn, s, length, modulus, exponent))
					{
						error("sec_parse_crypt_info(), invalid public sig");
						return False;
					}
					break;

				default:
					DEBUG(("sec_parse_crypt_info(), unhandled crypt tag 0x%x",tag));
			}

			s->p = next_tag;
		}
	}
	else
	{
		uint32 certcount;

		DEBUG_RDP5(("sec_parse_crypt_info(), We're going for the RDP5-style encryption"));
		in_uint32_le(s, certcount);	/* Number of certificates */
		if (certcount < 2)
		{
			error("sec_parse_crypt_info(), server didn't send enough x509 certificates");
			return False;
		}
		for (; certcount > 2; certcount--)
		{		/* ignore all the certificates between the root and the signing CA */
			uint32 ignorelen;
			X509 *ignorecert;

			DEBUG_RDP5(("Ignored certs left: %d\n", certcount));
			in_uint32_le(s, ignorelen);
			DEBUG_RDP5(("Ignored Certificate length is %d\n", ignorelen));
			ignorecert = d2i_X509(NULL, (const unsigned char**)&(s->p), ignorelen);

			in_uint8s(s, ignorelen);
			if (ignorecert == NULL)
			{	/* XXX: error out? */
				error("sec_parse_crypt_info(), got a bad cert: this will probably screw up the rest of the communication");
			}

#ifdef WITH_DEBUG_RDP5
			DEBUG_RDP5(("cert #%d (ignored):\n", certcount));
			X509_print_fp(stdout, ignorecert);
#endif
		}

		/* Do da funky X.509 stuffy

		   "How did I find out about this?  I looked up and saw a
		   bright light and when I came to I had a scar on my forehead
		   and knew about X.500"
		   - Peter Gutman in a early version of 
		   http://www.cs.auckland.ac.nz/~pgut001/pubs/x509guide.txt
		 */
		in_uint32_le(s, cacert_len);
		DEBUG(("sec_parse_crypt_info(), server CA Certificate length is %d", cacert_len));
		cacert = d2i_X509(NULL, (const unsigned char**)&(s->p), cacert_len);
		/* Note: We don't need to move s->p here - d2i_X509 is
		   "kind" enough to do it for us */
		in_uint8s(s, cacert_len);
		if (NULL == cacert)
		{
			error("sec_parse_crypt_info(), couldn't load CA Certificate from server");
			return False;
		}
		in_uint32_le(s, cert_len);
		DEBUG(("sec_parse_crypt_info(), certificate length is %d",cert_len));
		server_cert = d2i_X509(NULL, (const unsigned char**)&(s->p), cert_len);
		in_uint8s(s, cert_len);
		if (NULL == server_cert)
		{
			X509_free(cacert);
			error("sec_parse_crypt_info(), couldn't load Certificate from server");
			return False;
		}
		if (!ssl_certs_ok(server_cert, cacert))
		{
			X509_free(server_cert);
			X509_free(cacert);
			error("sec_parse_crypt_info(), security error, CA Certificate invalid");
			return False;
		}
		X509_free(cacert);
		in_uint8s(s, 16);	/* Padding */
		server_public_key = ssl_cert_to_rkey(server_cert, &conn->serverPublicKeyLen);
		if (NULL == server_public_key)
		{
			DEBUG_RDP5(("sec_parse_crypt_info(). failed to parse X509 correctly"));
			X509_free(server_cert);
			return False;
		}
		X509_free(server_cert);
		if ((conn->serverPublicKeyLen < SEC_MODULUS_SIZE) ||
		    (conn->serverPublicKeyLen > SEC_MAX_MODULUS_SIZE))
		{
			error("sec_parse_crypt_info(), bad server public key size (%u bits)",
			       conn->serverPublicKeyLen * 8);
			ssl_rkey_free(server_public_key);
			return False;
		}
		if (ssl_rkey_get_exp_mod(server_public_key, exponent, SEC_EXPONENT_SIZE,
					   *modulus, SEC_MAX_MODULUS_SIZE) != 0)
		{
			error("sec_parse_crypt_info(), problem extracting RSA exponent, modulus");
			ssl_rkey_free(server_public_key);
			return False;
		}
		ssl_rkey_free(server_public_key);
		return True;	/* There's some garbage here we don't care about */
	}
	return s_check_end(s);
}

/* Process crypto information blob */
static void
sec_process_crypt_info(RDConnectionRef conn, RDStreamRef s)
{
	uint8 *server_random = NULL;
	uint8 modulus[SEC_MAX_MODULUS_SIZE];
	uint8 exponent[SEC_EXPONENT_SIZE];
	uint32 rc4_key_size;

	memset(modulus, 0, sizeof(modulus));
	memset(exponent, 0, sizeof(exponent));
	if (!sec_parse_crypt_info(conn, s, &rc4_key_size, &server_random, modulus, exponent))
		{
			DEBUG(("Failed to parse crypt info\n"));
			return;
		}

	DEBUG(("sec_parse_crypt_info(), generating client random"));
	generate_random(conn->autoReconnectClientRandom);
	if (NULL != conn->serverPublicKey)
	{			/* Which means we should use 
				   RDP5-style encryption */
		DEBUG(("sec_process_crypt_info(), NULL != conn->serverPublicKey"));
		uint8 inr[SEC_MAX_MODULUS_SIZE];
		uint32 padding_len = conn->serverPublicKeyLen - SEC_RANDOM_SIZE;

		/* This is what the MS client do: */
		memset(inr, 0, padding_len);
		/*  *ARIGL!* Plaintext attack, anyone?
		   I tried doing:
		   generate_random(inr);
		   ..but that generates connection errors now and then (yes, 
		   "now and then". Something like 0 to 3 attempts needed before a 
		   successful connection. Nice. Not! 
		 */
		 
		memcpy(inr + padding_len, conn->autoReconnectClientRandom, SEC_RANDOM_SIZE);
		reverse(inr + padding_len, SEC_RANDOM_SIZE);

		RSA_public_encrypt(conn->serverPublicKeyLen, inr, conn->secCryptedRandom, conn->serverPublicKey, RSA_NO_PADDING);

		reverse(conn->secCryptedRandom, conn->serverPublicKeyLen);
		
		RSA_free(conn->serverPublicKey);
		conn->serverPublicKey = NULL;
	}
	else
	{	/* RDP4-style encryption */
		sec_rsa_encrypt(conn->secCryptedRandom, conn->autoReconnectClientRandom, SEC_RANDOM_SIZE, conn->serverPublicKeyLen, modulus, exponent);
	}
	sec_generate_keys(conn, conn->autoReconnectClientRandom, server_random, rc4_key_size);
}


/* Process SRV_INFO, find RDP version supported by server */
static void
sec_process_srv_info(RDConnectionRef conn, RDStreamRef s)
{
	in_uint16_le(s, conn->serverRdpVersion);
	DEBUG_RDP5(("sec_process_srv_info(), server RDP version is %d",conn->serverRdpVersion));
	if (1 == conn->serverRdpVersion)
	{
		conn->useRdp5 = 4;
		conn->serverBpp = 8;
	}
}


/* Process connect response data blob */
void
sec_process_mcs_data(RDConnectionRef conn, RDStreamRef s)
{
	uint16 tag, length;
	uint8 *next_tag;
	uint8 len;

	in_uint8s(s, 21);	/* header (T.124 ConferenceCreateResponse) */
	in_uint8(s, len);
	if (len & 0x80)
		in_uint8(s, len);

	while (s->p < s->end)
	{
		in_uint16_le(s, tag);
		in_uint16_le(s, length);

		if (length <= 4)
			return;

		next_tag = s->p + length - 4;

		switch (tag)
		{
			case SEC_TAG_SRV_INFO:
				sec_process_srv_info(conn, s);
				break;

			case SEC_TAG_SRV_CRYPT:
				sec_process_crypt_info(conn, s);
				break;

			case SEC_TAG_SRV_CHANNELS:
				/* FIXME: We should parse this information and
				   use it to map RDP5 channels to MCS 
				   channels */
				break;

			default:
				unimpl(("Unhandled response tag 0x%x", tag));
		}

		s->p = next_tag;
	}
}

/* Receive secure transport packet */
RDStreamRef
sec_recv(RDConnectionRef conn, uint8 * rdpver)
{
	uint16 sec_flags;
	uint16 channel;
	RDStreamRef s;

	while ((s = mcs_recv(conn, &channel, rdpver)) != NULL)
	{
		if (rdpver != NULL)
		{
			if (*rdpver != 3)
			{
				if (*rdpver & 0x80)
				{
					in_uint8s(s, 8);	/* signature */
					sec_decrypt(conn, s->p, s->end - s->p);
				}
				return s;
			}
		}
		if (conn->useEncryption || !conn->licenseIssued)
		{
			/* TS_SECURITY_HEADER */
			in_uint16_le(s, sec_flags);
			in_uint8s(s, 2);                        /* skip sec_flags_hi */

			if (conn->useEncryption)
			{
				if (sec_flags & SEC_ENCRYPT)
				{
					in_uint8s(s, 8);	/* signature */
					sec_decrypt(conn, s->p, s->end - s->p);
				}

				if (sec_flags & SEC_LICENSE_PKT)
				{
					licence_process(conn, s);
					continue;
				}

				if (sec_flags & SEC_REDIRECTION_PKT)
				{
					uint8 swapbyte;

					in_uint8s(s, 8);	/* signature */
					sec_decrypt(conn, s->p, s->end - s->p);

					/* Check for a redirect packet, starts with 00 04 */
					if (s->p[0] == 0 && s->p[1] == 4)
					{
						/* for some reason the PDU and the length seem to be swapped.
						   This isn't good, but we're going to do a byte for byte
						   swap.  So the first four value appear as: 00 04 XX YY,
						   where XX YY is the little endian length. We're going to
						   use 04 00 as the PDU type, so after our swap this will look
						   like: XX YY 04 00 */
						swapbyte = s->p[0];
						s->p[0] = s->p[2];
						s->p[2] = swapbyte;

						swapbyte = s->p[1];
						s->p[1] = s->p[3];
						s->p[3] = swapbyte;

						swapbyte = s->p[2];
						s->p[2] = s->p[3];
						s->p[3] = swapbyte;
					}
#ifdef WITH_DEBUG
				/* warning!  this debug statement will show passwords in the clear! */
				hexdump(s->p, s->end - s->p);
#endif
				}
			}
			else
			{
				if (sec_flags & SEC_LICENSE_PKT)
				{
					licence_process(conn, s);
					continue;
				}
				s->p -= 4;
			}
		}

		if (channel != MCS_GLOBAL_CHANNEL)
		{
			channel_process(conn, s, channel);
			if (rdpver != NULL)
				*rdpver = 0xff;
			return s;
		}

		return s;
	}

	return NULL;
}

/* Establish a secure connection */
RD_BOOL
sec_connect(RDConnectionRef conn, char *server, char *username, char *domain, char *password, RD_BOOL reconnect)
{
	uint32 selected_proto;
	RDStream mcs_data;

	/* Start a MCS connect sequence */
	if (!mcs_connect_start(conn, server, username, domain, password, reconnect, &selected_proto))
		return False;

	/* We exchange some RDP data during the MCS-Connect */
	mcs_data.size = 512;
	mcs_data.p = mcs_data.data = (uint8 *) xmalloc(mcs_data.size);
	sec_out_mcs_connect_initial_pdu(conn, &mcs_data, selected_proto);

	/* finalize the MCS connect sequence */
	if (!mcs_connect_finalize(conn, &mcs_data))
		return False;

	/* sec_process_mcs_data(&mcs_data); */
	if (conn->useEncryption)
		sec_establish_key(conn);
	xfree(mcs_data.data);
	return True;
}

/* Disconnect a connection */
void
sec_disconnect(RDConnectionRef conn)
{
	mcs_disconnect(conn);
}

/* reset the state of the sec layer */
void
sec_reset_state(RDConnectionRef conn)
{
	conn->serverRdpVersion = 0;
	conn->secEncryptUseCount = 0;
	conn->secDecryptUseCount = 0;
	conn->licenseIssued = 0;
	mcs_reset_state(conn);
}
