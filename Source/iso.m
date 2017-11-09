/* -*- c-basic-offset: 8 -*-
   rdesktop: A Remote Desktop Protocol client.
   Protocol services - ISO layer
   Copyright (C) Matthew Chapman <matthewc.unsw.edu.au> 1999-2008
   Copyright 2005-2011 Peter Astrand <astrand@cendio.se> for Cendio AB
   Copyright 2012-2017 Henrik Andersson <hean01@cendio.se> for Cendio AB

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
#import <Foundation/NSString.h>

#define T123_HEADER_VERSION 0x3
#define RDP_NEG_REQ 1
#define FASTPATH_OUTPUT_ACTION_FASTPATH	0x0
#define FASTPATH_OUTPUT_ACTION_X224	T123_HEADER_VERSION
#define IS_SLOWPATH(hdr) ((hdr) == FASTPATH_OUTPUT_ACTION_X224)
#define IS_FASTPATH(hdr) ((hdr & 0x03) == FASTPATH_OUTPUT_ACTION_FASTPATH)
enum RDP_NEG_FAILURE_CODE
{
	SSL_REQUIRED_BY_SERVER = 1,
	SSL_NOT_ALLOWED_BY_SERVER = 2,
	SSL_CERT_NOT_ON_SERVER = 3,
	INCONSISTENT_FLAGS = 4,
	HYBRID_REQUIRED_BY_SERVER = 5,
	SSL_WITH_USER_AUTH_REQUIRED_BY_SERVER = 6
};
enum RDP_NEG_REQ_CODE
{
	PROTOCOL_RDP = 0,
	PROTOCOL_SSL = 1,
	PROTOCOL_HYBRID = 2
};

static RD_BOOL g_negotiate_rdp_protocol = True;

/* Send a self-contained ISO PDU */
static void
iso_send_msg(RDConnectionRef conn, uint8 code)
{
	RDStreamRef s;

	s = tcp_init(conn, 11);

	out_uint8(s, 3);	/* version */
	out_uint8(s, 0);	/* reserved */
	out_uint16_be(s, 11);	/* length */

	out_uint8(s, 6);	/* hdrlen */
	out_uint8(s, code);
	out_uint16(s, 0);	/* dst_ref */
	out_uint16(s, 0);	/* src_ref */
	out_uint8(s, 0);	/* class */

	s_mark_end(s);
	tcp_send(conn, s);
}

static void
iso_send_connection_request(RDConnectionRef conn, char *username, uint32 neg_proto)
{
	RDStreamRef s;
	int length = 30 + strlen(username);

	if (conn->useRdp5 >= RDP_V5 && g_negotiate_rdp_protocol)
		length += 8;

	s = tcp_init(conn, length);

	out_uint8(s, 3);	/* version */
	out_uint8(s, 0);	/* reserved */
	out_uint16_be(s, length);	/* length */

	out_uint8(s, length - 5);	/* hdrlen */
	out_uint8(s, ISO_PDU_CR);
	out_uint16(s, 0);	/* dst_ref */
	out_uint16(s, 0);	/* src_ref */
	out_uint8(s, 0);	/* class */

	out_uint8p(s, "Cookie: mstshash=", strlen("Cookie: mstshash="));
	out_uint8p(s, username, strlen(username));

	out_uint8(s, 0x0d);	/* cookie termination string: CR+LF */
	out_uint8(s, 0x0a);

	if (conn->useRdp5 >= RDP_V5 && g_negotiate_rdp_protocol)
	{
		/* optional RDP protocol negotiation request for RDPv5 */
		out_uint8(s, RDP_NEG_REQ);
		out_uint8(s, 0);
		out_uint16(s, 8);
		out_uint32(s, neg_proto);
	}

	s_mark_end(s);
	tcp_send(conn, s);
}

/* Receive a message on the ISO layer, return code */
static RDStreamRef
iso_recv_msg(RDConnectionRef conn, uint8 * code, uint8 * rdpver)
{
	RDStreamRef s;
	uint16 length;
	uint8 version;

	s = tcp_recv(conn, NULL, 4);
	if (s == NULL)
		return NULL;
	in_uint8(s, version);
	if (rdpver != NULL)
		*rdpver = version;
	if (IS_SLOWPATH(version))
	{
		in_uint8s(s, 1);		/* reserved */
		in_uint16_be(s, length);	/* length */
	}
	else
	{
		in_uint8(s, length); /* length1 */
		if (length & 0x80)
		{
			/* length2 is only present if the most significant bit of length1 is set */
			length &= ~0x80;
			next_be(s, length);
		}
	}
	if (length < 4)
	{
		error( "iso_recv_msg(), bad packet header, length < 4");
		return NULL;
	}
	s = tcp_recv(conn, s, length - 4);
	if (s == NULL)
		return NULL;
	if (IS_FASTPATH(version))
		return s;
	in_uint8s(s, 1);	/* hdrlen */
	in_uint8(s, *code);
	if (*code == ISO_PDU_DT)
	{
		in_uint8s(s, 1);	/* eot */
		return s;
	}
	in_uint8s(s, 5);	/* dst_ref, src_ref, class */
	return s;
}

/* Initialise ISO transport data packet */
RDStreamRef
iso_init(RDConnectionRef conn, int length)
{
	RDStreamRef s;

	s = tcp_init(conn, length + 7);
	s_push_layer(s, iso_hdr, 7);

	return s;
}

/* Send an ISO data PDU */
void
iso_send(RDConnectionRef conn, RDStreamRef s)
{
	uint16 length;

	s_pop_layer(s, iso_hdr);
	length = s->end - s->p;

	out_uint8(s, T123_HEADER_VERSION);	/* version */
	out_uint8(s, 0);	/* reserved */
	out_uint16_be(s, length);

	out_uint8(s, 2);	/* hdrlen */
	out_uint8(s, ISO_PDU_DT);	/* code */
	out_uint8(s, 0x80);	/* eot */

	tcp_send(conn, s);
}

/* Receive ISO transport data packet */
RDStreamRef
iso_recv(RDConnectionRef conn, uint8 * rdpver)
{
	RDStreamRef s;
	uint8 code = 0;

	s = iso_recv_msg(conn, &code, rdpver);
	if (s == NULL)
		return NULL;
	if (rdpver != NULL)
		if (IS_FASTPATH(*rdpver))
			return s;
	if (code != ISO_PDU_DT)
	{
		error( "iso_recv(), expected ISO_PDU_DT, got 0x%x", code);
		return NULL;
	}
	return s;
}

/* Establish a connection up to the ISO layer */
RD_BOOL
iso_connect(RDConnectionRef conn, char *server, char *username, char *domain, char *password,
	    RD_BOOL reconnect, uint32 * selected_protocol)
{
	RDStreamRef s;
	uint8 code;
	uint32 neg_proto;

	g_negotiate_rdp_protocol = True;

	neg_proto = PROTOCOL_SSL;

        int nla = (neg_proto & PROTOCOL_HYBRID);
	DEBUG(("Connecting to server using %s...", nla?"NLA":"SSL"));

      retry:
	*selected_protocol = PROTOCOL_RDP;
	code = 0;

	if (!tcp_connect(conn, server))
		return False;

	iso_send_connection_request(conn, username, neg_proto);

	s = iso_recv_msg(conn, &code, NULL);
	if (s == NULL)
		return False;

	if (code != ISO_PDU_CC)
	{
		error( "iso_connect(), expected ISO_PDU_CC, got 0x%x", code);
		tcp_disconnect(conn);
		return False;
	}

	if (conn->useRdp5 >= RDP_V5 && s_check_rem(s, 8))
	{
		/* handle RDP_NEG_REQ response */
		const char *reason = NULL;

		uint8 type = 0;
		uint32 data = 0;

		in_uint8(s, type);
		in_uint8s(s, 1); /* skip flags */
		in_uint8s(s, 2); /* skip length */
		in_uint32(s, data);

		if (type == RDP_NEG_FAILURE)
		{
			RD_BOOL retry_without_neg = False;

			switch (data)
			{
				case SSL_WITH_USER_AUTH_REQUIRED_BY_SERVER:
					reason = "SSL with user authentication required by server";
					break;
				case SSL_NOT_ALLOWED_BY_SERVER:
					reason = "SSL not allowed by server";
					retry_without_neg = True;
					break;
				case SSL_CERT_NOT_ON_SERVER:
					reason = "no valid authentication certificate on server";
					retry_without_neg = True;
					break;
				case INCONSISTENT_FLAGS:
					reason = "inconsistent negotiation flags";
					break;
				case SSL_REQUIRED_BY_SERVER:
					reason = "SSL required by server";
					break;
				case HYBRID_REQUIRED_BY_SERVER:
					reason = "CredSSP required by server";
					break;
				default:
					reason = "unknown reason";
			}

			tcp_disconnect(conn);

			if (retry_without_neg)
			{
				if (reason != NULL)
				{
					DEBUG(("Protocol negotiation failed with reason: %s",reason));
				}

				DEBUG(("Retrying with plain RDP."));
				g_negotiate_rdp_protocol = False;
				goto retry;
			}

			DEBUG(("Failed to connect, %s.\n", reason));
			return False;
		}

		if (type != RDP_NEG_RSP)
		{
			error("iso_connect(), expected RDP_NEG_RSP, got 0x%x", type);
			tcp_disconnect(conn);
			return False;
		}

		else if (data == PROTOCOL_RDP)
		{
			DEBUG(("Connection established using plain RDP."));
		}
		else if (data != PROTOCOL_RDP)
		{
			error("iso_connect(), unexpected protocol in negotiation response, got 0x%x",data);
			tcp_disconnect(conn);
			return False;
		}

		*selected_protocol = data;
	}
	return True;
}

/* Disconnect from the ISO layer */
void
iso_disconnect(RDConnectionRef conn)
{
	iso_send_msg(conn, ISO_PDU_DR);
	tcp_disconnect(conn);
}

/* reset the state to support reconnecting */
void
iso_reset_state(RDConnectionRef conn)
{
	tcp_reset_state(conn);
}
