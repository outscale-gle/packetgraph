/* Copyright 2015 Nodalink EURL
 *
 * This file is part of Butterfly.
 *
 * Butterfly is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 3 as published
 * by the Free Software Foundation.
 *
 * Butterfly is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Butterfly.  If not, see <http://www.gnu.org/licenses/>.
 */

/**
 * Implements: https://tools.ietf.org/html/rfc7348#section-4.1
 *
 * Note: the implementation does not support the optional VLAN tag in the VXLAN
 *	 header
 *
 * Note2: the implementation expects that the IP checksum will be offloaded to
 *	  the NIC
 */

#include <ccan/endian/endian.h>

#include <rte_config.h>
#include <rte_errno.h>
#include <rte_ether.h>
#include <rte_hash_crc.h>
#include <rte_ip.h>
#include <rte_memcpy.h>
#include <rte_table.h>
#include <rte_table_hash.h>
#include <rte_prefetch.h>
#include <rte_udp.h>

#include "bricks/brick.h"
#include "packets/packets.h"
#include "utils/bitmask.h"
#include "utils/mempool.h"

#define VTEP_I_FLAG		(1 << 4)
#define VTEP_DST_PORT		4789

#define UDP_MIN_PORT 49152
#define UDP_PORT_RANGE 16383
#define UDP_PROTOCOL_NUMBER 17
#define IGMP_PROTOCOL_NUMBER 0x02
/**
 * Composite structure of all the headers required to wrap a packet in VTEP
 */
struct headers {
	struct ether_hdr ethernet; /* define in rte_ether.h */
	struct ipv4_hdr	 ipv4; /* define in rte_ip.h */
	struct udp_hdr	 udp; /* define in rte_udp.h */
	struct vxlan_hdr vxlan; /* define in rte_ether.h */
} __attribute__((__packed__));

struct igmp_hdr {
	uint8_t type;
	uint8_t maxRespTime;
	uint16_t checksum;
	uint32_t groupAddr;
} __attribute__((__packed__));

struct multicast_pkt {
	struct ether_hdr ethernet;
	struct ipv4_hdr ipv4;
	struct igmp_hdr igmp;
} __attribute__((__packed__));


#define HEADERS_LENGTH sizeof(struct headers)
#define IGMP_PKT_LEN sizeof(struct multicast_pkt)

/**
 * hold a couple of destination MAC and IP addresses
 */
struct dest_addresses {
	uint32_t ip;
	struct ether_addr mac;
};

/* structure used to describe a port of the vtep */
struct vtep_port {
	uint32_t vni;		/* the VNI of this ethernet port */
	uint32_t multicast_ip;  /* the multicast ip associated with the VNI */
	void *original;
	void *mac_to_dst;	/* is the destination mac learn by this port */
	void *known_mac;	/* is the MAC adress on this port  */
};

struct vtep_state {
	struct brick brick;
	uint32_t ip;			/* IP of the VTEP */
	uint64_t *masks;		/* internal port packet masks */
	enum side output;		/* the side the VTEP packets will go */
	uint16_t dst_port;		/* the UDP destination port */
	void *vni_to_port;		/* map VNIs to vtep_port pointers */
	struct ether_addr mac;		/* MAC address of the VTEP */
	struct vtep_port *ports;
	rte_atomic16_t packet_id;	/* IP identification number */
	struct rte_mbuf *pkts[64];
};

static inline int do_add_mac(struct vtep_port *port, struct ether_addr *mac);

static inline uint64_t hash_32(void *key, uint32_t key_size, uint64_t seed)
{
	return _mm_crc32_u32(seed, *((uint64_t *) key));
}

static inline uint64_t hash_64(void *key, uint32_t key_size, uint64_t seed)
{
	return _mm_crc32_u64(seed, *((uint64_t *) key));
}

static void multicast_filter(struct vtep_state *state,
			     struct rte_mbuf **pkts,
			     uint64_t pkts_mask,
			     uint64_t *result_mask)
{
	uint64_t unicast_mask = 0;

	for (; pkts_mask;) {
		struct ether_hdr *eth_hdr;
		struct rte_mbuf *pkt;
		uint64_t bit;
		uint16_t i;

		low_bit_iterate_full(pkts_mask, bit, i);

		pkt = pkts[i];

		eth_hdr = rte_pktmbuf_mtod(pkt, struct ether_hdr *);

		/* if the packet is multicast or broadcast flood it */
		if (unlikely(is_multicast_ether_addr(&eth_hdr->d_addr)))
			continue;

		unicast_mask |= bit;
	}

	*result_mask = unicast_mask;
}

/**
 * Is the given IP in the multicast range ?
 *
 * http://www.iana.org/assignments/multicast-addresses/multicast-addresses.xhtml
 *
 * @param	ip the ip to check
 * @return	1 if true, 0 if false
 */
static int is_multicast_ip(uint32_t ip)
{
	uint8_t byte;

	byte = ((uint8_t *) &ip)[0];

	if (byte >= 224 && byte <= 239)
		return 1;

	return 0;
}

/**
 * Build the VXLAN header
 *
 * @param	header pointer to the VTEP header
 * @param	vni 24 bit Virtual Network Identifier
 */
static void vxlan_build(struct vxlan_hdr *header, uint32_t vni)
{
	/* mark the VNI as valid */
	header->vx_flags |= VTEP_I_FLAG;

	/**
	 * We have checked the VNI validity at VNI setup so reserved byte will
	 * be zero.
	 */
	header->vx_vni = cpu_to_be32(vni);
}

/**
 * Compute a hash on the ethernet header that will be used for
 * ECMP/load-balancing
 *
 * @param	eth_hdr the ethernet header that must be hashed
 * @return	the hash of 16 first bytes of the ethernet frame
 */
static uint16_t ethernet_header_hash(struct ether_hdr *eth_hdr)
{
	uint64_t *data = (uint64_t *) eth_hdr;
	/* TODO: set the seed */
	uint64_t result = hash_64(data, 8, 0);

	result |= hash_64(data + 1, 8, 0);

	return (uint16_t) result;
}

/**
 * Compute the udp source port for ECMP/load-balancing
 *
 * @param	ether_hash the ethernet hash to use as a basis for the src port
 * @return	the resulting UDP source port
 */
static uint16_t src_port_compute(uint16_t ether_hash)
{
	return (ether_hash % UDP_PORT_RANGE) + UDP_MIN_PORT;
}

/**
 * Build the UDP header
 *
 * @param	udp_hdr pointer to the UDP header
 * @param	inner_eth_hdr pointer to the ethernet frame to encapsulate
 * @param	dst_port UDP destination port
 * @param	datagram_len length of the UDP datagram
 */
static void udp_build(struct udp_hdr *udp_hdr,
		      struct ether_hdr *inner_eth_hdr,
		      uint16_t dst_port,
		      uint16_t datagram_len)
{
	uint32_t ether_hash = ethernet_header_hash(inner_eth_hdr);
	uint16_t src_port = src_port_compute(ether_hash);

	udp_hdr->src_port = cpu_to_be16(src_port);
	udp_hdr->dst_port = cpu_to_be16(dst_port);
	udp_hdr->dgram_len = cpu_to_be16(datagram_len);

	/* UDP checksum SHOULD be transmited as zero */
}

/**
 * Build the IP header
 *
 * @param	ip_hdr pointer to the ip header to build
 * @param	src_ip the source IP
 * @param	dst_ip the destination IP
 * @param	datagram_len the lenght of the datagram including the header
 */
static void ip_build(struct vtep_state *state, struct ipv4_hdr *ip_hdr,
	      uint32_t src_ip, uint32_t dst_ip, uint16_t datagram_len)
{
	ip_hdr->version_ihl = 0x45;

	/* TOS is zero (routine) */

	ip_hdr->total_length = cpu_to_be16(datagram_len);

	/* Set the packet id and increment it */
	ip_hdr->packet_id =
		cpu_to_be16(rte_atomic16_add_return(&state->packet_id, 1));

	/* the implementation do not use neither DF nor MF */

	/* packet are not fragmented so Fragment Offset is zero */

	/* recommended TTL value */
	ip_hdr->time_to_live = 64;

	/* This IP datagram encapsulate and UDP packet */
	ip_hdr->next_proto_id = UDP_PROTOCOL_NUMBER;

	/* the header checksum computation is to be offloaded in the NIC */

	ip_hdr->src_addr = cpu_to_be32(src_ip);
	ip_hdr->dst_addr = cpu_to_be32(dst_ip);
}

/**
 * Build the ethernet header
 *
 * @param	eth_hdr pointer to the ethernet header
 * @param	src_mac source MAC address
 * @param	dst_mac destination MAC address
 */
static void ethernet_build(struct ether_hdr *eth_hdr,
			   struct ether_addr *src_mac,
			   struct ether_addr *dst_mac)
{
	/* copy mac addresses */
	ether_addr_copy(src_mac, &eth_hdr->s_addr);
	ether_addr_copy(dst_mac, &eth_hdr->d_addr);

	/* the ethernet frame carries an IP packet */
	eth_hdr->ether_type = cpu_to_be16(ETHER_TYPE_IPv4);
}

static uint16_t udp_overhead(void)
{
	return sizeof(struct vxlan_hdr) + sizeof(struct udp_hdr);
}

static uint16_t ip_overhead(void)
{
	return udp_overhead() + sizeof(struct ipv4_hdr);
}

static int vtep_header_prepend(struct vtep_state *state,
				 struct rte_mbuf *pkt, struct vtep_port *port,
				 struct dest_addresses *entry, int unicast,
				 struct switch_error **errp)
{
	struct ether_hdr *eth_hdr = rte_pktmbuf_mtod(pkt, struct ether_hdr *);
	uint16_t packet_len = rte_pktmbuf_data_len(pkt);
	/* TODO: double check this value */
	struct ether_addr multicast_mac = {{0x01, 0x00, 0x00,
					    0x00, 0x00, 0x00} };
	struct ether_addr *dst_mac;
	struct headers *headers;
	uint32_t dst_ip;

	headers = (struct headers *) rte_pktmbuf_prepend(pkt, HEADERS_LENGTH);

	if (!headers) {
		*errp = error_new("No enough headroom to add VTEP headers");
		return 0;
	}

	/* make sure headers are clear */
	memset(headers, 0, sizeof(struct headers));

	/* build the headers from the inside to the outside */

	vxlan_build(&headers->vxlan, port->vni);
	udp_build(&headers->udp, eth_hdr, state->dst_port,
		  packet_len + udp_overhead());

	/* select destination IP and MAC address */
	if (unicast) {
		dst_mac = &entry->mac;
		dst_ip = entry->ip;
	} else {
		if (!do_add_mac(port, &eth_hdr->s_addr)) {
			*errp = error_new("Failed to add mac for brick'%s'",
					  state->brick.name);
			return 0;
		}
		dst_mac = &multicast_mac;
		dst_ip = port->multicast_ip;
	}
	ip_build(state, &headers->ipv4, state->ip, dst_ip,
		 packet_len + ip_overhead());
	ethernet_build(&headers->ethernet, &state->mac, dst_mac);
	
	return 1;
}

static int vtep_encapsulate(struct vtep_state *state, struct vtep_port *port,
			     struct rte_mbuf **pkts, uint64_t pkts_mask,
			     uint64_t unicast_mask, struct switch_error **errp)
{
	uint64_t lookup_hit_mask = 0, ip_masks;
	struct dest_addresses *entries[64];
	int ret;

	/* lookup for known destination IPs */
	ret = rte_table_hash_key8_lru_dosig_ops.f_lookup(port->mac_to_dst,
						    pkts,
						    unicast_mask,
						    &lookup_hit_mask,
						    (void **) entries);

	if (unlikely(ret)) {
		*errp = error_new_errno(-ret, "Fail to lookup dest address");
		return 0;
	}

	ip_masks = unicast_mask & lookup_hit_mask;

	/* do the encapsulation */
	for (; pkts_mask;) {
		struct dest_addresses *entry = NULL;
		/* struct ether_hdr *eth_hdr; */
		/* uint32_t dst_ip; */
		uint64_t bit;
		int unicast;
		uint16_t i;
		struct rte_mbuf *tmp;
		struct rte_mempool *mp = get_mempool();

		low_bit_iterate_full(pkts_mask, bit, i);

		/* must we encapsulate in an unicast VTEP header */
		unicast = bit & ip_masks;

		/* pick up the right destination ip */
		if (unicast)
			entry = entries[i];
		
		tmp = rte_pktmbuf_clone(pkts[i], mp);
		if (unlikely(!tmp))
			return 0;

		ret = vtep_header_prepend(state, tmp, port,
					   entry, unicast, errp);

		if (unlikely(!ret)) {
			rte_pktmbuf_free(tmp);
			return 0;
		}
		state->pkts[i] = tmp;

	}

	return 1;
}

static int to_vtep(struct brick *brick, enum side from,
		    uint16_t edge_index, struct rte_mbuf **pkts,
		    uint16_t nb, uint64_t pkts_mask,
		    struct switch_error **errp)
{
	struct vtep_state *state = brick_get_state(brick, struct vtep_state);
	struct brick_side *s = &brick->sides[flip_side(from)];
	struct vtep_port *port = &state->ports[edge_index];
	/* TODO do we really need to initialise the variable here ? */
	uint64_t unicast_mask = 0;
	int ret;

	/* if the port VNI is not set up ignore the packets */
	if (!port->multicast_ip)
		return 1;

	packets_prefetch(pkts, pkts_mask);

	/* TODO: account the size of the VTEP header in prepare hash keys */
	ret = packets_prepare_hash_keys(pkts, pkts_mask, errp);

	if (unlikely(!ret))
		return 0;

	/* TODO: maybe we can merge this with vtep_encapsulate
	 * if we do that we will have one less loop :) */
	multicast_filter(state, pkts, pkts_mask, &unicast_mask);

	ret = vtep_encapsulate(state, port, pkts, pkts_mask,
				unicast_mask, errp);

	if (unlikely(!ret))
		goto no_forward;

	packets_clear_hash_keys(state->pkts, pkts_mask);

	ret =  brick_side_forward(s, from, state->pkts, nb, pkts_mask, errp);
	packets_free(state->pkts, pkts_mask);
	return ret;

no_forward:
	packets_clear_hash_keys(state->pkts, pkts_mask);
	return 0;
}

static inline int add_dst_iner_mac(struct vtep_port *port,
				   struct ether_addr *iner_mac,
				   struct dest_addresses *dst) {
	void *entry = NULL;
	int key_found;
	int ret;
	int8_t tmp[8] = {0, 0, 0, 0, 0, 0, 0, 0};
	int i;

	for (i = 0; i  < 6; ++i)
		tmp[i] = iner_mac->addr_bytes[i];
	ret = rte_table_hash_key8_lru_dosig_ops.f_add(port->mac_to_dst,
						      &tmp, dst,
						      &key_found,
						      &entry);
	return !ret;
}

static inline int add_dst_iner_macs(struct vtep_port *port,
				    struct rte_mbuf **pkts,
				    struct headers **hdrs,
				    uint64_t pkts_mask,
				    uint64_t multicast_mask) {
	uint64_t mask;
	uint64_t bit;

	for (mask = multicast_mask; mask;) {
		int i;

		low_bit_iterate_full(mask, bit, i);
		if (multicast_mask & (1 << i)) {
			struct dest_addresses dst;
			struct ether_hdr *pkt_addr;

			pkt_addr = rte_pktmbuf_mtod(pkts[i],
						    struct ether_hdr *);
			ether_addr_copy(&hdrs[i]->ethernet.s_addr, &dst.mac);
			dst.ip = be32_to_cpu(hdrs[i]->ipv4.src_addr);
			if (!unlikely(add_dst_iner_mac(port,
						       &pkt_addr->s_addr,
						       &dst)))
				return 0;
		}
	}
	return 1;
}

static inline int from_vtep_failure(struct rte_mbuf **pkts, uint64_t pkts_mask)
{
	packets_clear_hash_keys(pkts, pkts_mask);
	packets_free(pkts, pkts_mask);
	return 0;
}

static void check_multicasts_pkts(struct rte_mbuf **pkts, uint64_t mask,
				  struct headers **hdrs,
				  uint64_t *multicast_mask,
				  uint64_t *computed_mask)
{
	for (*multicast_mask = 0, *computed_mask = 0; mask;) {
		int i;

		low_bit_iterate(mask, i);
		hdrs[i] = rte_pktmbuf_mtod(pkts[i], struct headers *);
		if (hdrs[i]->ethernet.ether_type !=
		    cpu_to_be16(ETHER_TYPE_IPv4) ||
		    hdrs[i]->ipv4.next_proto_id != 17 ||
		    hdrs[i]->vxlan.vx_flags != VTEP_I_FLAG)
			continue;
		if (is_multicast_ip(be32_to_cpu(hdrs[i]->ipv4.dst_addr)))
			*multicast_mask |= (1 << i);
		*computed_mask |= (1 << i);
	}
}

static uint64_t check_vni_pkts(struct rte_mbuf **pkts, uint64_t mask,
			       struct headers **hdrs,
			       struct vtep_port *port,
			       struct rte_mbuf **out_pkts)
{
	uint64_t vni_mask;

	for (vni_mask = 0; mask;) {
		int j;

		low_bit_iterate(mask, j);
		if (hdrs[j]->vxlan.vx_vni == port->vni) {
			struct rte_mbuf *tmp;
			struct rte_mempool *mp = get_mempool();

			tmp = rte_pktmbuf_clone(pkts[j], mp);
			if (unlikely(!tmp))
				return 0;
			out_pkts[j] = tmp;
			rte_pktmbuf_adj(out_pkts[j], HEADERS_LENGTH);
			vni_mask |= (1 << j);
		}
	}
	return vni_mask;
}

static int from_vtep(struct brick *brick, enum side from,
		      uint16_t edge_index, struct rte_mbuf **pkts,
		      uint16_t nb, uint64_t pkts_mask,
		      struct switch_error **errp)
{
	struct vtep_state *state = brick_get_state(brick, struct vtep_state);
	struct brick_side *s = &brick->sides[flip_side(from)];
	int i;
	struct headers *hdrs[64];
	struct rte_mbuf **out_pkts = state->pkts;
	uint64_t multicast_mask;
	uint64_t computed_pkts;

	check_multicasts_pkts(pkts, pkts_mask, hdrs,
			      &multicast_mask, &computed_pkts);

	pkts_mask &= computed_pkts;
	/* TODO NEED optimisation and refatoring */
	for (i = 0; i < s->nb; ++i) {
		struct vtep_port *port = &state->ports[i];
		uint64_t hitted_mask = 0;
		uint64_t vni_mask;
		int *entries[64];
		int ret = 0;

		if (!pkts_mask)
			break;
		/* Decaspulate and check the vni*/
		vni_mask = check_vni_pkts(pkts, pkts_mask, hdrs,
					  port, out_pkts);
		if (!vni_mask)
			continue;

		pkts_mask = pkts_mask ^ vni_mask;
		packets_prefetch(out_pkts, vni_mask);
		if (unlikely(!packets_prepare_hash_keys(out_pkts,
							vni_mask,
							errp)))
			return 0;

		ret = rte_table_hash_key8_lru_dosig_ops.f_lookup(port->
								 known_mac,
								 out_pkts,
								 vni_mask,
								 &hitted_mask,
								 (void **)
								 entries);
		if (unlikely(ret)) {
			*errp = error_new_errno(-ret,
						"Fail to lookup dest address");
			return from_vtep_failure(out_pkts, vni_mask);
		}
		if (hitted_mask) {

			if (unlikely(!brick_burst(s->edges[i].link,
						  from,
						  i, out_pkts, nb,
						  hitted_mask,
						  errp)))
				return from_vtep_failure(out_pkts, vni_mask);

			if (unlikely(!add_dst_iner_macs(port, out_pkts, hdrs,
							hitted_mask,
							multicast_mask)))
				return from_vtep_failure(out_pkts, vni_mask);
		}
		packets_clear_hash_keys(out_pkts, vni_mask);
		packets_free(out_pkts, vni_mask);
	}
	return 1;
}

static int vtep_burst(struct brick *brick, enum side from,
			uint16_t edge_index, struct rte_mbuf **pkts,
			uint16_t nb, uint64_t pkts_mask,
			struct switch_error **errp)
{
	struct vtep_state *state = brick_get_state(brick, struct vtep_state);

	/* if pkts come from the outside,
	 * so the pkts are entering in the vtep */
	if (from == state->output)
		return from_vtep(brick, from, edge_index,
				  pkts, nb, pkts_mask, errp);
	else
		return to_vtep(brick, from, edge_index,
				pkts, nb, pkts_mask, errp);
}

/**
 * This function will initialize the vtep_state hash common hash tables
 *
 * @param	the brick we are working with
 * @param	an error pointer
 */
static void vtep_init_hashes(struct brick *brick,
			      struct switch_error **errp)
{
	struct vtep_state *state = brick_get_state(brick, struct vtep_state);

	struct rte_table_hash_lru_params vni_hash_params = {
		.key_size = 4,
		.n_keys = HASH_ENTRIES,
		.n_buckets = HASH_ENTRIES >> 2,
		.f_hash = hash_32,
		.seed = 0,
		.signature_offset = 0,
		.key_offset = 0,
	};

	state->vni_to_port = rte_table_hash_lru_dosig_ops.f_create(
		&vni_hash_params,
		rte_socket_id(),
		sizeof(struct vtep_port *));

	if (!state->vni_to_port) {
		*errp = error_new("Failed to create hash for brick '%s'",
				  brick->name);
		return;
	}
}

static int vtep_init(struct brick *brick,
		      struct brick_config *config, struct switch_error **errp)
{
	struct vtep_state *state = brick_get_state(brick, struct vtep_state);
	struct vtep_config *vtep_config;
	uint16_t max;

	if (!config) {
		*errp = error_new("config is NULL");
		return 0;
	}

	if (!config->vtep) {
		*errp = error_new("config->vtep is NULL");
		return 0;
	}

	vtep_config = config->vtep;

	state->output = vtep_config->output;
	if (brick->sides[state->output].max != 1) {
		*errp = error_new("brick %s Number of output port is not one",
				  brick->name);
		return 0;
	}
	state->ip = vtep_config->ip;
	ether_addr_copy(&vtep_config->mac, &state->mac);

	rte_atomic16_set(&state->packet_id, 0);

	if (error_is_set(errp))
		return 0;

	vtep_init_hashes(brick, errp);

	if (error_is_set(errp))
		return 0;

	/* do a lazy allocation of the VTEP ports: the code will init them
	 * at VNI port add
	 */
	max = brick->sides[flip_side(state->output)].max;
	state->ports = g_new0(struct vtep_port, max);
	state->masks = g_new0(uint64_t, max);

	brick->burst = vtep_burst;

	return 1;
}

static void vtep_destroy(struct brick *brick, struct switch_error **errp)
{
	struct vtep_state *state = brick_get_state(brick, struct vtep_state);

	g_free(state->masks);
	g_free(state->ports);

	rte_table_hash_lru_dosig_ops.f_free(state->vni_to_port);
}

/**
 * Is the given VNI valid
 *
 * @param	vni the VNI to check
 * @return	1 if true, 0 if false
 */
static int is_vni_valid(uint32_t vni)
{
	/* VNI is coded on 24 bits */
	return vni <= (UINT32_MAX >> 8);
}

/**
 * Map VNI to port
 *
 * No collision should be detected by this function: hence the g_assert
 *
 * @param	state the state we are working with
 * @param	vni the 24 bit VNI to map
 * @param	port a pointer to a struct vtep_port
 * @param	errp an error pointer
 */
static void vni_map(struct vtep_state *state, uint32_t vni,
		    struct vtep_port *port, struct switch_error **errp)
{
	void *entry = NULL;
	int key_found;
	int ret;

	ret = rte_table_hash_lru_dosig_ops.f_add(state->vni_to_port,
						 &vni, port,
						 &key_found, &entry);
	if (unlikely(ret)) {
		*errp = error_new_errno(-ret,
			"Fail to learn associate VNI to port");
		return;
	}
	/* A VNI was added twice to the VTEP -> assert */
	g_assert(!key_found);
}

static inline uint16_t igmp_checksum(struct igmp_hdr *msg, size_t size)
{
	uint16_t sum = 0;

	sum = rte_raw_cksum(msg, sizeof(struct igmp_hdr));
	return ~sum;
}


static uint64_t multicast_get_dst_addr(uint32_t ip)
{
	uint64_t dst = 0;

	/* Forge dst mac addr */
	dst |= (cpu_to_be32(ip) & 0x0007ffff);
	((uint8_t *)&dst)[5] = 0x10;
	((uint8_t *)&dst)[4] = 0x5e;
	/* To network order */
	dst = cpu_to_be64(dst);
	return dst;
}

#define UINT64_TO_MAC(val) ((struct ether_addr *)((uint16_t *)&val + 1))

/* static void multicast_build_ip() */
/* { */
/* 	hdr->ipv4.version_ihl = 0x45; */
/* 	hdr->ipv4.type_of_service = 0; */
/* 	hdr->ipv4.total_length = cpu_to_be16(sizeof(struct ipv4_hdr) + */
/* 					     sizeof(struct igmp_hdr)); */
/* 	hdr->ipv4.packet_id = 0; */
/* 	hdr->ipv4.fragment_offset = 0; */
/* 	hdr->ipv4.time_to_live = 1; */
/* 	hdr->ipv4.next_proto_id = IGMP_PROTOCOL_NUMBER; */
/* 	hdr->ipv4.hdr_checksum = 0; */
/* 	hdr->ipv4.dst_addr = multicast_ip; */
/* 	hdr->ipv4.src_addr = state->ip; */

/* 	hdr->ipv4.hdr_checksum = rte_ipv4_cksum(&hdr->ipv4); */
/* } */

static void multicast_subscribe(struct vtep_state *state,
				struct vtep_port *port,
				uint32_t multicast_ip,
				struct switch_error **errp)
{
	struct rte_mempool *mp = get_mempool();
	struct rte_mbuf *pkt[1];
	struct multicast_pkt *hdr;
	uint64_t dst = multicast_get_dst_addr(multicast_ip);

	if (!is_multicast_ip(multicast_ip))
		goto error_invalid_address;

	/* The all-systems group (224.0.0.1) is handled as a special case. */
	/* The host never sends a report for that group */
	if (multicast_ip == IPv4(224, 0, 0, 1))
		goto error_invalid_address;

	/* Allocate a memory buffer to hold an IGMP message */
	pkt[0] = rte_pktmbuf_alloc(mp);
	if (!pkt[0]) {
		error_new("Packet allocation faild");
		return;
	}

	/* Point to the beginning of the IGMP message */
	hdr = (struct multicast_pkt *) rte_pktmbuf_append(pkt[0],
							  IGMP_PKT_LEN);

	ether_addr_copy(&state->mac, &hdr->ethernet.s_addr);
	/* Because of the conversion from le to be, we need to skip the first
	 * byte of dst when making the copy*/
	ether_addr_copy(UINT64_TO_MAC(dst),
			&hdr->ethernet.d_addr);
	hdr->ethernet.ether_type = cpu_to_be16(ETHER_TYPE_IPv4);

	/* 4-5 = 0x45 */
	hdr->ipv4.version_ihl = 0x45;
	hdr->ipv4.type_of_service = 0;
	hdr->ipv4.total_length = cpu_to_be16(sizeof(struct ipv4_hdr) +
					     sizeof(struct igmp_hdr));
	hdr->ipv4.packet_id = 0;
	hdr->ipv4.fragment_offset = 0;
	hdr->ipv4.time_to_live = 1;
	hdr->ipv4.next_proto_id = IGMP_PROTOCOL_NUMBER;
	hdr->ipv4.hdr_checksum = 0;
	hdr->ipv4.dst_addr = multicast_ip;
	hdr->ipv4.src_addr = state->ip;

	hdr->ipv4.hdr_checksum = rte_ipv4_cksum(&hdr->ipv4);

	/* Version 2 Membership Report = 0x16 */
	hdr->igmp.type = 0x16;
	hdr->igmp.maxRespTime = 0;
	hdr->igmp.checksum = 0;
	hdr->igmp.groupAddr = multicast_ip;

	hdr->igmp.checksum = igmp_checksum(&hdr->igmp, sizeof(struct igmp_hdr));

	/* The Membership Report message is sent to the group being reported */
	if (!brick_side_forward(&state->brick.sides[state->output],
				flip_side(state->output),
				pkt, 1, mask_firsts(1), errp)) {
		rte_pktmbuf_free(pkt[0]);
		/* let's admit the error is set */
		return;
	}

	rte_pktmbuf_free(pkt[0]);
	return;
error_invalid_address:
	error_new("invalide multicast adress");
}

static void multicast_unsubscribe(struct vtep_state *state,
				  struct vtep_port *port,
				  uint32_t multicast_ip,
				  struct switch_error **errp)
{
	struct rte_mempool *mp = get_mempool();
	struct rte_mbuf *pkt[1];
	struct multicast_pkt *hdr;
	uint64_t dst = multicast_get_dst_addr(multicast_ip);

	if (!is_multicast_ip(multicast_ip))
		goto error_invalid_address;

	/* The all-systems group (224.0.0.1) is handled as a special case. */
	/* The host never sends a report for that group */
	if (multicast_ip == IPv4(224, 0, 0, 1))
		goto error_invalid_address;

	/* Allocate a memory buffer to hold an IGMP message */
	pkt[0] = rte_pktmbuf_alloc(mp);
	if (!pkt[0]) {
		error_new("Packet allocation faild");
		return;
	}

	/* Point to the beginning of the IGMP message */
	hdr = (struct multicast_pkt *) rte_pktmbuf_append(pkt[0],
							  IGMP_PKT_LEN);

	ether_addr_copy(&state->mac, &hdr->ethernet.s_addr);
	/* Because of the conversion from le to be, we need to skip the first
	 * byte of dst when making the copy*/
	ether_addr_copy(UINT64_TO_MAC(dst),
			&hdr->ethernet.d_addr);
	hdr->ethernet.ether_type = cpu_to_be16(ETHER_TYPE_IPv4);

	/* 4-5 = 0x45 */
	hdr->ipv4.version_ihl = 0x45;
	hdr->ipv4.type_of_service = 0;
	hdr->ipv4.total_length = cpu_to_be16(sizeof(struct ipv4_hdr) +
					     sizeof(struct igmp_hdr));
	hdr->ipv4.packet_id = 0;
	hdr->ipv4.fragment_offset = 0;
	hdr->ipv4.time_to_live = 1;
	hdr->ipv4.next_proto_id = 0x02;
	hdr->ipv4.hdr_checksum = 0;
	/* This ip is for All Routers */
	hdr->ipv4.dst_addr = IPv4(224, 0, 0, 2);
	hdr->ipv4.src_addr = state->ip;

	hdr->ipv4.hdr_checksum = rte_ipv4_cksum(&hdr->ipv4);

	/* Format the Leave Group message */
	hdr->igmp.type = 0x17;
	hdr->igmp.maxRespTime = 0;
	hdr->igmp.checksum = 0;
	hdr->igmp.groupAddr = multicast_ip;

	hdr->igmp.checksum = igmp_checksum(&hdr->igmp, sizeof(struct igmp_hdr));

	/* The Membership Report message is sent to the group being reported */
	if (brick_side_forward(&state->brick.sides[state->output],
			       flip_side(state->output),
			       pkt, 1, mask_firsts(1), errp)) {
		/* let's admit the error is set */
		return;
	}

	rte_pktmbuf_free(pkt[0]);
	return;
error_invalid_address:
	error_new("invalide multicast adress");
}

#undef UINT64_TO_MAC

static void do_add_vni(struct vtep_state *state, uint16_t edge_index,
		       int32_t vni, uint32_t multicast_ip,
		       struct switch_error **errp)
{
	struct vtep_port *port = &state->ports[edge_index];

	struct rte_table_hash_key8_lru_params hash_params = {
		.n_entries		= HASH_ENTRIES,
		.f_hash			= hash_64,
		.seed			= 0,
		.signature_offset	= 0,
		.key_offset		= 0,
	};

	/* TODO: return 1 ? */
	g_assert(!port->vni);
	g_assert(!port->multicast_ip);
	g_assert(!port->mac_to_dst);
	g_assert(!port->known_mac);

	port->vni = vni;
	port->multicast_ip = multicast_ip;

	port->mac_to_dst =
		rte_table_hash_key8_lru_dosig_ops.f_create(&hash_params,
		rte_socket_id(),
		sizeof(struct dest_addresses));

	port->original = port->mac_to_dst;
	if (!port->mac_to_dst) {
		*errp = error_new("Failed to create hash for vtep brick '%s'",
				  state->brick.name);
		return;
	}

	port->known_mac =
		rte_table_hash_key8_lru_dosig_ops.f_create(&hash_params,
		rte_socket_id(),
		sizeof(int)); /* 1 or 0 */

	if (!port->known_mac) {
		*errp = error_new("Failed to create hash for vtep brick '%s'",
				  state->brick.name);
		goto known_error_exit;
	}
	vni_map(state, vni, port, errp);

	if (error_is_set(errp))
		goto map_error_exit;

	multicast_subscribe(state, port, multicast_ip, errp);

	if (error_is_set(errp))
		goto map_error_exit;

	return;
map_error_exit:
	rte_table_hash_key8_lru_dosig_ops.f_free(port->known_mac);
known_error_exit:
	rte_table_hash_key8_lru_dosig_ops.f_free(port->mac_to_dst);
}

/**
 * Add a VNI to the VTEP
 *
 * NOTE: Adding the same VNI twice is not authorized and will result in an
 *       assertion
 *
 * @param	brick the brick we are working on
 * @param	neighbor a brick connected to the VTEP port
 * @param	vni the VNI to add
 * @param	multicast_ip the multicast ip to associate to the VNI
 * @param	errp an error pointer
 */
void vtep_add_vni(struct brick *brick,
		   struct brick *neighbor,
		   uint32_t vni, uint32_t multicast_ip,
		   struct switch_error **errp)
{
	struct vtep_state *state = brick_get_state(brick, struct vtep_state);
	enum side side = flip_side(state->output);
	uint16_t i;
	int found;
	struct ether_addr mac = {{0xff, 0xff, 0xff,
				  0xff, 0xff, 0xff} };

	if (!brick) {
		*errp = error_new("brick is NULL");
		return;
	}

	if (!neighbor) {
		*errp = error_new("VTEP brick is NULL");
		return;
	}

	if (!is_vni_valid(vni)) {
		*errp = error_new("Invalid VNI");
		return;
	}

	if (!is_multicast_ip(multicast_ip)) {
		*errp = error_new("Provided IP is not in the multicast range");
		return;
	}

	/* lookup for the vtep brick index */
	found = 0;
	for (i = 0; i < brick->sides[side].max; i++)
		if (neighbor == brick->sides[side].edges[i].link) {
			found = 1;
			break;
		}

	if (!found) {
		*errp = error_new("VTEP brick index not found");
		return;
	}

	do_add_vni(state, i, vni, multicast_ip, errp);
	if (!do_add_mac(&state->ports[i], &mac)) {
		*errp = error_new("Failed to add mac for brick'%s'",
				  state->brick.name);
	}

}

/**
 * Unmap VNI from port
 *
 * No spurious VNI removal should occur but we just ignore them since they are
 * harmless.
 *
 * @param	state the state we are working with
 * @param	vni the 24 bit VNI to map
 * @param	port a pointer to a struct vtep_port
 * @param	errp and error pointer
 */
static void vni_unmap(struct vtep_state *state,
		      uint32_t vni, struct switch_error **errp)
{
	void *entry = NULL;
	int key_found;
	int ret;

	ret = rte_table_hash_lru_dosig_ops.f_delete(state->vni_to_port,
						    &vni, &key_found, &entry);
	if (unlikely(ret)) {
		*errp = error_new_errno(-ret,
			"Fail to deassociate VNI from port");
		return;
	}
}

static void do_remove_vni(struct vtep_state *state,
		   uint16_t edge_index, struct switch_error **errp)
{
	struct vtep_port *port = &state->ports[edge_index];

	multicast_unsubscribe(state, port, port->multicast_ip, errp);

	if (error_is_set(errp))
		return;

	vni_unmap(state, port->vni, errp);

	if (error_is_set(errp))
		return;

	/* Do the hash destroy at the end since it's the less idempotent */
	rte_table_hash_key8_lru_dosig_ops.f_free(port->known_mac);
	rte_table_hash_key8_lru_dosig_ops.f_free(port->mac_to_dst);

	/* clear for next user */
	memset(port, 0, sizeof(struct vtep_port));
}

static inline int do_add_mac(struct vtep_port *port, struct ether_addr *mac)
{
	void *entry = NULL;
	int8_t tmp[8] = {0, 0, 0, 0, 0, 0, 0, 0};
	int val = 1;
	int i;

	for (i = 0; i  < 6; ++i)
		tmp[i] = mac->addr_bytes[i];
	return !rte_table_hash_key8_lru_dosig_ops.f_add(port->known_mac,
							&tmp, &val,
							&i,
							&entry);
}

/**
 * Add a MAC to a VNI
 *
 * @param	brick the brick
 * @param	neighbor the neighbor brick which is use as a VNI
 * @param	mac the mac
 * @param	errp an error pointer
 */
void vtep_add_mac(struct brick *brick,
		   struct brick *neighbor,

		   struct ether_addr *mac,
		   struct switch_error **errp)
{
	struct vtep_state *state = brick_get_state(brick, struct vtep_state);
	enum side side = flip_side(state->output);
	struct vtep_port *port;
	int ret;
	int i;

	for (i = 0; i < brick->sides[side].max; i++)
		if (neighbor == brick->sides[side].edges[i].link) {
			ret = 1;
			break;
		}
	if (!ret) {
		*errp = error_new("VTEP brick index not found");
		return;
	}

	port = &state->ports[i];
	if (!do_add_mac(port, mac)) {
		*errp = error_new("Failed to add mac for brick'%s'",
				  state->brick.name);
	}
}


static void vtep_unlink_notify(struct brick *brick,
				enum side side, uint16_t edge_index,
				struct switch_error **errp)
{
	struct vtep_state *state = brick_get_state(brick, struct vtep_state);

	if (side == state->output)
		return;

	do_remove_vni(state, edge_index, errp);
}

static struct brick_ops vtep_ops = {
	.name		= "vtep",
	.state_size	= sizeof(struct vtep_state),

	.init		= vtep_init,
	.destroy	= vtep_destroy,

	.unlink		= brick_generic_unlink,

	.unlink_notify  = vtep_unlink_notify,
};

#undef HEADERS_LENGTH

brick_register(struct vtep_state, &vtep_ops);