/*
 * lispd_external.h
 *
 * This file is part of LISP Mobile Node Implementation.
 * External definitions for lispd
 *
 * Copyright (C) 2011 Cisco Systems, Inc, 2011. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * Please send any bug reports or fixes you make to the email address(es):
 *    LISP-MN developers <devel@lispmob.org>
 *
 * Written or modified by:
 *    David Meyer       <dmm@cisco.com>
 *    Preethi Natarajan <prenatar@cisco.com>
 *    Lorand Jakab      <ljakab@ac.upc.edu>
 *    Alberto Rodriguez Natal <arnatal@ac.upc.edu>
 *
 */

#include "lispd.h"

/* from patricia.h */


extern  uint64_t build_nonce(int seed);
extern  struct udphdr *build_ip_header();
extern  int get_afi(char * str);
extern  lisp_addr_t *get_my_addr(char *if_name, int afi);
extern  lisp_addr_t *lispd_get_address(char *host,
                    lisp_addr_t *addr,
                    uint32_t *flags);
extern  lisp_addr_t *lispd_get_ifaceaddress(char *iface_name,
                                        lisp_addr_t *addr);
extern  uint8_t *build_map_request_pkt();
extern int process_map_reply(uint8_t *packet);
extern  lispd_pkt_map_register_t *build_map_register_pkt (lispd_locator_chain_t
                              *locator_chain);
extern  int install_database_mapping(lispd_db_entry_t *db_entry);
extern  patricia_node_t * make_and_lookup (patricia_tree_t *tree,
                       int afi, char *string);
extern  char *prefix_toa (prefix_t * prefix);
extern  int setup_netlink_iface();
extern  int process_netlink_iface();
extern  int update_iface_list(char *iface_name, 
                                char *eid_preifx, 
                                lispd_db_entry_t *db_entry, int ready,
                                int weight, int priority);
extern  iface_list_elt *find_active_ctrl_iface ();
extern  iface_list_elt *search_iface_list(char *iface_name);
extern  void add_item_to_db_entry_list(db_entry_list *dbl, 
                                        db_entry_list_elt *elt);
extern  int del_item_from_db_entry_list(db_entry_list *dbl, 
                                        lispd_db_entry_t *elt);


extern  lispd_database_t  *lispd_database;
extern  lispd_map_cache_t *lispd_map_cache;
extern  patricia_tree_t   *AF4_database;
extern  patricia_tree_t   *AF6_database;
extern  datacache_t   *datacache;

extern  lispd_addr_list_t *map_resolvers;
extern  lispd_addr_list_t *proxy_etrs;
extern  lispd_addr_list_t *proxy_itrs;
extern  lispd_map_server_list_t *map_servers;
extern  char            *config_file;
extern  char            *map_resolver;
extern  char            *map_server;
extern  char            *proxy_etr;
extern  char            *proxy_itr;
extern  char            msg[];
extern  int             map_request_retries;
extern  int             control_port;
extern  int             debug;
extern  int             daemonize;

extern  int         netlink_fd;
extern  int         v6_receive_fd;
extern  int         v4_receive_fd;
extern  int         map_register_timer_fd;
extern  struct  sockaddr_nl dst_addr;
extern  struct  sockaddr_nl src_addr;
extern  nlsock_handle       nlh;
extern  iface_list_elt      *ctrl_iface; 
extern  lisp_addr_t         source_rloc;

//modified by arnatal
extern int nat_aware;
extern int behind_nat;
lisp_addr_t rtr;



//modified by arnatal
// To avoid implicit function declaration warning
extern lisp_addr_t inet_lisp_addr(char *ipaddr, int afi);
extern char *inet_ntop_char(void *src, char *dst, int afi);
extern int compute_sha1_hmac(char *key, void *packet, int pckt_len,
                             void *auth_data_pos, int auth_data_len);
extern int get_lisp_afi_len(int afi);
extern int get_auth_data_len(int key_id);
extern int build_and_send_map_register(lispd_locator_chain_t *locator_chain,
                                       lispd_map_server_list_t *map_server,
                                       lisp_addr_t * source_addr);
extern int build_and_send_info_request(uint64_t nonce,
                                       uint16_t key_type,
                                       char *key,
                                       uint32_t ttl,
                                       uint8_t eid_mask_length,
                                       lisp_addr_t *eid_prefix,
                                       lisp_addr_t *src_addr,
                                       unsigned int src_port,
                                       lisp_addr_t *dst_addr,
                                       unsigned int dst_port);

extern lispd_pkt_info_nat_t *create_and_fill_info_nat_header(int lisp_type,
                                                             int reply,
                                                             unsigned long nonce,
                                                             uint16_t auth_data_len,
                                                             uint32_t ttl,
                                                             uint8_t eid_mask_length,
                                                             lisp_addr_t *eid_prefix,
                                                             unsigned int *header_len);

extern lisp_addr_t inet_lisp_addr(char *ipaddr, int afi);
extern int inet2lispafi(int afi);
extern char *inet_ntop_char(void *src, char *dst, int afi);
extern int get_ntop_lisp_length(int afi);
extern int get_lisp_afi_len(int afi);
extern int get_auth_data_len(int key_id);
extern int complete_auth_fields(int key_id,
                                uint16_t * key_id_pos,
                                char *key,
                                void *packet,
                                int pckt_len,
                                void *auth_data_pos);
extern int compute_sha1_hmac(char *key,
                             void *packet,
                             int pckt_len,
                             void *auth_data_pos,
                             int auth_data_len);
extern int get_source_address_and_port(struct sockaddr *from,
                                       lisp_addr_t * lisp_addr,
                                       uint16_t * port);
extern int print_address(lisp_addr_t * address);
extern int syslog_with_address_name(int log,
                                    char *text,
                                    lisp_addr_t * address);
extern int process_info_nat_msg(uint8_t * packet, int s,
                                struct sockaddr *from, int afi);

extern int extract_info_nat_header(lispd_pkt_info_nat_t *hdr,
                                   uint8_t *type,
                                   uint8_t *reply,
                                   uint64_t *nonce,
                                   uint16_t *key_id,
                                   uint16_t *auth_data_len,
                                   uint8_t **auth_data,
                                   uint32_t *ttl,
                                   uint8_t *eid_mask_len,
                                   lisp_addr_t *eid_prefix);



extern lisp_addr_t extract_lisp_address(void *ptr);

extern int send_packet(void *pkt_ptr,
                       int pkt_len,
                       lisp_addr_t * src_add,
                       unsigned int src_port,
                       lisp_addr_t * dst_addr,
                       unsigned int dst_port);

extern void free_lisp_addr_list(lisp_addr_list_t * list);

extern void NAT_info_request(void);
extern void ecm_map_register(void);


extern int build_and_send_ecm_map_register(lispd_locator_chain_t *locator_chain,
                                           int proxy_reply,
                                           lisp_addr_t *inner_addr_from,
                                           lisp_addr_t *inner_addr_dest,
                                           unsigned int inner_port_from,
                                           unsigned int inner_port_dest,
                                           lisp_addr_t *outer_addr_from,
                                           lisp_addr_t *outer_addr_dest,
                                           unsigned int outer_port_from,
                                           unsigned int outer_port_dest,
                                           int key_id,
                                           char *key);

extern lisp_addr_t *select_best_rtr_from_rtr_list(lisp_addr_list_t *rtr_rloc_list);

extern int copy_addr(void *a1, lisp_addr_t *a2, int convert);

extern lisp_addr_t *get_current_locator(void);

extern int compare_lisp_addresses(lisp_addr_t *add1, lisp_addr_t *add2);

extern int add_rtr_as_default_in_map_cache(lisp_addr_t *rtr_add);




/*
 * Editor modelines
 *
 * vi: set shiftwidth=4 tabstop=4 expandtab:
 * :indentSize=4:tabSize=4:noTabs=true:
 */
