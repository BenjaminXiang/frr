/*
 * FRR filter northbound implementation.
 *
 * Copyright (C) 2019 Network Device Education Foundation, Inc. ("NetDEF")
 *                    Rafael Zalamena
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301 USA.
 */

#include "zebra.h"

#include "lib/log.h"
#include "lib/northbound.h"

#include "lib/filter.h"

DEFINE_MTYPE_STATIC(LIB, ACCESS_LIST, "Access List")
DEFINE_MTYPE_STATIC(LIB, ACCESS_LIST_STR, "Access List Str")
DEFINE_MTYPE_STATIC(LIB, ACCESS_FILTER, "Access Filter")

/*
 * XPath: /frr-filter:lib/access-list-legacy
 */
static int lib_access_list_legacy_create(enum nb_event event,
					 const struct lyd_node *dnode,
					 union nb_resource *resource)
{
	struct access_list *acl;
	const char *acl_name;

	if (event != NB_EV_APPLY)
		return NB_OK;

	acl_name = yang_dnode_get_string(dnode, "./number");
	acl = access_list_get(AFI_IP, acl_name);
	nb_running_set_entry(dnode, acl);

	return NB_OK;
}

static int lib_access_list_legacy_destroy(enum nb_event event,
					  const struct lyd_node *dnode)
{
	struct access_master *am;
	struct access_list *acl;

	if (event != NB_EV_APPLY)
		return NB_OK;

	acl = nb_running_unset_entry(dnode);
	am = acl->master;
	if (am->delete_hook)
		am->delete_hook(acl);

	access_list_delete(acl);

	return NB_OK;
}

/*
 * XPath: /frr-filter:lib/access-list-legacy/remark
 */
static int lib_access_list_legacy_remark_modify(enum nb_event event,
						const struct lyd_node *dnode,
						union nb_resource *resource)
{
	struct access_list *acl;
	const char *remark;

	if (event != NB_EV_APPLY)
		return NB_OK;

	acl = nb_running_get_entry(dnode, NULL, true);
	if (acl->remark)
		XFREE(MTYPE_TMP, acl->remark);

	remark = yang_dnode_get_string(dnode, NULL);
	acl->remark = XSTRDUP(MTYPE_TMP, remark);

	return NB_OK;
}

static int lib_access_list_legacy_remark_destroy(enum nb_event event,
						 const struct lyd_node *dnode)
{
	struct access_list *acl;

	if (event != NB_EV_APPLY)
		return NB_OK;

	acl = nb_running_get_entry(dnode, NULL, true);
	if (acl->remark)
		XFREE(MTYPE_TMP, acl->remark);

	acl->remark = NULL;

	return NB_OK;
}

/*
 * XPath: /frr-filter:lib/access-list-legacy/entry
 */
static int lib_access_list_legacy_entry_create(enum nb_event event,
					       const struct lyd_node *dnode,
					       union nb_resource *resource)
{
	const char *filter_type;
	struct filter_cisco *fc;
	struct access_list *acl;
	struct filter *f;
	struct prefix p;
	uint32_t aclno;

	/* TODO: validate `filter_lookup_cisco` returns NULL. */

	if (event != NB_EV_APPLY)
		return NB_OK;

	filter_type = yang_dnode_get_string(dnode, "./action");
	aclno = yang_dnode_get_uint32(dnode, "../number");

	f = XCALLOC(MTYPE_ACCESS_FILTER, sizeof(*f));
	f->cisco = 1;
	f->seq = yang_dnode_get_uint32(dnode, "./sequence");
	if (strcmp(filter_type, "permit") == 0)
		f->type = FILTER_PERMIT;
	else
		f->type = FILTER_DENY;

	fc = &f->u.cfilter;
	if ((aclno >= 1 && aclno <= 99) || (aclno >= 1300 && aclno <= 1999))
		fc->extended = 0;
	else
		fc->extended = 1;

	if (yang_dnode_exists(dnode, "./network")) {
		yang_dnode_get_ipv4p(&p, dnode, "./network");
		fc->addr.s_addr =
			ipv4_network_addr(p.u.prefix4.s_addr, p.prefixlen);
		masklen2ip(p.prefixlen, &fc->addr_mask);
	} else if (yang_dnode_exists(dnode, "./host")) {
		yang_dnode_get_ipv4(&fc->addr, dnode, "./host");
		fc->addr_mask.s_addr = INADDR_ANY;
	} else {
		fc->addr.s_addr = INADDR_ANY;
		fc->addr_mask.s_addr = INADDR_NONE;
	}

	if (yang_dnode_exists(dnode, "./destination-network")) {
		yang_dnode_get_ipv4p(&p, dnode, "./destination-network");
		fc->mask.s_addr =
			ipv4_network_addr(p.u.prefix4.s_addr, p.prefixlen);
		masklen2ip(p.prefixlen, &fc->mask_mask);
	} else if (yang_dnode_exists(dnode, "./destination-host")) {
		yang_dnode_get_ipv4(&fc->mask, dnode, "./destination-host");
		fc->mask_mask.s_addr = INADDR_ANY;
	} else {
		fc->mask.s_addr = INADDR_ANY;
		fc->mask_mask.s_addr = INADDR_NONE;
	}

	acl = nb_running_get_entry(dnode, NULL, true);
	access_list_filter_add(acl, f);
	nb_running_set_entry(dnode, f);

	return NB_OK;
}

static int lib_access_list_legacy_entry_destroy(enum nb_event event,
						const struct lyd_node *dnode)
{
	struct access_list *acl;
	struct filter *f;

	if (event != NB_EV_APPLY)
		return NB_OK;

	f = nb_running_unset_entry(dnode);
	acl = f->acl;
	access_list_filter_delete(acl, f);

	return NB_OK;
}

/*
 * XPath: /frr-filter:lib/access-list-legacy/entry/action
 */
static int
lib_access_list_legacy_entry_action_modify(enum nb_event event,
					   const struct lyd_node *dnode,
					   union nb_resource *resource)
{
	const char *filter_type;
	struct filter *f;

	if (event != NB_EV_APPLY)
		return NB_OK;

	f = nb_running_unset_entry(dnode);
	filter_type = yang_dnode_get_string(dnode, "./action");
	if (strcmp(filter_type, "permit") == 0)
		f->type = FILTER_PERMIT;
	else
		f->type = FILTER_DENY;

	return NB_OK;
}

/*
 * XPath: /frr-filter:lib/access-list-legacy/entry/host
 */
static int
lib_access_list_legacy_entry_host_modify(enum nb_event event,
					 const struct lyd_node *dnode,
					 union nb_resource *resource)
{
	struct filter_cisco *fc;
	struct filter *f;

	if (event != NB_EV_APPLY)
		return NB_OK;

	f = nb_running_unset_entry(dnode);
	fc = &f->u.cfilter;
	yang_dnode_get_ipv4(&fc->addr, dnode, "./host");
	fc->addr_mask.s_addr = INADDR_ANY;

	return NB_OK;
}

static int
lib_access_list_legacy_entry_host_destroy(enum nb_event event,
					  const struct lyd_node *dnode)
{
	struct filter_cisco *fc;
	struct filter *f;

	if (event != NB_EV_APPLY)
		return NB_OK;

	f = nb_running_unset_entry(dnode);
	fc = &f->u.cfilter;
	fc->addr.s_addr = INADDR_ANY;
	fc->addr_mask.s_addr = INADDR_NONE;

	return NB_OK;
}

/*
 * XPath: /frr-filter:lib/access-list-legacy/entry/network
 */
static int
lib_access_list_legacy_entry_network_modify(enum nb_event event,
					    const struct lyd_node *dnode,
					    union nb_resource *resource)
{
	struct filter_cisco *fc;
	struct filter *f;
	struct prefix p;

	if (event != NB_EV_APPLY)
		return NB_OK;

	f = nb_running_unset_entry(dnode);
	fc = &f->u.cfilter;
	yang_dnode_get_ipv4p(&p, dnode, "./network");
	fc->addr.s_addr =
		ipv4_network_addr(p.u.prefix4.s_addr, p.prefixlen);
	masklen2ip(p.prefixlen, &fc->addr_mask);

	return NB_OK;
}

static int
lib_access_list_legacy_entry_network_destroy(enum nb_event event,
					     const struct lyd_node *dnode)
{
	struct filter_cisco *fc;
	struct filter *f;

	if (event != NB_EV_APPLY)
		return NB_OK;

	f = nb_running_unset_entry(dnode);
	fc = &f->u.cfilter;
	fc->addr.s_addr = INADDR_ANY;
	fc->addr_mask.s_addr = INADDR_NONE;

	return NB_OK;
}

/*
 * XPath: /frr-filter:lib/access-list-legacy/entry/any
 */
static int lib_access_list_legacy_entry_any_create(enum nb_event event,
						   const struct lyd_node *dnode,
						   union nb_resource *resource)
{
	struct filter_cisco *fc;
	struct filter *f;

	if (event != NB_EV_APPLY)
		return NB_OK;

	f = nb_running_unset_entry(dnode);
	fc = &f->u.cfilter;
	fc->addr.s_addr = INADDR_ANY;
	fc->addr_mask.s_addr = INADDR_NONE;

	return NB_OK;
}

static int
lib_access_list_legacy_entry_any_destroy(enum nb_event event,
					 const struct lyd_node *dnode)
{
	struct filter_cisco *fc;
	struct filter *f;

	if (event != NB_EV_APPLY)
		return NB_OK;

	f = nb_running_unset_entry(dnode);
	fc = &f->u.cfilter;
	fc->addr.s_addr = INADDR_ANY;
	fc->addr_mask.s_addr = INADDR_NONE;

	return NB_OK;
}

/*
 * XPath: /frr-filter:lib/access-list-legacy/entry/destination-host
 */
static int lib_access_list_legacy_entry_destination_host_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	struct filter_cisco *fc;
	struct filter *f;

	if (event != NB_EV_APPLY)
		return NB_OK;

	f = nb_running_unset_entry(dnode);
	fc = &f->u.cfilter;
	yang_dnode_get_ipv4(&fc->mask, dnode, "./destination-host");
	fc->mask_mask.s_addr = INADDR_ANY;

	return NB_OK;
}

static int lib_access_list_legacy_entry_destination_host_destroy(
	enum nb_event event, const struct lyd_node *dnode)
{
	struct filter_cisco *fc;
	struct filter *f;

	if (event != NB_EV_APPLY)
		return NB_OK;

	f = nb_running_unset_entry(dnode);
	fc = &f->u.cfilter;
	fc->mask.s_addr = INADDR_ANY;
	fc->mask_mask.s_addr = INADDR_NONE;

	return NB_OK;
}

/*
 * XPath: /frr-filter:lib/access-list-legacy/entry/destination-network
 */
static int lib_access_list_legacy_entry_destination_network_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
}

static int lib_access_list_legacy_entry_destination_network_destroy(
	enum nb_event event, const struct lyd_node *dnode)
{
}

/*
 * XPath: /frr-filter:lib/access-list-legacy/entry/destination-any
 */
static int lib_access_list_legacy_entry_destination_any_create(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
}

static int lib_access_list_legacy_entry_destination_any_destroy(
	enum nb_event event, const struct lyd_node *dnode)
{
}

/*
 * XPath: /frr-filter:lib/access-list
 */
static int lib_access_list_create(enum nb_event event,
				  const struct lyd_node *dnode,
				  union nb_resource *resource)
{
	switch (event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

static int lib_access_list_destroy(enum nb_event event,
				   const struct lyd_node *dnode)
{
	switch (event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-filter:lib/access-list/entry
 */
static int lib_access_list_entry_create(enum nb_event event,
					const struct lyd_node *dnode,
					union nb_resource *resource)
{
	switch (event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

static int lib_access_list_entry_destroy(enum nb_event event,
					 const struct lyd_node *dnode)
{
	switch (event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-filter:lib/access-list/entry/action
 */
static int lib_access_list_entry_action_modify(enum nb_event event,
					       const struct lyd_node *dnode,
					       union nb_resource *resource)
{
	switch (event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-filter:lib/access-list/entry/remark
 */
static int lib_access_list_entry_remark_modify(enum nb_event event,
					       const struct lyd_node *dnode,
					       union nb_resource *resource)
{
	switch (event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

static int lib_access_list_entry_remark_destroy(enum nb_event event,
						const struct lyd_node *dnode)
{
	switch (event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-filter:lib/access-list/entry/ipv4-prefix
 */
static int
lib_access_list_entry_ipv4_prefix_modify(enum nb_event event,
					 const struct lyd_node *dnode,
					 union nb_resource *resource)
{
	switch (event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

static int
lib_access_list_entry_ipv4_prefix_destroy(enum nb_event event,
					  const struct lyd_node *dnode)
{
	switch (event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-filter:lib/access-list/entry/ipv4-exact-match
 */
static int
lib_access_list_entry_ipv4_exact_match_modify(enum nb_event event,
					      const struct lyd_node *dnode,
					      union nb_resource *resource)
{
	switch (event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

static int
lib_access_list_entry_ipv4_exact_match_destroy(enum nb_event event,
					       const struct lyd_node *dnode)
{
	switch (event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-filter:lib/access-list/entry/ipv6-prefix
 */
static int
lib_access_list_entry_ipv6_prefix_modify(enum nb_event event,
					 const struct lyd_node *dnode,
					 union nb_resource *resource)
{
	switch (event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

static int
lib_access_list_entry_ipv6_prefix_destroy(enum nb_event event,
					  const struct lyd_node *dnode)
{
	switch (event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-filter:lib/access-list/entry/ipv6-exact-match
 */
static int
lib_access_list_entry_ipv6_exact_match_modify(enum nb_event event,
					      const struct lyd_node *dnode,
					      union nb_resource *resource)
{
	switch (event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

static int
lib_access_list_entry_ipv6_exact_match_destroy(enum nb_event event,
					       const struct lyd_node *dnode)
{
	switch (event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-filter:lib/access-list/entry/mac
 */
static int lib_access_list_entry_mac_modify(enum nb_event event,
					    const struct lyd_node *dnode,
					    union nb_resource *resource)
{
	switch (event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

static int lib_access_list_entry_mac_destroy(enum nb_event event,
					     const struct lyd_node *dnode)
{
	switch (event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-filter:lib/access-list/entry/any
 */
static int lib_access_list_entry_any_create(enum nb_event event,
					    const struct lyd_node *dnode,
					    union nb_resource *resource)
{
	switch (event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

static int lib_access_list_entry_any_destroy(enum nb_event event,
					     const struct lyd_node *dnode)
{
	switch (event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-filter:lib/prefix-list
 */
static int lib_prefix_list_create(enum nb_event event,
				  const struct lyd_node *dnode,
				  union nb_resource *resource)
{
	switch (event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

static int lib_prefix_list_destroy(enum nb_event event,
				   const struct lyd_node *dnode)
{
	switch (event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-filter:lib/prefix-list/entry
 */
static int lib_prefix_list_entry_create(enum nb_event event,
					const struct lyd_node *dnode,
					union nb_resource *resource)
{
	switch (event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

static int lib_prefix_list_entry_destroy(enum nb_event event,
					 const struct lyd_node *dnode)
{
	switch (event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-filter:lib/prefix-list/entry/action
 */
static int lib_prefix_list_entry_action_modify(enum nb_event event,
					       const struct lyd_node *dnode,
					       union nb_resource *resource)
{
	switch (event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-filter:lib/prefix-list/entry/description
 */
static int
lib_prefix_list_entry_description_modify(enum nb_event event,
					 const struct lyd_node *dnode,
					 union nb_resource *resource)
{
	switch (event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

static int
lib_prefix_list_entry_description_destroy(enum nb_event event,
					  const struct lyd_node *dnode)
{
	switch (event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-filter:lib/prefix-list/entry/ipv4-prefix
 */
static int
lib_prefix_list_entry_ipv4_prefix_modify(enum nb_event event,
					 const struct lyd_node *dnode,
					 union nb_resource *resource)
{
	switch (event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

static int
lib_prefix_list_entry_ipv4_prefix_destroy(enum nb_event event,
					  const struct lyd_node *dnode)
{
	switch (event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-filter:lib/prefix-list/entry/ipv4-prefix-length-greater-or-equal
 */
static int lib_prefix_list_entry_ipv4_prefix_length_greater_or_equal_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	switch (event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

static int lib_prefix_list_entry_ipv4_prefix_length_greater_or_equal_destroy(
	enum nb_event event, const struct lyd_node *dnode)
{
	switch (event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-filter:lib/prefix-list/entry/ipv4-prefix-length-lesser-or-equal
 */
static int lib_prefix_list_entry_ipv4_prefix_length_lesser_or_equal_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	switch (event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

static int lib_prefix_list_entry_ipv4_prefix_length_lesser_or_equal_destroy(
	enum nb_event event, const struct lyd_node *dnode)
{
	switch (event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-filter:lib/prefix-list/entry/ipv6-prefix
 */
static int
lib_prefix_list_entry_ipv6_prefix_modify(enum nb_event event,
					 const struct lyd_node *dnode,
					 union nb_resource *resource)
{
	switch (event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

static int
lib_prefix_list_entry_ipv6_prefix_destroy(enum nb_event event,
					  const struct lyd_node *dnode)
{
	switch (event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-filter:lib/prefix-list/entry/ipv6-prefix-length-greater-or-equal
 */
static int lib_prefix_list_entry_ipv6_prefix_length_greater_or_equal_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	switch (event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

static int lib_prefix_list_entry_ipv6_prefix_length_greater_or_equal_destroy(
	enum nb_event event, const struct lyd_node *dnode)
{
	switch (event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-filter:lib/prefix-list/entry/ipv6-prefix-length-lesser-or-equal
 */
static int lib_prefix_list_entry_ipv6_prefix_length_lesser_or_equal_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	switch (event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

static int lib_prefix_list_entry_ipv6_prefix_length_lesser_or_equal_destroy(
	enum nb_event event, const struct lyd_node *dnode)
{
	switch (event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-filter:lib/prefix-list/entry/any
 */
static int lib_prefix_list_entry_any_create(enum nb_event event,
					    const struct lyd_node *dnode,
					    union nb_resource *resource)
{
	switch (event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

static int lib_prefix_list_entry_any_destroy(enum nb_event event,
					     const struct lyd_node *dnode)
{
	switch (event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/* clang-format off */
const struct frr_yang_module_info frr_filter_info = {
	.name = "frr-filter",
	.nodes = {
		{
			.xpath = "/frr-filter:lib/access-list-legacy",
			.cbs = {
				.create = lib_access_list_legacy_create,
				.destroy = lib_access_list_legacy_destroy,
			}
		},
		{
			.xpath = "/frr-filter:lib/access-list-legacy/remark",
			.cbs = {
				.modify = lib_access_list_legacy_remark_modify,
				.destroy = lib_access_list_legacy_remark_destroy,
			}
		},
		{
			.xpath = "/frr-filter:lib/access-list-legacy/entry",
			.cbs = {
				.create = lib_access_list_legacy_entry_create,
				.destroy = lib_access_list_legacy_entry_destroy,
			}
		},
		{
			.xpath = "/frr-filter:lib/access-list-legacy/entry/action",
			.cbs = {
				.modify = lib_access_list_legacy_entry_action_modify,
			}
		},
		{
			.xpath = "/frr-filter:lib/access-list-legacy/entry/host",
			.cbs = {
				.modify = lib_access_list_legacy_entry_host_modify,
				.destroy = lib_access_list_legacy_entry_host_destroy,
			}
		},
		{
			.xpath = "/frr-filter:lib/access-list-legacy/entry/network",
			.cbs = {
				.modify = lib_access_list_legacy_entry_network_modify,
				.destroy = lib_access_list_legacy_entry_network_destroy,
			}
		},
		{
			.xpath = "/frr-filter:lib/access-list-legacy/entry/any",
			.cbs = {
				.create = lib_access_list_legacy_entry_any_create,
				.destroy = lib_access_list_legacy_entry_any_destroy,
			}
		},
		{
			.xpath = "/frr-filter:lib/access-list-legacy/entry/destination-host",
			.cbs = {
				.modify = lib_access_list_legacy_entry_destination_host_modify,
				.destroy = lib_access_list_legacy_entry_destination_host_destroy,
			}
		},
		{
			.xpath = "/frr-filter:lib/access-list-legacy/entry/destination-network",
			.cbs = {
				.modify = lib_access_list_legacy_entry_destination_network_modify,
				.destroy = lib_access_list_legacy_entry_destination_network_destroy,
			}
		},
		{
			.xpath = "/frr-filter:lib/access-list-legacy/entry/destination-any",
			.cbs = {
				.create = lib_access_list_legacy_entry_destination_any_create,
				.destroy = lib_access_list_legacy_entry_destination_any_destroy,
			}
		},
		{
			.xpath = "/frr-filter:lib/access-list",
			.cbs = {
				.create = lib_access_list_create,
				.destroy = lib_access_list_destroy,
			}
		},
		{
			.xpath = "/frr-filter:lib/access-list/entry",
			.cbs = {
				.create = lib_access_list_entry_create,
				.destroy = lib_access_list_entry_destroy,
			}
		},
		{
			.xpath = "/frr-filter:lib/access-list/entry/action",
			.cbs = {
				.modify = lib_access_list_entry_action_modify,
			}
		},
		{
			.xpath = "/frr-filter:lib/access-list/entry/remark",
			.cbs = {
				.modify = lib_access_list_entry_remark_modify,
				.destroy = lib_access_list_entry_remark_destroy,
			}
		},
		{
			.xpath = "/frr-filter:lib/access-list/entry/ipv4-prefix",
			.cbs = {
				.modify = lib_access_list_entry_ipv4_prefix_modify,
				.destroy = lib_access_list_entry_ipv4_prefix_destroy,
			}
		},
		{
			.xpath = "/frr-filter:lib/access-list/entry/ipv4-exact-match",
			.cbs = {
				.modify = lib_access_list_entry_ipv4_exact_match_modify,
				.destroy = lib_access_list_entry_ipv4_exact_match_destroy,
			}
		},
		{
			.xpath = "/frr-filter:lib/access-list/entry/ipv6-prefix",
			.cbs = {
				.modify = lib_access_list_entry_ipv6_prefix_modify,
				.destroy = lib_access_list_entry_ipv6_prefix_destroy,
			}
		},
		{
			.xpath = "/frr-filter:lib/access-list/entry/ipv6-exact-match",
			.cbs = {
				.modify = lib_access_list_entry_ipv6_exact_match_modify,
				.destroy = lib_access_list_entry_ipv6_exact_match_destroy,
			}
		},
		{
			.xpath = "/frr-filter:lib/access-list/entry/mac",
			.cbs = {
				.modify = lib_access_list_entry_mac_modify,
				.destroy = lib_access_list_entry_mac_destroy,
			}
		},
		{
			.xpath = "/frr-filter:lib/access-list/entry/any",
			.cbs = {
				.create = lib_access_list_entry_any_create,
				.destroy = lib_access_list_entry_any_destroy,
			}
		},
		{
			.xpath = "/frr-filter:lib/prefix-list",
			.cbs = {
				.create = lib_prefix_list_create,
				.destroy = lib_prefix_list_destroy,
			}
		},
		{
			.xpath = "/frr-filter:lib/prefix-list/entry",
			.cbs = {
				.create = lib_prefix_list_entry_create,
				.destroy = lib_prefix_list_entry_destroy,
			}
		},
		{
			.xpath = "/frr-filter:lib/prefix-list/entry/action",
			.cbs = {
				.modify = lib_prefix_list_entry_action_modify,
			}
		},
		{
			.xpath = "/frr-filter:lib/prefix-list/entry/description",
			.cbs = {
				.modify = lib_prefix_list_entry_description_modify,
				.destroy = lib_prefix_list_entry_description_destroy,
			}
		},
		{
			.xpath = "/frr-filter:lib/prefix-list/entry/ipv4-prefix",
			.cbs = {
				.modify = lib_prefix_list_entry_ipv4_prefix_modify,
				.destroy = lib_prefix_list_entry_ipv4_prefix_destroy,
			}
		},
		{
			.xpath = "/frr-filter:lib/prefix-list/entry/ipv4-prefix-length-greater-or-equal",
			.cbs = {
				.modify = lib_prefix_list_entry_ipv4_prefix_length_greater_or_equal_modify,
				.destroy = lib_prefix_list_entry_ipv4_prefix_length_greater_or_equal_destroy,
			}
		},
		{
			.xpath = "/frr-filter:lib/prefix-list/entry/ipv4-prefix-length-lesser-or-equal",
			.cbs = {
				.modify = lib_prefix_list_entry_ipv4_prefix_length_lesser_or_equal_modify,
				.destroy = lib_prefix_list_entry_ipv4_prefix_length_lesser_or_equal_destroy,
			}
		},
		{
			.xpath = "/frr-filter:lib/prefix-list/entry/ipv6-prefix",
			.cbs = {
				.modify = lib_prefix_list_entry_ipv6_prefix_modify,
				.destroy = lib_prefix_list_entry_ipv6_prefix_destroy,
			}
		},
		{
			.xpath = "/frr-filter:lib/prefix-list/entry/ipv6-prefix-length-greater-or-equal",
			.cbs = {
				.modify = lib_prefix_list_entry_ipv6_prefix_length_greater_or_equal_modify,
				.destroy = lib_prefix_list_entry_ipv6_prefix_length_greater_or_equal_destroy,
			}
		},
		{
			.xpath = "/frr-filter:lib/prefix-list/entry/ipv6-prefix-length-lesser-or-equal",
			.cbs = {
				.modify = lib_prefix_list_entry_ipv6_prefix_length_lesser_or_equal_modify,
				.destroy = lib_prefix_list_entry_ipv6_prefix_length_lesser_or_equal_destroy,
			}
		},
		{
			.xpath = "/frr-filter:lib/prefix-list/entry/any",
			.cbs = {
				.create = lib_prefix_list_entry_any_create,
				.destroy = lib_prefix_list_entry_any_destroy,
			}
		},
		{
			.xpath = NULL,
		},
	}
};
