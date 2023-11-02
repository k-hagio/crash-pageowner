/* page_owner.c - crash extension module for page_owner information
 *
 * Copyright (C) 2023 NEC Corporation
 *
 * Author: Kazuhito Hagio <k-hagio-ab@nec.com>
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
 */

#include "defs.h"

#define PO_OFFSET_INIT(X,Y,Z)	(po_offset_table.X = MEMBER_OFFSET(Y, Z))
#define PO_SIZE_INIT(X,Y)	(po_size_table.X = STRUCT_SIZE(Y))
#define PO_VALID_MEMBER(X)	(po_offset_table.X >= 0)
#define PO_VALID_STRUCT(X)	(po_size_table.X >= 0)
#define PO_OFFSET(X)		(OFFSET_verify(po_offset_table.X, (char *)__FUNCTION__, __FILE__, __LINE__, #X))
#define PO_SIZE(X)		(SIZE_verify(po_size_table.X, (char *)__FUNCTION__, __FILE__, __LINE__, #X))
#define INVALID_VALUE		(-1)

static void page_owner_init(void);
static void page_owner_fini(void);
static void cmd_owner(void);

extern int section_has_mem_map(ulong);

struct po_offset_table {
	long mem_section_page_ext;
	long page_ext_operations_offset;
	long page_ext_flags;

	long page_owner_order;
	long page_owner_last_migrate_reason;
	long page_owner_gfp_mask;
	long page_owner_handle;
	long page_owner_free_handle;
	long page_owner_ts_nsec;
	long page_owner_free_ts_nsec;
	long page_owner_comm;
	long page_owner_pid;
	long page_owner_tgid;

	long stack_record_size;
	long stack_record_entries;
} po_offset_table = { INVALID_OFFSET };

static struct po_size_table {
	long page_owner;
	long page_ext;
} po_size_table = { INVALID_OFFSET };

/* from mm/page_ext.c */
#define PAGE_EXT_INVALID	(0x1)

/* from lib/stackdepot.c */
#define DEPOT_STACK_ALIGN	4

union handle_parts {
	uint handle;
	struct {
		uint pool_index	: 21;
		uint offset	: 10;
		uint valid	: 1;
	} v1;
	struct {
		uint pool_index : 16;
		uint offset	: 10;
		uint valid	: 1;
		uint extra	: 5;
	} v2;
};

/* for cmd_flags */
#define LIST_PAGE_OWNERS	(0x0001)
#define LIST_PAGE_OWNERS_ALL	(0x0002)

/* for env_flags */
#define PAGE_OWNER_INITED	(0x0001)
#define HANDLE_PARTS_EXTRA	(0x0002)

/* Global variables */
static int cmd_flags;
static int env_flags;

static long page_ext_size		= INVALID_VALUE;
static long page_owner_ops_offset	= INVALID_VALUE;
static long PAGE_EXT_OWNER		= INVALID_VALUE;
static long PAGE_EXT_OWNER_ALLOCATED	= INVALID_VALUE;
static ulong stack_pools;
static ulong max_pfn;

static void
print_stack_depot(uint handle)
{
	union handle_parts parts = { .handle = handle };
	ulong pool, stack_record, entries;
	uint size, pool_index, offset;
	struct load_module *lm;
	char buf[BUFSIZE];
	ulong *stack;
	int i;

	if (env_flags & HANDLE_PARTS_EXTRA) {
		pool_index = parts.v2.pool_index;
		offset = parts.v2.offset << DEPOT_STACK_ALIGN;
	} else {
		pool_index = parts.v1.pool_index;
		offset = parts.v1.offset << DEPOT_STACK_ALIGN;
	}

	if (CRASHDEBUG(1))
		fprintf(fp, "handle %x pool_index %u offset %u\n", handle, pool_index, offset);

	if (!stack_pools)
		return;

	if (!readmem(stack_pools + sizeof(ulong) * pool_index, KVADDR, &pool,
			sizeof(ulong), "stack_pools[pool_index]", RETURN_ON_ERROR|QUIET)) {
		error(WARNING, "cannot read stack_pools[%u]\n", pool_index);
		return;
	}

	if (!pool) {
		error(WARNING, "stack_pools[%u] is NULL", pool_index);
		return;
	}

	stack_record = pool + offset;
	entries = stack_record + PO_OFFSET(stack_record_entries);

	if (!readmem(stack_record + PO_OFFSET(stack_record_size), KVADDR, &size,
			sizeof(uint), "stack_record.size", RETURN_ON_ERROR|QUIET)) {
		error(WARNING, "cannot read stack_record.size\n");
		return;
	}

	if (CRASHDEBUG(1))
		fprintf(fp, "stack_record %lx size %u entries %lx\n", stack_record, size, entries);

	if (!size) {
		error(WARNING, "stack_record.size is zero");
		return;
	}

	stack = (ulong *)GETBUF(sizeof(ulong) * size);
	readmem(entries, KVADDR, stack, sizeof(ulong) * size, "stack_record.entries[]", FAULT_ON_ERROR);

	for (i = 0; i < size; i++) {
		if (in_ksymbol_range(stack[i]) && strlen(value_to_symstr(stack[i], buf, 16))) {
			if (CRASHDEBUG(1))
				sprintf(buf + strlen(buf), " at %016lx", stack[i]);

			if (module_symbol(stack[i], NULL, &lm, NULL, 0))
				sprintf(buf + strlen(buf), " [%s]", lm->mod_name);

			fprintf(fp, "  %s\n", buf);
		} else
			fprintf(fp, "  %016lx\n", stack[i]);
	}

	FREEBUF(stack);
}

static void
print_page_owner(ulong page_owner, int show_all, int alloc)
{
	char buf[BUFSIZE], *bufp, *po;
	uint handle, free_handle;

	po = GETBUF(PO_SIZE(page_owner));
	readmem(page_owner, KVADDR, po, PO_SIZE(page_owner), "page_owner", FAULT_ON_ERROR);

	BZERO(buf, BUFSIZE);
	bufp = buf;

	bufp += sprintf(bufp, "Page allocated via order %u", USHORT(po + PO_OFFSET(page_owner_order)));
	bufp += sprintf(bufp, ", mask 0x%x", UINT(po + PO_OFFSET(page_owner_gfp_mask)));

	if (PO_VALID_MEMBER(page_owner_pid))
		bufp += sprintf(bufp, ", pid %d", INT(po + PO_OFFSET(page_owner_pid)));

	if (PO_VALID_MEMBER(page_owner_tgid))
		bufp += sprintf(bufp, ", tgid %d", INT(po + PO_OFFSET(page_owner_tgid)));

	if (PO_VALID_MEMBER(page_owner_comm))
		bufp += sprintf(bufp, " (%s)", po + PO_OFFSET(page_owner_comm));

	if (PO_VALID_MEMBER(page_owner_ts_nsec))
		bufp += sprintf(bufp, ", ts %llu ns", ULONGLONG(po + PO_OFFSET(page_owner_ts_nsec)));

	if (PO_VALID_MEMBER(page_owner_free_ts_nsec))
		bufp += sprintf(bufp, ", free_ts %llu ns", ULONGLONG(po + PO_OFFSET(page_owner_free_ts_nsec)));

	fprintf(fp, "%s\n", buf);

	handle = UINT(po + PO_OFFSET(page_owner_handle));
	if (handle) {
		/* No PAGE_EXT_OWNER_ALLOCATED means a valid page_owner is "alloc" state. */
		if (alloc)
			fprintf(fp, "[alloc]\n");
		else
			fprintf(fp, "alloc\n");
		print_stack_depot(handle);
	}

	if (show_all && PO_VALID_MEMBER(page_owner_free_handle)) {
		free_handle = UINT(po + PO_OFFSET(page_owner_free_handle));
		if (free_handle) {
			if (alloc)
				fprintf(fp, "free\n");
			else
				fprintf(fp, "[free]\n");
			print_stack_depot(free_handle);
		}
	}

	FREEBUF(po);
}

static ulong
pfn_to_page_owner(ulong pfn, int show_all, int *allocated)
{
	ulong nr, mem_section, page_ext, entry, flags, page_owner;

	/* lookup_page_ext() */
	nr = pfn_to_section_nr(pfn);
	mem_section = valid_section_nr(nr);

	if (!mem_section) {
		error(WARNING, "cannot get valid mem_section for pfn: %lx\n", pfn);
		return 0;
	}

	if (!readmem(mem_section + PO_OFFSET(mem_section_page_ext), KVADDR, &page_ext,
			sizeof(ulong), "mem_section.page_ext", RETURN_ON_ERROR))
		return 0;

	/* page_ext_invalid() */
	if (!page_ext || ((page_ext & PAGE_EXT_INVALID) == PAGE_EXT_INVALID)) {
		error(WARNING, "mem_section %lx has invalid page_ext: %lx\n", mem_section, page_ext);
		return 0;
	}

	/* get_entry() */
	entry = page_ext + (page_ext_size * pfn);

	/* get_page_owner() */
	page_owner = entry + page_owner_ops_offset;

	if (!readmem(entry + PO_OFFSET(page_ext_flags), KVADDR, &flags, sizeof(ulong),
			"page_ext.flags", RETURN_ON_ERROR))
		return 0;

	if (CRASHDEBUG(1))
		fprintf(fp, "pfn %lu sec_nr %lu mem_sec %lx page_ext %lx entry %lx flags %lx page_owner %lx\n",
			pfn, nr, mem_section, page_ext, entry, flags, page_owner);

	if (!(flags & (1 << PAGE_EXT_OWNER)))
		return 0;

	if (PAGE_EXT_OWNER_ALLOCATED != INVALID_VALUE) {
		int alloc = flags & (1 << PAGE_EXT_OWNER_ALLOCATED);

		if (allocated)
			*allocated = alloc;

		if (!show_all && !alloc)
			return 0;
	}

	return page_owner;
}

static void
dump_page_owner(ulong vaddr)
{
	physaddr_t paddr;
	ulong pfn, page, page_owner;
	int alloc;

	if (!kvtop(NULL, vaddr, &paddr, 0)) {
		error(WARNING, "cannot make virtual-to-physical translation: %lx\n", vaddr);
		return;
	}

	pfn = BTOP(paddr);
	alloc = INVALID_VALUE;
	page_owner = pfn_to_page_owner(pfn, 1, &alloc);

	if (!page_owner) {
		error(WARNING, "cannot get page_owner for vaddr: %lx\n", vaddr);
		return;
	}

	if (!phys_to_page(paddr, &page))
		error(INFO, "cannot find struct page for physical address: %lx\n", paddr);

	fprintf(fp, "PFN %ld(0x%lx) paddr %lx vaddr %lx page %lx page_owner %lx\n",
		pfn, pfn, paddr, vaddr, page, page_owner);

	print_page_owner(page_owner, 1, alloc);
}

#define IS_ALIGNED(x, a)	(((x) & ((typeof(x))(a) - 1)) == 0)

static void
list_page_owner(int show_all)
{
	ulong pfn, page_owner;
	char *po;
	ushort order;
	uint handle;
	int alloc;

	po = GETBUF(PO_SIZE(page_owner));

	for (pfn = 0 ; pfn < max_pfn; pfn++) {

		/* Find a valid PFN */
		while (!section_has_mem_map(valid_section_nr(pfn_to_section_nr(pfn))))
			pfn++;

		alloc = INVALID_VALUE;
		page_owner = pfn_to_page_owner(pfn, show_all, &alloc);
		if (!page_owner)
			continue;

		readmem(page_owner, KVADDR, po, PO_SIZE(page_owner), "page_owner", FAULT_ON_ERROR);

		/* Don't print "tail" pages of high-order allocations */
		order = USHORT(po + PO_OFFSET(page_owner_order));
		if (!IS_ALIGNED(pfn, 1 << order))
			continue;

		handle = UINT(po + PO_OFFSET(page_owner_handle));
		if (!handle)
			continue;

		fprintf(fp, "PFN %ld(0x%lx) paddr %lx page_owner %lx\n",
			pfn, pfn, (ulong)PTOB(pfn), page_owner);
		print_page_owner(page_owner, show_all, alloc);
		fprintf(fp, "\n");
	}

	return;
}

static void
cmd_owner(void)
{
	int c;
	char *arg;
	ulong vaddr;

	if (!(env_flags & PAGE_OWNER_INITED))
		error(FATAL, "page_owner is disabled\n");

	cmd_flags = 0;

	while ((c = getopt(argcnt, args, "lL")) != EOF) {
		switch(c) {
		case 'L':
			if (!PO_VALID_MEMBER(page_owner_free_handle)) {
				error(INFO, "this kernel does not have page owner information for freed pages.\n");
				return;
			}
			cmd_flags |= LIST_PAGE_OWNERS_ALL;
		case 'l':
			cmd_flags |= LIST_PAGE_OWNERS;
			break;
		default:
			argerrs++;
			break;
		}
	}

	if (argerrs)
		cmd_usage(pc->curcmd, SYNOPSIS);

	if (cmd_flags & LIST_PAGE_OWNERS) {
		list_page_owner(cmd_flags & LIST_PAGE_OWNERS_ALL);
		return;
	}

	if (!args[optind])
		cmd_usage(pc->curcmd, SYNOPSIS);

	while ((arg = args[optind++])) {
		vaddr = htol(arg, RETURN_ON_ERROR|QUIET, NULL);

		if (vaddr == BADADDR) {
			error(INFO, "invalid value: %s\n", arg);
			continue;
		}

		dump_page_owner(vaddr);
		fprintf(fp, "\n");
	}
}

static char *help_owner[] = {
"owner",				/* command name */
"dump page owner information",		/* short description */
"address\n"
"  owner -l|-L",			/* argument synopsis, or " " if none */
"  This command dumps the page owner information of a specified address.",
"",
"       -l  list page owner information for allocated pages.",
"       -L  list page owner information for allocated and freed pages.",
"           (this option is available only on Linux 5.4, RHEL8.5 and later.)",
"  address  a kernel virtual address.",
"",
"EXAMPLES",
"  Dump the page owner information of a specified page address:",
"",
"    crash> owner ffff892b73200000",
"    PFN 471552(0x73200) paddr 73200000 vaddr ffff892b73200000 page fffff4bec1cc8000 page_owner ffff892c024c8008",
"    Page allocated via order 9, mask 0x346cca, pid 46265, tgid 46265 (bash), ts 88704902141361 ns, free_ts 23514284799158 ns",
"    [alloc]",
"      get_page_from_freelist+0x33e",
"      __alloc_pages+0xe6",
"      alloc_buddy_huge_page+0x43",
"      alloc_fresh_huge_page+0x16f",
"      alloc_pool_huge_page+0x76",
"      set_max_huge_pages+0x198",
"      __nr_hugepages_store_common+0x48",
"      hugetlb_sysctl_handler_common+0xdf",
"      proc_sys_call_handler+0x162",
"      new_sync_write+0xfc",
"      vfs_write+0x1ef",
"      ksys_write+0x5f",
"      do_syscall_64+0x59",
"      entry_SYSCALL_64_after_hwframe+0x63",
"    free",
"      free_pcp_prepare+0x142",
"      free_unref_page_list+0x92",
"      release_pages+0x16d",
"      tlb_flush_mmu+0x4b",
"      zap_pte_range+0x808",
"      zap_pmd_range+0x141",
"      unmap_page_range+0x2c6",
"      unmap_vmas+0x78",
"      exit_mmap+0xa5",
"      mmput+0x5a",
"      exit_mm+0xb8",
"      do_exit+0x1f3",
"      do_group_exit+0x2d",
"      __x64_sys_exit_group+0x14",
"      do_syscall_64+0x59",
"      entry_SYSCALL_64_after_hwframe+0x63",
"",
"  List the page owner information of allocated pages:",
"",
"    crash> owner -l",
"    PFN 256(0x100) paddr 100000 page_owner ffff892c00804008",
"    Page allocated via order 7, mask 0xcc1, pid 1, tgid 1 (swapper/0), ts 129969032 ns, free_ts 0 ns",
"    [alloc]",
"      get_page_from_freelist+0x33e",
"      __alloc_pages+0xe6",
"      alloc_page_interleave+0xf",
"      atomic_pool_expand+0x11c",
"      __dma_atomic_pool_init+0x45",
"      dma_atomic_pool_init+0xaf",
"      do_one_initcall+0x41",
"      do_initcalls+0xc6",
"      kernel_init_freeable+0x153",
"      kernel_init+0x16",
"      ret_from_fork+0x1f",
"",
"    PFN 4096(0x1000) paddr 1000000 page_owner ffff892c00840008",
"    Page allocated via order 9, mask 0x3c24ca, pid 45, tgid 45 (khugepaged), ts 96573977813114 ns, free_ts 0 ns",
"    [alloc]",
"      get_page_from_freelist+0x33e",
"      __alloc_pages+0xe6",
"      collapse_huge_page+0x8b",
"      khugepaged_scan_pmd+0x32b",
"    ...",
NULL
};

static struct command_table_entry command_table[] = {
	{ "owner", cmd_owner, help_owner, 0},
	{ NULL },
};

static void __attribute__((constructor))
page_owner_init(void)
{
	char *s;

	register_extension(command_table);

	PO_OFFSET_INIT(mem_section_page_ext, "mem_section", "page_ext");
	PO_OFFSET_INIT(page_ext_flags, "page_ext", "flags");
	PO_OFFSET_INIT(page_ext_operations_offset, "page_ext_operations", "offset");
	s = "page_owner";
	PO_OFFSET_INIT(page_owner_order, s, "order");
	PO_OFFSET_INIT(page_owner_last_migrate_reason, s, "last_migrate_reason");
	PO_OFFSET_INIT(page_owner_gfp_mask, s, "gfp_mask");
	PO_OFFSET_INIT(page_owner_handle, s, "handle");
	PO_OFFSET_INIT(page_owner_free_handle, s, "free_handle");	/* 5.4  and later */
	PO_OFFSET_INIT(page_owner_ts_nsec, s, "ts_nsec");		/* 5.11 and later */
	PO_OFFSET_INIT(page_owner_free_ts_nsec, s, "free_ts_nsec");	/* 5.13 and later */
	PO_OFFSET_INIT(page_owner_comm, s, "comm");			/* 5.18 and later */
	PO_OFFSET_INIT(page_owner_pid, s, "pid");			/* 5.11 and later */
	PO_OFFSET_INIT(page_owner_tgid, s, "tgid");			/* 5.18 and later */
	s = "stack_record";
	PO_OFFSET_INIT(stack_record_size, s, "size");
	PO_OFFSET_INIT(stack_record_entries, s, "entries");

	PO_SIZE_INIT(page_owner, "page_owner");
	PO_SIZE_INIT(page_ext, "page_ext");

	/* PAGE_OWNER_INITED */
	if (kernel_symbol_exists("page_owner_inited")) {
		int inited;	/* lazy hack: probably no offset */
		try_get_symbol_data("page_owner_inited", sizeof(int), &inited);
		if (inited)
			env_flags |= PAGE_OWNER_INITED;
	} else
		error(WARNING, "cannot find page_owner_inited\n");

	if (!(env_flags & PAGE_OWNER_INITED))
		error(WARNING, "page_owner is disabled\n");

	/* page_ext_size */
	if (kernel_symbol_exists("page_ext_size")) /* 5.4 and later */
		try_get_symbol_data("page_ext_size", sizeof(ulong), &page_ext_size);
	else if (kernel_symbol_exists("extra_mem") && PO_VALID_STRUCT(page_ext)) {
		ulong extra_mem;
		if (try_get_symbol_data("extra_mem", sizeof(ulong), &extra_mem))
			page_ext_size = PO_SIZE(page_ext) + extra_mem;
	}

	if (page_ext_size <= 0)
		error(WARNING, "cannot get page_exit_size value\n");

	/* page_owner_ops_offset */
	if (kernel_symbol_exists("page_owner_ops") && PO_VALID_MEMBER(page_ext_operations_offset))
		readmem(symbol_value("page_owner_ops") + PO_OFFSET(page_ext_operations_offset),
			KVADDR, &page_owner_ops_offset, sizeof(ulong), "page_owner_ops.offset",
			RETURN_ON_ERROR);

	if (page_owner_ops_offset < 0)
		error(WARNING, "cannot get page_owner_ops.offset value\n");

	/* PAGE_EXT_OWNER{,_ALLOCATED} */
	if (!enumerator_value("PAGE_EXT_OWNER", &PAGE_EXT_OWNER))
		error(WARNING, "cannot get PAGE_EXT_OWNER value\n");

	enumerator_value("PAGE_EXT_OWNER_ALLOCATED", &PAGE_EXT_OWNER_ALLOCATED); /* 5.4 and later */

	/* HANDLE_PARTS_EXTRA */
	if (MEMBER_EXISTS("handle_parts", "extra")) /* 6.1 and later */
		env_flags |= HANDLE_PARTS_EXTRA;

	/* stack_pools */
	if (kernel_symbol_exists("stack_pools")) /* 6.3 and later */
		stack_pools = symbol_value("stack_pools");
	else if (kernel_symbol_exists("stack_slabs"))
		stack_pools = symbol_value("stack_slabs");

	if (!stack_pools)
		error(WARNING, "cannot get stack_{pools|slabs}\n");

	/* max_pfn */
	if (kernel_symbol_exists("max_pfn"))
		try_get_symbol_data("max_pfn", sizeof(ulong), &max_pfn);

	if (!max_pfn)
		error(WARNING, "cannot get max_pfn\n");

	if (CRASHDEBUG(1)) {
		ulonglong data_debug = pc->flags & DATADEBUG;
		pc->flags &= ~DATADEBUG;

		fprintf(fp, "  env_flags: 0x%x ", env_flags);
		fprintf(fp, "(%sPAGE_OWNER_INITED", (env_flags & PAGE_OWNER_INITED) ? "" : "!");
		fprintf(fp, "|%sHANDLE_PARTS_EXTRA", (env_flags & HANDLE_PARTS_EXTRA) ? "" : "!");
		fprintf(fp, ")\n");
		fprintf(fp, "offsets:\n");
		fprintf(fp, "  mem_section.page_ext      : %ld\n", PO_OFFSET(mem_section_page_ext));
		fprintf(fp, "  page_ext.flags            : %ld\n", PO_OFFSET(page_ext_flags));
		fprintf(fp, "  page_ext_operations.offset: %ld\n", PO_OFFSET(page_ext_operations_offset));
		fprintf(fp, "  page_owner.order          : %ld\n", PO_OFFSET(page_owner_order));
		fprintf(fp, "        .last_migrate_reason: %ld\n", PO_OFFSET(page_owner_last_migrate_reason));
		fprintf(fp, "            .gfp_mask       : %ld\n", PO_OFFSET(page_owner_gfp_mask));
		fprintf(fp, "            .handle         : %ld\n", PO_OFFSET(page_owner_handle));
		fprintf(fp, "            .free_handle    : %ld\n", PO_OFFSET(page_owner_free_handle));
		fprintf(fp, "            .ts_nsec        : %ld\n", PO_OFFSET(page_owner_ts_nsec));
		fprintf(fp, "            .free_ts_nsec   : %ld\n", PO_OFFSET(page_owner_free_ts_nsec));
		fprintf(fp, "            .comm           : %ld\n", PO_OFFSET(page_owner_comm));
		fprintf(fp, "            .pid            : %ld\n", PO_OFFSET(page_owner_pid));
		fprintf(fp, "            .tgid           : %ld\n", PO_OFFSET(page_owner_tgid));
		fprintf(fp, "  stack_record.size         : %ld\n", PO_OFFSET(stack_record_size));
		fprintf(fp, "              .entries      : %ld\n", PO_OFFSET(stack_record_entries));
		fprintf(fp, "sizes:\n");
		fprintf(fp, "  page_owner                : %ld\n", PO_SIZE(page_owner));
		fprintf(fp, "  page_ext                  : %ld\n", PO_SIZE(page_ext));
		fprintf(fp, "variables:\n");
		fprintf(fp, "  page_ext_size             : %ld\n", page_ext_size);
		fprintf(fp, "  page_owner_ops.offset     : %ld\n", page_owner_ops_offset);
		fprintf(fp, "  PAGE_EXT_OWNER            : %ld\n", PAGE_EXT_OWNER);
		fprintf(fp, "  PAGE_EXT_OWNER_ALLOCATED  : %ld\n", PAGE_EXT_OWNER_ALLOCATED);
		fprintf(fp, "  max_pfn                   : %ld (0x%lx)\n", max_pfn, max_pfn);

		pc->flags |= data_debug;
	}
}

static void __attribute__((destructor))
page_owner_fini(void)
{
}
