The page_owner extension module
===============================

This is a [crash utility][1] extension module to display Linux kernel's page owner
information.  To use the module, the page owner facility must be enabled by the
kernel command-line parameter "page_owner=on".

Getting Started
---------------

To build the module from the top-level `crash-<version>` directory, enter:

    $ cp <path-to>/page_owner.c extensions
    $ make extensions

To load the module's commands to a running crash session, enter:

    crash> extend <path-to>/page_owner.so

To show the module's commands, enter:

    crash> extend
    SHARED OBJECT            COMMANDS
    <path-to>/page_owner.so  owner

Help Pages
----------

The module has only a command: [`owner`](#owner-command).

### `owner` command

```
NAME
  owner - dump page owner information

SYNOPSIS
  owner [-p] address..
  owner -l|-L [count]

DESCRIPTION
  This command dumps the page owner information of a specified address.

       -l  list page owner information for allocated pages.
       -L  list page owner information for allocated and freed pages.
           (this option is available only on Linux 5.4, RHEL8.5 and later.)
       -p  address argument is a physical address.
  address  a kernel virtual address by default, a physical address with -p.
    count  number of pages to display for -l and -L option.

EXAMPLES
  Dump the page owner information of a specified page address:

    crash> owner ffff892b73200000
    PFN 471552(0x73200) paddr 73200000 vaddr ffff892b73200000 page fffff4bec1cc8000 page_owner ffff892c024c8008
    Page allocated via order 9, mask 0x346cca, pid 46265, tgid 46265 (bash), ts 88704902141361 ns, free_ts 23514284799158 ns
    [alloc]
      get_page_from_freelist+0x33e
      __alloc_pages+0xe6
      alloc_buddy_huge_page+0x43
      alloc_fresh_huge_page+0x16f
      alloc_pool_huge_page+0x76
      set_max_huge_pages+0x198
      __nr_hugepages_store_common+0x48
      hugetlb_sysctl_handler_common+0xdf
      proc_sys_call_handler+0x162
      new_sync_write+0xfc
      vfs_write+0x1ef
      ksys_write+0x5f
      do_syscall_64+0x59
      entry_SYSCALL_64_after_hwframe+0x63
    free
      free_pcp_prepare+0x142
      free_unref_page_list+0x92
      release_pages+0x16d
      tlb_flush_mmu+0x4b
      zap_pte_range+0x808
      zap_pmd_range+0x141
      unmap_page_range+0x2c6
      unmap_vmas+0x78
      exit_mmap+0xa5
      mmput+0x5a
      exit_mm+0xb8
      do_exit+0x1f3
      do_group_exit+0x2d
      __x64_sys_exit_group+0x14
      do_syscall_64+0x59
      entry_SYSCALL_64_after_hwframe+0x63

  List the page owner information of allocated pages:

    crash> owner -l
    PFN 256(0x100) paddr 100000 page_owner ffff892c00804008
    Page allocated via order 7, mask 0xcc1, pid 1, tgid 1 (swapper/0), ts 129969032 ns, free_ts 0 ns
    [alloc]
      get_page_from_freelist+0x33e
      __alloc_pages+0xe6
      alloc_page_interleave+0xf
      atomic_pool_expand+0x11c
      __dma_atomic_pool_init+0x45
      dma_atomic_pool_init+0xaf
      do_one_initcall+0x41
      do_initcalls+0xc6
      kernel_init_freeable+0x153
      kernel_init+0x16
      ret_from_fork+0x1f

    PFN 4096(0x1000) paddr 1000000 page_owner ffff892c00840008
    Page allocated via order 9, mask 0x3c24ca, pid 45, tgid 45 (khugepaged), ts 96573977813114 ns, free_ts 0 ns
    [alloc]
      get_page_from_freelist+0x33e
      __alloc_pages+0xe6
      collapse_huge_page+0x8b
      khugepaged_scan_pmd+0x32b
    ...

```

Tested Kernels
--------------

- RHEL8.3 to RHEL9.4 (x86_64)
- 4.18 to 6.17 (x86_64)

Related Links
-------------

- [crash utility][1] (https://crash-utility.github.io/)

[1]: https://crash-utility.github.io/

Author
------

- Kazuhito Hagio &lt;k-hagio-ab@nec.com&gt;

