# Xen 4.22.0 for DRAKVUF (temporary fork)

**Use branch [`RELEASE-4.22.0-drakvuf1`](https://github.com/icedevml/xen/tree/RELEASE-4.22.0-drakvuf1).**

Stock Xen `RELEASE-4.22.0` plus fixes that DRAKVUF needs and that are not in a Xen release yet:

1. **x86/p2m: don't request mapcache invalidation for altp2m removals.** Removing an altp2m entry
   (DRAKVUF does this every time it removes a breakpoint) made every guest vCPU send a mapcache
   invalidation to QEMU. With DRAKVUF hooks active that is hundreds of invalidations per second,
   each one stalling the guest. A traced syscall drops from ~8.1 ms to ~0.19 ms.
   Submitted upstream: [xen-devel](https://lists.xenproject.org/archives/html/xen-devel/2026-11/msg01979.html).
2. **Config.mk: build QEMU from [icedevml/qemu-xen](https://github.com/icedevml/qemu-xen)**
   (branch `qemu-xen-4.22.0-drakvuf1`, pinned by commit hash): qemu-xen 4.22.0 with the backported
   upstream fix for a deadlock between IDE TRIM and block drain, which froze analyses at random.
3. **Version marker:** the build reports `4.22.0-drakvuf1` (hypervisor, `xen-upstream` debball) and
   QEMU reports `qemu-xen-4.22.0-drakvuf1`.

Background: [tklengyel/drakvuf#1858](https://github.com/tklengyel/drakvuf/issues/1858).

This fork is temporary and will be removed once the fixes are in a Xen release.
