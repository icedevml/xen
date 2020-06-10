/******************************************************************************
 * xc_tbuf.c
 *
 * API for manipulating and accessing trace buffer parameters
 *
 * Copyright (c) 2005, Rob Gardner
 *
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation;
 * version 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; If not, see <http://www.gnu.org/licenses/>.
 */

#include "xc_private.h"
#include <xen/trace.h>

static int tbuf_enable(xc_interface *xch, int enable)
{
    DECLARE_SYSCTL;

    sysctl.cmd = XEN_SYSCTL_tbuf_op;
    sysctl.interface_version = XEN_SYSCTL_INTERFACE_VERSION;
    if ( enable )
        sysctl.u.tbuf_op.cmd  = XEN_SYSCTL_TBUFOP_enable;
    else
        sysctl.u.tbuf_op.cmd  = XEN_SYSCTL_TBUFOP_disable;

    return xc_sysctl(xch, &sysctl);
}

int xc_tbuf_set_size(xc_interface *xch, unsigned long size)
{
    DECLARE_SYSCTL;

    sysctl.cmd = XEN_SYSCTL_tbuf_op;
    sysctl.interface_version = XEN_SYSCTL_INTERFACE_VERSION;
    sysctl.u.tbuf_op.cmd  = XEN_SYSCTL_TBUFOP_set_size;
    sysctl.u.tbuf_op.size = size;

    return xc_sysctl(xch, &sysctl);
}

int xc_tbuf_get_size(xc_interface *xch, unsigned long *size)
{
    struct t_info *t_info;
    int rc;
    DECLARE_SYSCTL;

    sysctl.cmd = XEN_SYSCTL_tbuf_op;
    sysctl.interface_version = XEN_SYSCTL_INTERFACE_VERSION;
    sysctl.u.tbuf_op.cmd  = XEN_SYSCTL_TBUFOP_get_info;

    rc = xc_sysctl(xch, &sysctl);
    if ( rc != 0 )
        return rc;

    t_info = xc_map_foreign_range(xch, DOMID_XEN,
                    sysctl.u.tbuf_op.size, PROT_READ | PROT_WRITE,
                    sysctl.u.tbuf_op.buffer_mfn);

    if ( t_info == NULL || t_info->tbuf_size == 0 )
        rc = -1;
    else
	*size = t_info->tbuf_size;

    xenforeignmemory_unmap(xch->fmem, t_info, sysctl.u.tbuf_op.size);

    return rc;
}

int xc_ptbuf_enable(xc_interface *xch, uint32_t domid, unsigned long order, xc_ptbuf_alloc_res_t *out)
{
    DECLARE_HYPERCALL_BUFFER(xen_hvm_ipt_op_t, arg);
    int rc = -1;
    unsigned long mfn;
    struct pt_state *ptst;
    void *buf;
    int i;

    arg = xc_hypercall_buffer_alloc(xch, arg, sizeof(*arg));
    if ( arg == NULL )
        return -1;

    arg->version = HVMOP_IPT_INTERFACE_VERSION;
    arg->cmd = HVMOP_ipt_enable;
    arg->domain = domid;
    arg->order = order;

    rc = xencall2(xch->xcall, __HYPERVISOR_hvm_op, HVMOP_ipt,
                  HYPERCALL_BUFFER_AS_ARG(arg));

    if ( rc == 0 )
    {
        printf("MFN: %llx\n", (unsigned long long)arg->mfn);
        mfn = arg->mfn;
        ptst = (struct pt_state *)xc_map_foreign_range(xch, DOMID_XEN, PAGE_SIZE, PROT_READ, mfn);

        out->num_vcpus = ptst->num_vcpus;
        out->pt_buf = (void **)malloc(ptst->num_vcpus * sizeof(void *));
        out->state = (struct pt_vcpu_state **)malloc(ptst->num_vcpus * sizeof(struct pt_vcpu_state *));

        for (i = 0; i < ptst->num_vcpus; i++)
        {
            printf("IPT buffer vCPU: %d MFN: %llx\n", i, (unsigned long long)ptst->vcpu[i].buf_mfn);
            out->pt_buf[i] = NULL;
            out->state[i] = NULL;

            if (ptst->vcpu[i].buf_mfn) {
                buf = xc_map_foreign_range(xch, DOMID_XEN, ptst->vcpu[i].size, PROT_READ, ptst->vcpu[i].buf_mfn);
                printf("Mapped buffer: %llx\n", (unsigned long long)buf);
                out->pt_buf[i] = buf;
                out->state[i] = &ptst->vcpu[i];
            }
        }
    }

    return rc;
}

int xc_ptbuf_disable(xc_interface *xch, uint32_t domid)
{
    DECLARE_HYPERCALL_BUFFER(xen_hvm_ipt_op_t, arg);
    int rc = -1;

    arg = xc_hypercall_buffer_alloc(xch, arg, sizeof(*arg));
    if ( arg == NULL )
        return -1;

    arg->version = HVMOP_IPT_INTERFACE_VERSION;
    arg->cmd = HVMOP_ipt_disable;
    arg->domain = domid;

    rc = xencall2(xch->xcall, __HYPERVISOR_hvm_op, HVMOP_ipt,
                  HYPERCALL_BUFFER_AS_ARG(arg));

    return rc;
}

int xc_tbuf_enable(xc_interface *xch, unsigned long pages, unsigned long *mfn,
                   unsigned long *size)
{
    DECLARE_SYSCTL;
    int rc;

    /*
     * Ignore errors (at least for now) as we get an error if size is already
     * set (since trace buffers cannot be reallocated). If we really have no
     * buffers at all then tbuf_enable() will fail, so this is safe.
     */
    (void)xc_tbuf_set_size(xch, pages);

    if ( tbuf_enable(xch, 1) != 0 )
        return -1;

    sysctl.cmd = XEN_SYSCTL_tbuf_op;
    sysctl.interface_version = XEN_SYSCTL_INTERFACE_VERSION;
    sysctl.u.tbuf_op.cmd  = XEN_SYSCTL_TBUFOP_get_info;

    rc = xc_sysctl(xch, &sysctl);
    if ( rc == 0 )
    {
        *size = sysctl.u.tbuf_op.size;
        *mfn = sysctl.u.tbuf_op.buffer_mfn;
    }

    return 0;
}

int xc_tbuf_disable(xc_interface *xch)
{
    return tbuf_enable(xch, 0);
}

int xc_tbuf_set_cpu_mask(xc_interface *xch, xc_cpumap_t mask)
{
    DECLARE_SYSCTL;
    DECLARE_HYPERCALL_BOUNCE(mask, 0, XC_HYPERCALL_BUFFER_BOUNCE_IN);
    int ret = -1;
    int bits, cpusize;

    cpusize = xc_get_cpumap_size(xch);
    if (cpusize <= 0)
    {
        PERROR("Could not get number of cpus");
        return -1;
    }

    HYPERCALL_BOUNCE_SET_SIZE(mask, cpusize);

    bits = xc_get_max_cpus(xch);
    if (bits <= 0)
    {
        PERROR("Could not get number of bits");
        return -1;
    }

    if ( xc_hypercall_bounce_pre(xch, mask) )
    {
        PERROR("Could not allocate memory for xc_tbuf_set_cpu_mask hypercall");
        goto out;
    }

    sysctl.cmd = XEN_SYSCTL_tbuf_op;
    sysctl.interface_version = XEN_SYSCTL_INTERFACE_VERSION;
    sysctl.u.tbuf_op.cmd  = XEN_SYSCTL_TBUFOP_set_cpu_mask;

    set_xen_guest_handle(sysctl.u.tbuf_op.cpu_mask.bitmap, mask);
    sysctl.u.tbuf_op.cpu_mask.nr_bits = bits;

    ret = do_sysctl(xch, &sysctl);

    xc_hypercall_bounce_post(xch, mask);

 out:
    return ret;
}

int xc_tbuf_set_evt_mask(xc_interface *xch, uint32_t mask)
{
    DECLARE_SYSCTL;

    sysctl.cmd = XEN_SYSCTL_tbuf_op;
    sysctl.interface_version = XEN_SYSCTL_INTERFACE_VERSION;
    sysctl.u.tbuf_op.cmd  = XEN_SYSCTL_TBUFOP_set_evt_mask;
    sysctl.u.tbuf_op.evt_mask = mask;

    return do_sysctl(xch, &sysctl);
}

