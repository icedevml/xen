/******************************************************************************
 * arch/x86/mm/mem_access.c
 *
 * Parts of this code are Copyright (c) 2009 by Citrix Systems, Inc. (Patrick Colp)
 * Parts of this code are Copyright (c) 2007 by Advanced Micro Devices.
 * Parts of this code are Copyright (c) 2006-2007 by XenSource Inc.
 * Parts of this code are Copyright (c) 2006 by Michael A Fetterman
 * Parts based on earlier work by Michael A Fetterman, Ian Pratt et al.
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
 * along with this program; If not, see <http://www.gnu.org/licenses/>.
 */

#include <xen/vm_event.h>
#include <asm/altp2m.h>
#include <asm/p2m.h>
#include <asm/event.h>
#include <asm/mem_access.h>
#include <asm/vm_event.h>

#include "mm-locks.h"

/* Override macro from asm/page.h to make them work with mfn_t */
#undef mfn_valid
#define mfn_valid(_mfn) __mfn_valid(mfn_x(_mfn))

void p2m_mem_access_emulate_check(struct vcpu *v,
                                  const vm_event_response_t *rsp)
{
    /* Mark vcpu for skipping one instruction upon rescheduling. */
    if ( rsp->flags & VM_EVENT_FLAG_EMULATE )
    {
        xenmem_access_t access;
        bool_t violation = 1;
        const struct vm_event_mem_access *data = &rsp->u.mem_access;

        if ( p2m_get_mem_access(v->domain, _gfn(data->gfn), &access) == 0 )
        {
            switch ( access )
            {
            case XENMEM_access_n:
            case XENMEM_access_n2rwx:
            default:
                violation = data->flags & MEM_ACCESS_RWX;
                break;

            case XENMEM_access_r:
                violation = data->flags & MEM_ACCESS_WX;
                break;

            case XENMEM_access_w:
                violation = data->flags & MEM_ACCESS_RX;
                break;

            case XENMEM_access_x:
                violation = data->flags & MEM_ACCESS_RW;
                break;

            case XENMEM_access_rx:
            case XENMEM_access_rx2rw:
                violation = data->flags & MEM_ACCESS_W;
                break;

            case XENMEM_access_wx:
                violation = data->flags & MEM_ACCESS_R;
                break;

            case XENMEM_access_rw:
                violation = data->flags & MEM_ACCESS_X;
                break;

            case XENMEM_access_rwx:
                violation = 0;
                break;
            }
        }

        v->arch.vm_event->emulate_flags = violation ? rsp->flags : 0;

        if ( (rsp->flags & VM_EVENT_FLAG_SET_EMUL_READ_DATA) )
            v->arch.vm_event->emul_read_data = rsp->data.emul_read_data;
    }
}

bool_t p2m_mem_access_check(paddr_t gpa, unsigned long gla,
                            struct npfec npfec,
                            vm_event_request_t **req_ptr)
{
    struct vcpu *v = current;
    unsigned long gfn = gpa >> PAGE_SHIFT;
    struct domain *d = v->domain;
    struct p2m_domain *p2m = NULL;
    mfn_t mfn;
    p2m_type_t p2mt;
    p2m_access_t p2ma;
    vm_event_request_t *req;
    int rc;

    if ( altp2m_active(d) )
        p2m = p2m_get_altp2m(v);
    if ( !p2m )
        p2m = p2m_get_hostp2m(d);

    /* First, handle rx2rw conversion automatically.
     * These calls to p2m->set_entry() must succeed: we have the gfn
     * locked and just did a successful get_entry(). */
    gfn_lock(p2m, gfn, 0);
    mfn = p2m->get_entry(p2m, gfn, &p2mt, &p2ma, 0, NULL, NULL);

    if ( npfec.write_access && p2ma == p2m_access_rx2rw )
    {
        rc = p2m->set_entry(p2m, gfn, mfn, PAGE_ORDER_4K, p2mt, p2m_access_rw, -1);
        ASSERT(rc == 0);
        gfn_unlock(p2m, gfn, 0);
        return 1;
    }
    else if ( p2ma == p2m_access_n2rwx )
    {
        ASSERT(npfec.write_access || npfec.read_access || npfec.insn_fetch);
        rc = p2m->set_entry(p2m, gfn, mfn, PAGE_ORDER_4K,
                            p2mt, p2m_access_rwx, -1);
        ASSERT(rc == 0);
    }
    gfn_unlock(p2m, gfn, 0);

    /* Otherwise, check if there is a memory event listener, and send the message along */
    if ( !vm_event_check_ring(&d->vm_event->monitor) || !req_ptr )
    {
        /* No listener */
        if ( p2m->access_required )
        {
            gdprintk(XENLOG_INFO, "Memory access permissions failure, "
                                  "no vm_event listener VCPU %d, dom %d\n",
                                  v->vcpu_id, d->domain_id);
            domain_crash(v->domain);
            return 0;
        }
        else
        {
            gfn_lock(p2m, gfn, 0);
            mfn = p2m->get_entry(p2m, gfn, &p2mt, &p2ma, 0, NULL, NULL);
            if ( p2ma != p2m_access_n2rwx )
            {
                /* A listener is not required, so clear the access
                 * restrictions.  This set must succeed: we have the
                 * gfn locked and just did a successful get_entry(). */
                rc = p2m->set_entry(p2m, gfn, mfn, PAGE_ORDER_4K,
                                    p2mt, p2m_access_rwx, -1);
                ASSERT(rc == 0);
            }
            gfn_unlock(p2m, gfn, 0);
            return 1;
        }
    }

    *req_ptr = NULL;
    req = xzalloc(vm_event_request_t);
    if ( req )
    {
        *req_ptr = req;
        req->reason = VM_EVENT_REASON_MEM_ACCESS;

        /* Pause the current VCPU */
        if ( p2ma != p2m_access_n2rwx )
            req->flags |= VM_EVENT_FLAG_VCPU_PAUSED;

        /* Send request to mem event */
        req->u.mem_access.gfn = gfn;
        req->u.mem_access.offset = gpa & ((1 << PAGE_SHIFT) - 1);
        if ( npfec.gla_valid )
        {
            req->u.mem_access.flags |= MEM_ACCESS_GLA_VALID;
            req->u.mem_access.gla = gla;

            if ( npfec.kind == npfec_kind_with_gla )
                req->u.mem_access.flags |= MEM_ACCESS_FAULT_WITH_GLA;
            else if ( npfec.kind == npfec_kind_in_gpt )
                req->u.mem_access.flags |= MEM_ACCESS_FAULT_IN_GPT;
        }
        req->u.mem_access.flags |= npfec.read_access    ? MEM_ACCESS_R : 0;
        req->u.mem_access.flags |= npfec.write_access   ? MEM_ACCESS_W : 0;
        req->u.mem_access.flags |= npfec.insn_fetch     ? MEM_ACCESS_X : 0;
        req->vcpu_id = v->vcpu_id;

        vm_event_fill_regs(req);

        if ( altp2m_active(v->domain) )
        {
            req->flags |= VM_EVENT_FLAG_ALTERNATE_P2M;
            req->altp2m_idx = vcpu_altp2m(v).p2midx;
        }
    }

    /* Pause the current VCPU */
    if ( p2ma != p2m_access_n2rwx )
        vm_event_vcpu_pause(v);

    /* VCPU may be paused, return whether we promoted automatically */
    return (p2ma == p2m_access_n2rwx);
}

static inline
int p2m_set_altp2m_mem_access(struct domain *d, struct p2m_domain *hp2m,
                              struct p2m_domain *ap2m, p2m_access_t a,
                              gfn_t gfn)
{
    mfn_t mfn;
    p2m_type_t t;
    p2m_access_t old_a;
    unsigned int page_order;
    unsigned long gfn_l = gfn_x(gfn);
    int rc;

    mfn = ap2m->get_entry(ap2m, gfn_l, &t, &old_a, 0, NULL, NULL);

    /* Check host p2m if no valid entry in alternate */
    if ( !mfn_valid(mfn) )
    {

        mfn = get_gfn_type_access(hp2m, gfn_l, &t, &old_a,
                                  P2M_ALLOC | P2M_UNSHARE, &page_order);

        rc = -ESRCH;
        if ( !mfn_valid(mfn) || t != p2m_ram_rw )
            return rc;

        /* If this is a superpage, copy that first */
        if ( page_order != PAGE_ORDER_4K )
        {
            unsigned long mask = ~((1UL << page_order) - 1);
            unsigned long gfn2_l = gfn_l & mask;
            mfn_t mfn2 = _mfn(mfn_x(mfn) & mask);

            rc = ap2m->set_entry(ap2m, gfn2_l, mfn2, page_order, t, old_a, 1);
            if ( rc )
                return rc;
        }
    }

    return ap2m->set_entry(ap2m, gfn_l, mfn, PAGE_ORDER_4K, t, a,
                         (current->domain != d));
}

/*
 * Set access type for a region of gfns.
 * If gfn == INVALID_GFN, sets the default access type.
 */
long p2m_set_mem_access(struct domain *d, gfn_t gfn, uint32_t nr,
                        uint32_t start, uint32_t mask, xenmem_access_t access,
                        unsigned int altp2m_idx)
{
    struct p2m_domain *p2m = p2m_get_hostp2m(d), *ap2m = NULL;
    p2m_access_t a, _a;
    p2m_type_t t;
    mfn_t mfn;
    unsigned long gfn_l;
    long rc = 0;

    static const p2m_access_t memaccess[] = {
#define ACCESS(ac) [XENMEM_access_##ac] = p2m_access_##ac
        ACCESS(n),
        ACCESS(r),
        ACCESS(w),
        ACCESS(rw),
        ACCESS(x),
        ACCESS(rx),
        ACCESS(wx),
        ACCESS(rwx),
        ACCESS(rx2rw),
        ACCESS(n2rwx),
#undef ACCESS
    };

    /* altp2m view 0 is treated as the hostp2m */
    if ( altp2m_idx )
    {
        if ( altp2m_idx >= MAX_ALTP2M ||
             d->arch.altp2m_eptp[altp2m_idx] == mfn_x(INVALID_MFN) )
            return -EINVAL;

        ap2m = d->arch.altp2m_p2m[altp2m_idx];
    }

    switch ( access )
    {
    case 0 ... ARRAY_SIZE(memaccess) - 1:
        a = memaccess[access];
        break;
    case XENMEM_access_default:
        a = p2m->default_access;
        break;
    default:
        return -EINVAL;
    }

    /* If request to set default access. */
    if ( gfn_eq(gfn, INVALID_GFN) )
    {
        p2m->default_access = a;
        return 0;
    }

    p2m_lock(p2m);
    if ( ap2m )
        p2m_lock(ap2m);

    for ( gfn_l = gfn_x(gfn) + start; nr > start; ++gfn_l )
    {
        if ( ap2m )
        {
            rc = p2m_set_altp2m_mem_access(d, p2m, ap2m, a, _gfn(gfn_l));
            /* If the corresponding mfn is invalid we will just skip it */
            if ( rc && rc != -ESRCH )
                break;
        }
        else
        {
            mfn = p2m->get_entry(p2m, gfn_l, &t, &_a, 0, NULL, NULL);
            rc = p2m->set_entry(p2m, gfn_l, mfn, PAGE_ORDER_4K, t, a, -1);
            if ( rc )
                break;
        }

        /* Check for continuation if it's not the last iteration. */
        if ( nr > ++start && !(start & mask) && hypercall_preempt_check() )
        {
            rc = start;
            break;
        }
    }

    if ( ap2m )
        p2m_unlock(ap2m);
    p2m_unlock(p2m);

    return rc;
}

/*
 * Get access type for a gfn.
 * If gfn == INVALID_GFN, gets the default access type.
 */
int p2m_get_mem_access(struct domain *d, gfn_t gfn, xenmem_access_t *access)
{
    struct p2m_domain *p2m = p2m_get_hostp2m(d);
    p2m_type_t t;
    p2m_access_t a;
    mfn_t mfn;

    static const xenmem_access_t memaccess[] = {
#define ACCESS(ac) [p2m_access_##ac] = XENMEM_access_##ac
            ACCESS(n),
            ACCESS(r),
            ACCESS(w),
            ACCESS(rw),
            ACCESS(x),
            ACCESS(rx),
            ACCESS(wx),
            ACCESS(rwx),
            ACCESS(rx2rw),
            ACCESS(n2rwx),
#undef ACCESS
    };

    /* If request to get default access. */
    if ( gfn_eq(gfn, INVALID_GFN) )
    {
        *access = memaccess[p2m->default_access];
        return 0;
    }

    gfn_lock(p2m, gfn, 0);
    mfn = p2m->get_entry(p2m, gfn_x(gfn), &t, &a, 0, NULL, NULL);
    gfn_unlock(p2m, gfn, 0);

    if ( mfn_eq(mfn, INVALID_MFN) )
        return -ESRCH;

    if ( (unsigned) a >= ARRAY_SIZE(memaccess) )
        return -ERANGE;

    *access =  memaccess[a];
    return 0;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
