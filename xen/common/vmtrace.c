/*
 * xen/common/monitor.c
 *
 * Common monitor_op domctl handler.
 *
 * Copyright (c) 2015 Tamas K Lengyel (tamas@tklengyel.com)
 * Copyright (c) 2016, Bitdefender S.R.L.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License v2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this program; If not, see <http://www.gnu.org/licenses/>.
 */

#include <xen/event.h>
#include <xen/monitor.h>
#include <xen/sched.h>
#include <xen/vm_event.h>
#include <xsm/xsm.h>
#include <asm/altp2m.h>
#include <asm/vmtrace.h>

int vmtrace_domctl(struct domain *d, struct xen_domctl_vmtrace_op *vmtop)
{
    int rc;
    bool requested_status = false;

    if ( unlikely(current->domain == d) ) /* no domain_pause() */
        return -EPERM;

    switch ( mop->event )
    {
    case XEN_DOMCTL_vmtrace_pt_enable:
        vcpu_pause(v);
        spin_lock(&d->vmtrace_lock);

	arch_vmtrace_
        if ( vmx_add_guest_msr(v, MSR_RTIT_CTL,
                               RTIT_CTL_TRACEEN | RTIT_CTL_OS |
                               RTIT_CTL_USR | RTIT_CTL_BRANCH_EN) )
        {
            rc = -EFAULT;
            goto out;
        }

        pt->active = 1;
        spin_unlock(&d->vmtrace_lock);
        vcpu_unpause(v);
        break;

    case XEN_DOMCTL_vmtrace_pt_disable:
        vcpu_pause(v);
        spin_lock(&d->vmtrace_lock);

        if ( vmx_del_msr(v, MSR_RTIT_CTL, VMX_MSR_GUEST) )
        {
            rc = -EFAULT;
            goto out;
        }

        pt->active = 0;
        spin_unlock(&d->vmtrace_lock);
        vcpu_unpause(v);
        break;

    case XEN_DOMCTL_vmtrace_pt_get_offset:
        a.offset = pt->output_mask.offset;

        if ( __copy_field_to_guest(guest_handle_cast(arg, xen_domctl_vmtrace_op_t), &a, offset) )
        {
            rc = -EFAULT;
            goto out;
        }
        break;

    default:
        return -EOPNOTSUPP;
    }

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
