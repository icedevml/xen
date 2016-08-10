/******************************************************************************
 * include/asm-x86/mem_access.h
 *
 * Copyright (c) 2011 GridCentric Inc. (Andres Lagar-Cavilla)
 * Copyright (c) 2007 Advanced Micro Devices (Wei Huang)
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

#ifndef _XEN_X86_MEM_ACCESS_H
#define _XEN_X86_MEM_ACCESS_H

/* Send mem event based on the access (gla is -1ull if not available).  Handles
 * the rw2rx conversion. Boolean return value indicates if access rights have
 * been promoted with no underlying vcpu pause. If the req_ptr has been populated,
 * then the caller must put the event in the ring (once having released get_gfn*
 * locks -- caller must also xfree the request. */
bool_t p2m_mem_access_check(paddr_t gpa, unsigned long gla,
                            struct npfec npfec,
                            vm_event_request_t **req_ptr);

/* Check for emulation and mark vcpu for skipping one instruction
 * upon rescheduling if required. */
void p2m_mem_access_emulate_check(struct vcpu *v,
                                  const vm_event_response_t *rsp);

/* Sanity check for mem_access hardware support */
static inline bool_t p2m_mem_access_sanity_check(struct domain *d)
{
    return is_hvm_domain(d) && cpu_has_vmx && hap_enabled(d);
}

#endif /* _XEN_X86_MEM_ACCESS_H */
