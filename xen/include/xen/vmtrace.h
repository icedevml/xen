/*
 * include/xen/vmtrace.h
 *
 * ...
 *
 * Copyright (c) 2020 CERT Polska
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

#ifndef __XEN_VMTRACE_H__
#define __XEN_VMTRACE_H__

#include <public/xen.h>

struct domain;
struct xen_domctl_vmtrace_op;

int vmtrace_domctl(struct domain *d, struct xen_domctl_vmtrace_op *op);

#endif /* __XEN_VMTRACE_H__ */
