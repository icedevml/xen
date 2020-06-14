/******************************************************************************
 * tools/xenbaked.c
 *
 * Tool for collecting raw trace buffer data from Xen and 
 *  performing some accumulation operations and other processing
 *  on it.
 *
 * Copyright (C) 2004 by Intel Research Cambridge
 * Copyright (C) 2005 by Hewlett Packard, Palo Alto and Fort Collins
 * Copyright (C) 2006 by Hewlett Packard Fort Collins
 *
 * Authors: Diwaker Gupta, diwaker.gupta@hp.com
 *          Rob Gardner, rob.gardner@hp.com
 *          Lucy Cherkasova, lucy.cherkasova.hp.com
 * Much code based on xentrace, authored by Mark Williamson, 
 * mark.a.williamson@intel.com
 * Date:   November, 2005
 * 
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; under version 2 of the License.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; If not, see <http://www.gnu.org/licenses/>.
 */

#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <xenevtchn.h>
#include <xenctrl.h>
#include <xen/xen.h>
#include <string.h>
#include <sys/select.h>
#include <getopt.h>


volatile int interrupted = 0;

void term_handler(int signum) {
    interrupted = 1;
}

int main(int argc, char* argv[]) {
    xc_interface *xc;
    uint32_t domid;
    uint32_t vcpu_id;

    int rc = -1;
    uint8_t *buf;
    uint64_t size;
    uint64_t last_offset = 0;

    signal(SIGINT, term_handler);

    if (argc != 3) {
        fprintf(stderr, "Usage: %s <domid> <vcpu_id>\n", argv[0]);
	fprintf(stderr, "It's recommended to redirect this program's output to file\n");
	fprintf(stderr, "or to pipe it's output to xxd or other program.\n");
	return 1;
    }

    domid = atoi(argv[1]);
    vcpu_id = atoi(argv[2]);

    xc = xc_interface_open(0, 0, 0);

    if (!xc) {
        fprintf(stderr, "Failed to open xc interface\n");
        return 1;
    }
    
    rc = xc_ptbuf_enable(xc, domid, vcpu_id, 64 * 1024 * 1024);

    if (rc) {
        fprintf(stderr, "Failed to call xc_ptbuf_enable\n");
	return 1;
    }

    rc = xc_ptbuf_map(xc, domid, vcpu_id, &buf, &size);

    if (rc) {
        fprintf(stderr, "Failed to call xc_ptbuf_map\n");
	return 1;
    }

    while (!interrupted) {
        uint64_t offset;
        rc = xc_ptbuf_get_offset(xc, domid, vcpu_id, &offset);

	if (rc) {
            fprintf(stderr, "Failed to call xc_ptbuf_get_offset\n");
	    return 1;
	}

	if (offset > last_offset)
	{
            fwrite(buf + last_offset, offset - last_offset, 1, stdout);
	}
	else
	{
            // buffer wrapped
	    fwrite(buf + last_offset, size - last_offset, 1, stdout);
	    fwrite(buf, offset, 1, stdout);
	}

        last_offset = offset;
	usleep(1000 * 100);
    }

    rc = xc_ptbuf_unmap(xc, buf, size);

    if (rc) {
        fprintf(stderr, "Failed to call xc_ptbuf_unmap\n");
	return 1;
    }

    rc = xc_ptbuf_disable(xc, domid, vcpu_id);

    if (rc) {
        fprintf(stderr, "Failed to call xc_ptbuf_disable\n");
	return 1;
    }

    return 0;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
