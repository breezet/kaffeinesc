/*
 * Softcam plugin to VDR (C++)
 *
 * This code is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This code is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 * Or, point your browser to http://www.gnu.org/copyleft/gpl.html
 */

#ifndef ___OPENSSL_COMPAT_H
#define ___OPENSSL_COMPAT_H

#include <openssl/opensslv.h>

#if OPENSSL_VERSION_NUMBER < 0x0090700fL
#define DES_cblock               des_cblock
#define DES_key_schedule         des_key_schedule
#define DES_KEY_SCHED(k,s)       des_key_sched(k,s)
#define DES_ECB_ENCRYPT(c,o,s,d) des_ecb_encrypt(c,o,s,d)
#define DES_set_odd_parity       des_set_odd_parity
#define DES_random_key           des_random_key
#define DES_EDE2_CBC_ENCRYPT(i,o,l,k1,k2,iv,e) des_ede2_cbc_encrypt((i),(o),(l),k1,k2,(iv),(e))
#else
#define DES_KEY_SCHED(k,s)       DES_key_sched(k,&s)
#define DES_ECB_ENCRYPT(c,o,s,d) DES_ecb_encrypt(c,o,&s,d)
#define DES_EDE2_CBC_ENCRYPT(i,o,l,k1,k2,iv,e) DES_ede2_cbc_encrypt((i),(o),(l),&k1,&k2,(iv),(e))
#endif

#endif
