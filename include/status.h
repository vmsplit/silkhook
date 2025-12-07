/*
 * silkhook  - miniature arm64 hooking lib
 * status.h  - status codes
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _SILKHOOK_STATUS_H_
#define _SILKHOOK_STATUS_H_


enum silkhook_status {
    SILKHOOK_OK          =  0,
    SILKHOOK_ERR_INVAL   = -1,
    SILKHOOK_ERR_NOMEM   = -2,
    SILKHOOK_ERR_PROT    = -3,
    SILKHOOK_ERR_EXISTS  = -4,
    SILKHOOK_ERR_NOENT   = -5,
    SILKHOOK_ERR_INSTR   = -6,
    SILKHOOK_ERR_STATE   = -7,
    SILKHOOK_ERR_RESOLVE = -8,
};


/*static inline */ const char *silkhook_strerror(int e);


#endif /* _SILKHOOK_STATUS_H_ */
