/*
 * silkhook  - miniature arm64 hooking lib
 * status.h  - status codes
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _SILKHOOK_STATUS_H_
#define _SILKHOOK_STATUS_H_


enum silkhook_status {
    SILKHOOK_OK         =  0,
    SILKHOOK_ERR_INVAL  = -1,
    SILKHOOK_ERR_NOMEM  = -2,
    SILKHOOK_ERR_PROT   = -3,
    SILKHOOK_ERR_EXISTS = -4,
    SILKHOOK_ERR_NOENT  = -5,
    SILKHOOK_ERR_INSTR  = -6,
};


static inline const char *silkhook_strerror(int e)
{
    switch (e)
    {
        case SILKHOOK_OK:          return "ok";
        case SILKHOOK_ERR_INVAL:   return "invalid argument";
        case SILKHOOK_ERR_NOMEM:   return "out of memory";
        case SILKHOOK_ERR_PROT:    return "protection failure";
        case SILKHOOK_ERR_EXISTS:  return "hook exists";
        case SILKHOOK_ERR_NOENT:   return "not found";
        case SILKHOOK_ERR_INSTR:   return "bad instruction";
        default:                   return "unknown";
    }
}


#endif /* _SILKHOOK_STATUS_H_ */
