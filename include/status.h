/*
 * silkhook - miniature arm64 hooking lib
 * status.h - status codes
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _STATUS_H_
#define _STATUS_H_


enum status {
    OK              = 0,
    ERR_INVALID_ARG = -1,
    ERR_ALLOC       = -2,
    ERR_PROT        = -3,
    ERR_EXISTS      = -4,
    ERR_NOT_HOOKED  = -5,
    ERR_BAD_INSTR   = -6,
    ERR_TRAMP       = -7,
};


static inline const char *status_str(enum status s)
{
    switch (s)
    {
        case OK:              return "ok";
        case ERR_INVALID_ARG: return "invalid argument";
        case ERR_ALLOC:       return "allocation failure";
        case ERR_PROT:        return "protection failure";
        case ERR_EXISTS:      return "pre-existing hook";
        case ERR_NOT_HOOKED:  return "hook failure";
        case ERR_BAD_INSTR:   return "unsupported instruction";
        case ERR_TRAMP:       return "trampoline failure";
        default:              return "unknown error (this is bad)";
    }
}


#endif /* _STATUS_H_ */
