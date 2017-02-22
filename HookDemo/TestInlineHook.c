//
//  TestInlineHook.c
//  libhook
//
//  Created by 吴昕 on 22/02/2017.
//  Copyright © 2017 ChinaNetCenter. All rights reserved.
//

#include "substitute.h"
#include "substitute-internal.h"
#include <stdio.h>
#include <search.h>
#include <unistd.h>
#include <errno.h>

#include "TestInlineHook.h"

static pid_t (*old_getpid)();

static pid_t hook_getpid() {
    return old_getpid() * 2;
}

static int hook_hcreate(size_t nel) {
    return (int) nel;
}

static size_t (*old_fwrite)(const void *restrict, size_t, size_t, FILE *restrict);

static size_t hook_fwrite(const void *restrict ptr, size_t size, size_t nitems,
                          FILE *restrict stream) {
    size_t ret = old_fwrite(ptr, size, nitems, stream);
    old_fwrite("*hic*\n", 1, 6, stream);
    return ret;
}

static const struct substitute_function_hook hooks[] = {
    {getpid, hook_getpid, &old_getpid},
    {hcreate, hook_hcreate, NULL},
    {fwrite, hook_fwrite, &old_fwrite},
};

void test_inline_hook() {

    for (size_t i = 0; i < sizeof(hooks)/sizeof(*hooks); i++) {
        uintptr_t p = (uintptr_t) hooks[i].function;
        uint32_t *insns = (void *) (p & ~1);
        printf("<%zd: ptr=%p insns=0x%08x, 0x%08x, 0x%08x\n",
               i, hooks[i].function,
               insns[0], insns[1], insns[2]);
        
    }
    printf("getpid() => %d\n", getpid());
    printf("before hook \n");
    
    int ret = substitute_hook_functions(&hooks[0], sizeof(hooks)/sizeof(*hooks),
                                        NULL, 0);
    
    printf("after hook \n");
    
    for (size_t i = 0; i < sizeof(hooks)/sizeof(*hooks); i++) {
        uintptr_t p = (uintptr_t) hooks[i].function;
        uint32_t *insns = (void *) (p & ~1);
        printf("<%zd: ptr=%p insns=0x%08x, 0x%08x, 0x%08x\n",
               i, hooks[0].function,
               insns[0], insns[1], insns[2]);
    }
    int e = errno;
    printf("ret = %d\n", ret);
    printf("errno = %d\n", e);
    printf("getpid() => %d\n", getpid());
    printf("hcreate() => %d\n", hcreate(42));
    
}
