#ifndef COR_POOL_H
#define COR_POOL_H

#include <inttypes.h>
#include <sys/types.h>

typedef struct cor_pool_s cor_pool_t;
typedef struct cor_pool_large_s cor_pool_large_t;

struct cor_pool_large_s
{
    cor_pool_large_t *next;
    void *data;
};

struct cor_pool_s
{
    uint8_t *last;
    uint8_t *end;
    size_t size;
    int failed;
    cor_pool_t *cur;
    cor_pool_t *next;
    cor_pool_large_t *large;
};

cor_pool_t *cor_pool_new(size_t size);
void cor_pool_reset(cor_pool_t *pool);
size_t cor_pool_allocated_size(cor_pool_t *pool);
void *cor_pool_alloc(cor_pool_t *pool, size_t size);
void *cor_pool_calloc(cor_pool_t *pool, size_t size);
void cor_pool_free(cor_pool_t *pool, void *m);
void cor_pool_delete(cor_pool_t *pool);

#endif
