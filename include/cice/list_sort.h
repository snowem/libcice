#ifndef _LINUX_LIST_SORT_H
#define _LINUX_LIST_SORT_H
 
#ifdef __cplusplus
extern "C" {
#endif

#include "list.h"

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(*(x)))
  
struct list_head;
void list_sort(void *priv, struct list_head *head,
               int (*cmp)(void *priv, struct list_head *a,
                           struct list_head *b));

#ifdef __cplusplus
}
#endif

#endif
 
