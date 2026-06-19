#ifndef LANCET_ALLOCATION_HPP
#define LANCET_ALLOCATION_HPP

#include "common.hpp"
#include "ownership.hpp"
#include "log.hpp"
#include <map>
#include <utility>

#define HEAP_FREE  0
#define HEAP_INUSE 1

class AllocationManager {
public:
    AllocationManager(Ownership* owner, Logger* log = nullptr);
    ~AllocationManager();

    VOID MallocBefore(ADDRINT size);
    VOID MallocAfter(ADDRINT ret, ADDRINT caller = 0);
    VOID CallocBefore(ADDRINT nmemb, ADDRINT size);
    VOID CallocAfter(ADDRINT ret, ADDRINT caller = 0);
    VOID ReallocBefore(ADDRINT ptr, ADDRINT size);
    VOID ReallocAfter(ADDRINT ret, ADDRINT caller = 0);
    VOID FreeBefore(ADDRINT ptr, ADDRINT caller = 0);
    VOID FreeAfter();
    VOID SetContext(CONTEXT* ctx) { ctxt_ = ctx; }

private:
    Ownership* ownership_;
    Logger* logger_;
    std::map<ADDRINT, std::pair<int, size_t>> alloc_map_;
    size_t pending_malloc_size_;
    size_t pending_calloc_size_;
    size_t pending_realloc_size_;
    ADDRINT pending_realloc_old_ptr_;
    ADDRINT pending_free_ptr_;
    CONTEXT* ctxt_;
};

#endif
