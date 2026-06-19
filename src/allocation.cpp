#include "allocation.hpp"
#include "config.hpp"
#include <iostream>

AllocationManager::AllocationManager(Ownership* owner, Logger* log)
    : ownership_(owner)
    , logger_(log)
    , pending_malloc_size_(0)
    , pending_calloc_size_(0)
    , pending_realloc_size_(0)
    , pending_realloc_old_ptr_(0)
    , pending_free_ptr_(0)
    , ctxt_(nullptr)
{}

AllocationManager::~AllocationManager() {}

VOID AllocationManager::MallocBefore(ADDRINT size) {
    pending_malloc_size_ = size;
}

VOID AllocationManager::MallocAfter(ADDRINT ret, ADDRINT caller) {
    if (gConfig.debug_output)
        std::cout << "malloc(0x" << std::hex << pending_malloc_size_ << ") -> " << toHex(ret) << std::endl;

    // TAINT check: returned chunk's fd was UAF-written by user code.
    // Only fire on USER_WRITE_UNKNOWN — this marker is exclusively set in
    // rulesMovWrite/rulesMovWriteImm when writing to freed memory (co == HEAP_SUBJECT_ID)
    // with a lost register pointee. Normal alloc→write→free→realloc cycles produce
    // fd_vo == HEAP_SUBJECT_ID (from FreeBefore pre-mark) or stale subject IDs
    // (from bulk-set) — neither should trigger TAINT.
    // MUST be BEFORE alloc_new_subject() + bulk-set which overwrite vo.
    if (ret && ownership_ && logger_) {
        int64_t fd_vo = ownership_->get_value_owner(ret);
        if (fd_vo == USER_WRITE_UNKNOWN) {
            logger_->log("[HEAP METADATA TAINT] malloc(", toHex(pending_malloc_size_),
                ") -> ", toHex(ret),
                ": fd at ", toHex(ret),
                " has vo=", fd_vo, " (UAF write poisoned free-list)\n");
        }
    }

    int64_t id = ownership_->alloc_new_subject(ret, pending_malloc_size_);
    ownership_->assign_reg_pointee_id(REG_RAX, id);
    alloc_map_[ret] = std::make_pair(HEAP_INUSE, pending_malloc_size_);

    // Log allocation with caller source location
    // [EXPERIMENTAL] Tag libc-internal allocations as [ALLOC:internal]
    if (logger_ && caller) {
        std::string loc;
        INT32 col = 0, line = 0;
        std::string fname, func;
        PIN_LockClient();
        PIN_GetSourceLocation(caller - 1, &col, &line, &fname);
        RTN rtn = RTN_FindByAddress(caller - 1);
        if (RTN_Valid(rtn)) func = RTN_Name(rtn);
        PIN_UnlockClient();
        if (line > 0 || !func.empty()) {
            auto slash = fname.rfind('/');
            if (slash != std::string::npos) fname = fname.substr(slash + 1);
            loc = func.empty() ? "" : func;
            if (line > 0 && !fname.empty()) {
                if (!loc.empty()) loc += " @ ";
                loc += fname + ":" + std::to_string(line);
            }
        }
        // Caller outside main/target_lib → libc-internal allocation
        bool is_internal = (line == 0 && fname.empty());
        const char* tag = is_internal ? "[ALLOC:internal]" : "[ALLOC]";
        logger_->log(tag, " malloc(", toHex(pending_malloc_size_),
            ") -> ", toHex(ret), " subject=", id,
            loc.empty() ? "" : " at ", loc, "\n");
    }

    size_t slots = (pending_malloc_size_ + 7) / 8;
    if (slots <= 0x20000) {
        for (size_t i = 0; i < slots; i++)
            ownership_->update_value_owner(ret + i * 8, id);
    }
}

VOID AllocationManager::CallocBefore(ADDRINT nmemb, ADDRINT size) {
    pending_calloc_size_ = nmemb * size;
}

VOID AllocationManager::CallocAfter(ADDRINT ret, ADDRINT caller) {
    if (gConfig.debug_output)
        std::cout << "calloc(0x" << std::hex << pending_calloc_size_ << ") -> " << toHex(ret) << std::endl;
    int64_t id = ownership_->alloc_new_subject(ret, pending_calloc_size_);
    ownership_->assign_reg_pointee_id(REG_RAX, id);
    alloc_map_[ret] = std::make_pair(HEAP_INUSE, pending_calloc_size_);

    if (logger_ && caller) {
        std::string loc;
        INT32 col = 0, line = 0; std::string fname, func;
        PIN_LockClient();
        PIN_GetSourceLocation(caller - 1, &col, &line, &fname);
        RTN rtn = RTN_FindByAddress(caller - 1);
        if (RTN_Valid(rtn)) func = RTN_Name(rtn);
        PIN_UnlockClient();
        if (line > 0 || !func.empty()) {
            auto slash = fname.rfind('/'); if (slash != std::string::npos) fname = fname.substr(slash + 1);
            loc = func; if (line > 0 && !fname.empty()) { if (!loc.empty()) loc += " @ "; loc += fname + ":" + std::to_string(line); }
        }
        bool is_internal_c = (line == 0 && fname.empty());
        const char* tag_c = is_internal_c ? "[ALLOC:internal]" : "[ALLOC]";
        logger_->log(tag_c, " calloc(", toHex(pending_calloc_size_), ") -> ", toHex(ret), " subject=", id, loc.empty() ? "" : " at ", loc, "\n");
    }
    size_t slots = (pending_calloc_size_ + 7) / 8;
    if (slots <= 0x20000) {  // 1MB cap
        for (size_t i = 0; i < slots; i++)
            ownership_->update_value_owner(ret + i * 8, id);
    }
}

VOID AllocationManager::ReallocBefore(ADDRINT ptr, ADDRINT size) {
    // BUG-4 fix: validate current ptr, not stale pending_realloc_old_ptr_
    if (ptr) {
        auto it = alloc_map_.find(ptr);
        if (it == alloc_map_.end()) {
            if (gConfig.debug_output)
                std::cout << "realloc: ptr " << toHex(ptr) << " not in alloc map" << std::endl;
        }
    }
    pending_realloc_old_ptr_ = ptr;
    pending_realloc_size_ = size;
}

VOID AllocationManager::ReallocAfter(ADDRINT ret, ADDRINT caller) {
    if (gConfig.debug_output)
        std::cout << "realloc(0x" << std::hex << pending_realloc_size_
                  << ") " << toHex(pending_realloc_old_ptr_) << " -> " << toHex(ret) << std::endl;

    if (!ret) return; // realloc failed

    // BUG-5 fix: distinguish in-place vs new allocation
    if (pending_realloc_old_ptr_ != 0 && ret != pending_realloc_old_ptr_) {
        // New allocation: free old, create new
        ownership_->free_subject(pending_realloc_old_ptr_);
        alloc_map_.erase(pending_realloc_old_ptr_);
    } else if (pending_realloc_old_ptr_ != 0 && ret == pending_realloc_old_ptr_) {
        // In-place: update the existing subject's size
        // Free old and re-create with new size
        ownership_->free_subject(pending_realloc_old_ptr_);
    }
    // realloc(NULL, size) is equivalent to malloc(size) - just create new
    int64_t id = ownership_->alloc_new_subject(ret, pending_realloc_size_);
    ownership_->assign_reg_pointee_id(REG_RAX, id);
    alloc_map_[ret] = std::make_pair(HEAP_INUSE, pending_realloc_size_);
}

VOID AllocationManager::FreeBefore(ADDRINT ptr, ADDRINT caller) {
    if (gConfig.debug_output)
        std::cout << "free(" << toHex(ptr) << ")" << std::endl;

    // TAINT check: chunk size field (ptr-8) should be allocator-owned.
    // Only fire when the header is in the allocator's domain (co == HEAP_SUBJECT_ID
    // or co == -1) AND a user subject wrote there. This excludes adjacent-allocation
    // padding overlap where the header is inside another live allocation's region.
    // MUST be BEFORE free_subject() which changes cell_owner.
    if (ptr && ownership_ && logger_) {
        int64_t size_vo = ownership_->get_value_owner(ptr - 8);
        int64_t header_co = ownership_->get_cell_owner(ptr - 8);
        if ((size_vo >= STACK_SUBJECT_ID || size_vo == USER_WRITE_UNKNOWN) &&
            (header_co == HEAP_SUBJECT_ID || header_co == -1)) {
            logger_->log("[HEAP METADATA TAINT] free(", toHex(ptr),
                "): chunk size at ", toHex(ptr - 8),
                " has vo=", size_vo, " co=", header_co, " (cross-subject taint)\n");
        }

        // Clear value_owners for the freed region so malloc's TAINT check
        // can distinguish "old allocation data" from "user UAF write".
        // Then pre-mark fd (ptr+0) and bk (ptr+8) as HEAP_SUBJECT_ID to
        // model ptmalloc's invisible libc writes when inserting into free-list.
        // Use the subject from ownership (not alloc_map_ which may be stale).
        const Subject* subj = ownership_->find_subject(ptr);
        if (subj && subj->id != HEAP_SUBJECT_ID) {
            size_t sz = subj->size;
            size_t slots = (sz + 7) / 8;
            if (slots <= 0x20000) {
                for (size_t i = 0; i < slots; i++)
                    ownership_->update_value_owner(ptr + i * 8, -1);
            }
        }
        ownership_->update_value_owner(ptr, HEAP_SUBJECT_ID);      // fd
        ownership_->update_value_owner(ptr + 8, HEAP_SUBJECT_ID);  // bk
    }

    // Log free with caller source location
    if (logger_ && caller && ptr) {
        const Subject* fsubj = ownership_->find_subject(ptr);
        int64_t fid = fsubj ? fsubj->id : -1;
        std::string loc;
        INT32 col = 0, line = 0; std::string fname, func;
        PIN_LockClient();
        PIN_GetSourceLocation(caller - 1, &col, &line, &fname);
        RTN rtn = RTN_FindByAddress(caller - 1);
        if (RTN_Valid(rtn)) func = RTN_Name(rtn);
        PIN_UnlockClient();
        if (line > 0 || !func.empty()) {
            auto slash = fname.rfind('/'); if (slash != std::string::npos) fname = fname.substr(slash + 1);
            loc = func; if (line > 0 && !fname.empty()) { if (!loc.empty()) loc += " @ "; loc += fname + ":" + std::to_string(line); }
        }
        bool is_internal_f = (line == 0 && fname.empty());
        const char* tag_f = is_internal_f ? "[FREE:internal]" : "[FREE]";
        logger_->log(tag_f, " free(", toHex(ptr), ") subject=", fid, loc.empty() ? "" : " at ", loc, "\n");
    }

    pending_free_ptr_ = ptr;
    FreeResult res = ownership_->free_subject(pending_free_ptr_);
    if (res == FREE_DOUBLE_FREE && logger_) {
        logger_->log("[DOUBLE FREE] free(", toHex(ptr), ") — already freed\n");
    } else if (res == FREE_NOT_FOUND && ptr != 0) {
        if (logger_)
            logger_->log("[INVALID FREE] free(", toHex(ptr), ") — not in allocation map\n");
    }
    // RDI held the pointer to free'd memory — mark its pointee as heap (dangling)
    ownership_->assign_reg_pointee_id(REG_RDI, HEAP_SUBJECT_ID);
}

VOID AllocationManager::FreeAfter() {
    alloc_map_.erase(pending_free_ptr_);
}
