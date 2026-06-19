#ifndef LANCET_DANGLING_HPP
#define LANCET_DANGLING_HPP

#include "pin.H"
#include <map>
#include <queue>

class DanglingPtrManager {
public:
    DanglingPtrManager() {}
    ~DanglingPtrManager() {}

    void addDanglingPtr(ADDRINT store_addr, ADDRINT ptr_value, size_t pc_idx);
    bool isExpiredPtr(ADDRINT store_addr, ADDRINT ptr_value);
    size_t getFirstDanglingIdx(ADDRINT key);
    bool hasDanglingRecord(ADDRINT key);

private:
    // Maps a store address → queue of pc indices where dangling writes occurred
    std::map<ADDRINT, std::queue<size_t>> dangling_idx_;
    // Maps a store address → the dangling pointer value stored there
    std::map<ADDRINT, ADDRINT> dangling_ptr_;
};

#endif
