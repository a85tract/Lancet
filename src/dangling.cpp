#include "dangling.hpp"

// BUG-1 fix: use consistent key (store_addr) for both maps
void DanglingPtrManager::addDanglingPtr(ADDRINT store_addr, ADDRINT ptr_value, size_t pc_idx) {
    auto it = dangling_idx_.find(store_addr);
    if (it == dangling_idx_.end()) {
        std::queue<size_t> q;
        q.push(pc_idx);
        dangling_idx_[store_addr] = q;
    } else {
        it->second.push(pc_idx);
    }
    dangling_ptr_[store_addr] = ptr_value;
}

bool DanglingPtrManager::isExpiredPtr(ADDRINT store_addr, ADDRINT ptr_value) {
    auto it = dangling_ptr_.find(store_addr);
    if (it != dangling_ptr_.end()) {
        return it->second == ptr_value;
    }
    return false;
}

size_t DanglingPtrManager::getFirstDanglingIdx(ADDRINT key) {
    auto it = dangling_idx_.find(key);
    if (it != dangling_idx_.end() && !it->second.empty()) {
        return it->second.front();
    }
    return 0;
}

bool DanglingPtrManager::hasDanglingRecord(ADDRINT key) {
    auto it = dangling_idx_.find(key);
    return it != dangling_idx_.end() && !it->second.empty();
}
