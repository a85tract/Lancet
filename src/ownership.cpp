#include "ownership.hpp"
#include "common.hpp"
#include <cstdint>
#include <iostream>
#include <fstream>
#include <unordered_set>
#include <sstream>

Ownership::Ownership()
    : next_subject_id_(2) // 0=heap, 1=stack, 2+ = user allocations
    , stack_lo_(0), stack_hi_(0)
    , heap_start_(0), heap_end_(0)
{
    id2subject_[HEAP_SUBJECT_ID] = Subject(HEAP_SUBJECT_ID, 0, 0);
    std::cout << GREEN << "[lancet] Ownership tracker initialized (range-based)" << RESET << std::endl;
}

Ownership::~Ownership() {}

void Ownership::init_regs(CONTEXT* ctx) {
    static const REG common_regs[] = {
        REG_RAX, REG_RBX, REG_RCX, REG_RDX,
        REG_RSI, REG_RDI, REG_RBP, REG_RSP,
        REG_R8,  REG_R9,  REG_R10, REG_R11,
        REG_R12, REG_R13, REG_R14, REG_R15,
        REG_RIP
    };
    for (auto reg : common_regs) {
        reg_pointee_[reg] = -1;
    }
}

void Ownership::set_regions(ADDRINT stack_lo, ADDRINT stack_hi,
                            ADDRINT heap_start, ADDRINT heap_end) {
    stack_lo_ = stack_lo;
    stack_hi_ = stack_hi;
    heap_start_ = heap_start;
    heap_end_ = heap_end;
}

int64_t Ownership::alloc_new_subject(ADDRINT base, size_t user_size) {
    // Subject covers exactly the user-requested size, NOT padded with
    // ptmalloc header. Writing past user_size into chunk metadata (prev_size,
    // size field) should be detected as CROSSBOUNDARY/INTRA_OBJECT_OVERFLOW.
    // Align to 8 for value_owner tracking granularity.
    size_t aligned = (user_size + 0x7) & ~0x7ULL;

    // Check for overlapping allocation: does [base, base+aligned) overlap
    // any LIVE subject? Scan all subjects in the range.
    ADDRINT end = base + aligned;
    for (auto it = cell_regions_.lower_bound(base); it != cell_regions_.end() && it->first < end; ++it) {
        // [EXPERIMENTAL] Heap chunk overlap detection.
        // Only fires for heap allocations (below stack, above heap_start) where
        // a new allocation partially covers an existing LIVE subject at a
        // DIFFERENT base address (same-base = realloc/reuse, not overlap).
        // Deduped per address pair to limit noise from ptmalloc reuse patterns.
        if (it->second.id > STACK_SUBJECT_ID && it->first != base &&
            base < stack_lo_ && it->first >= heap_start_ &&
            base + aligned > it->first) {  // must actually overlap, not just adjacent
            static std::unordered_set<uint64_t> reported;
            uint64_t key = ((uint64_t)base << 32) ^ it->first;
            if (reported.find(key) == reported.end()) {
                reported.insert(key);
                if (logger_for_overlap_)
                    logger_for_overlap_->log("[OVERLAP] new alloc [", toHex(base), ", ", toHex(end),
                        ") overlaps live subject ", it->second.id,
                        " [", toHex(it->first), ", ", toHex(it->first + it->second.size), ")\n");
            }
        }
    }

    // Approach A: if a struct layout matches this allocation size, split into
    // per-field sub-subjects so intra-struct overflow triggers CROSSBOUNDARY.
    const StructLayout* layout = find_struct_by_size(user_size);
    if (layout && layout->fields.size() >= 2) {
        int64_t first_id = next_subject_id_;
        for (size_t i = 0; i < layout->fields.size(); i++) {
            const auto& f = layout->fields[i];
            int64_t fid = next_subject_id_++;
            Subject fsub(fid, base + f.offset, f.size);
            cell_regions_[base + f.offset] = fsub;
            id2subject_[fid] = fsub;
        }
        std::cout << GREEN << "[lancet] struct split: " << layout->name
                  << " at " << toHex(base) << " → " << layout->fields.size()
                  << " sub-subjects (" << first_id << "-" << (next_subject_id_ - 1)
                  << ")" << RESET << std::endl;
        return first_id;
    }

    int64_t id = next_subject_id_++;
    Subject subj(id, base, aligned);
    cell_regions_[base] = subj;
    id2subject_[id] = subj;
    return id;
}

FreeResult Ownership::free_subject(ADDRINT base) {
    if (!base) return FREE_NOT_FOUND;

    auto it = cell_regions_.find(base);
    if (it == cell_regions_.end()) {
        return FREE_NOT_FOUND;
    }

    if (it->second.id == HEAP_SUBJECT_ID) {
        std::cout << "[lancet] error: double free detected at " << toHex(base) << std::endl;
        return FREE_DOUBLE_FREE;
    }

    // Record in recently-freed shadow before overwriting
    recently_freed_.push_back({it->first, it->second.size});
    // Cap size to prevent unbounded growth
    if (recently_freed_.size() > 4096)
        recently_freed_.erase(recently_freed_.begin(), recently_freed_.begin() + 2048);

    // Mark region as freed (heap-owned)
    int64_t old_id = it->second.id;
    it->second.id = HEAP_SUBJECT_ID;

    // For struct-split allocations: free all sub-subjects with consecutive IDs
    // that follow this one in the address space.
    if (!struct_layouts_.empty()) {
        auto scan = it;
        ++scan;
        int64_t expect_id = old_id + 1;
        while (scan != cell_regions_.end() && scan->second.id == expect_id) {
            recently_freed_.push_back({scan->first, scan->second.size});
            scan->second.id = HEAP_SUBJECT_ID;
            expect_id++;
            ++scan;
        }
    }

    return FREE_OK;
}

int64_t Ownership::get_cell_owner(ADDRINT addr) {
    // Range lookup: find allocation containing addr
    auto it = cell_regions_.upper_bound(addr);
    if (it != cell_regions_.begin()) {
        --it;
        if (addr >= it->first && addr < it->first + it->second.size) {
            int64_t id = it->second.id;
            // If the current subject is alive but this address was recently freed,
            // report as freed (HEAP_SUBJECT_ID). This catches the case where a
            // freed buffer is immediately reallocated — the range-based map shows
            // the new subject, but the address still belongs to a freed region.
            if (id > STACK_SUBJECT_ID) {
                for (auto rit = recently_freed_.rbegin(); rit != recently_freed_.rend(); ++rit) {
                    if (addr >= rit->base && addr < rit->base + rit->size) {
                        // Only report as freed if the current subject was created AFTER the free
                        // (i.e., the current subject ID is higher than the freed region's original)
                        if (it->second.base != rit->base) {
                            // Different base → the current allocation is a new one that overlaps
                            // the freed region → the address IS still freed from the old allocation
                            return HEAP_SUBJECT_ID;
                        }
                        break;
                    }
                }
            }
            return id;
        }
    }

    // Check recently-freed regions for addresses outside current allocations
    for (auto rit = recently_freed_.rbegin(); rit != recently_freed_.rend(); ++rit) {
        if (addr >= rit->base && addr < rit->base + rit->size) {
            return HEAP_SUBJECT_ID;
        }
    }

    // Stack check
    if (stack_lo_ != 0 && addr >= stack_lo_ && addr <= stack_hi_) {
        return STACK_SUBJECT_ID;
    }

    return -1; // unknown
}

const Subject* Ownership::find_subject(ADDRINT addr) {
    auto it = cell_regions_.upper_bound(addr);
    if (it != cell_regions_.begin()) {
        --it;
        if (addr >= it->first && addr < it->first + it->second.size) {
            return &it->second;
        }
    }
    return nullptr;
}

void Ownership::update_value_owner(ADDRINT addr, int64_t owner_id) {
    value_owners_[addr] = owner_id;
}

int64_t Ownership::get_value_owner(ADDRINT addr) {
    auto it = value_owners_.find(addr);
    if (it != value_owners_.end()) return it->second;
    // Fall back to 8-byte-aligned lookup: bulk-set in MallocAfter/CallocAfter
    // populates at 8-byte granularity, but reads can hit any offset within a slot.
    ADDRINT aligned = addr & ~0x7ULL;
    if (aligned != addr) {
        it = value_owners_.find(aligned);
        if (it != value_owners_.end()) return it->second;
    }
    return -1;
}

void Ownership::assign_reg_pointee(REG r, ADDRINT addr) {
    reg_pointee_[r] = get_cell_owner(addr);
}

void Ownership::assign_reg_pointee_id(REG r, int64_t id) {
    reg_pointee_[r] = id;
}

void Ownership::dup_reg_pointee(REG dst, REG src) {
    auto it = reg_pointee_.find(src);
    reg_pointee_[dst] = (it != reg_pointee_.end()) ? it->second : -1;
}

int64_t Ownership::get_reg_pointee(REG r) {
    auto it = reg_pointee_.find(r);
    return (it != reg_pointee_.end()) ? it->second : -1;
}

void Ownership::correct_reg_id(REG r, CONTEXT* ctx) {
    ADDRINT val = PIN_GetContextReg(ctx, r);
    assign_reg_pointee(r, val);
}

void Ownership::print_common_reg_pointee(std::string prefix) {
    static const REG common_regs[] = {
        REG_RAX, REG_RBX, REG_RCX, REG_RDX,
        REG_RSI, REG_RDI, REG_RBP, REG_RSP,
        REG_R8, REG_R9, REG_R10, REG_R11,
        REG_R12, REG_R13, REG_R14, REG_R15
    };
    std::string output = prefix;
    size_t orig = output.size();
    for (auto reg : common_regs) {
        auto it = reg_pointee_.find(reg);
        if (it == reg_pointee_.end()) continue;
        int64_t id = it->second;
        output += REG_StringShort(reg) + ": ";
        if (id == 0) output += "(heap) ";
        else if (id == -1) output += "-1 ";
        else output += "(" + std::to_string(id) + ") ";
    }
    if (output.size() != orig)
        std::cout << output << std::endl;
}

bool Ownership::load_struct_layouts(const std::string& path) {
    std::ifstream file(path.c_str());
    if (!file.is_open()) {
        std::cout << YELLOW << "[lancet] warning: cannot open struct layout file: "
                  << path << RESET << std::endl;
        return false;
    }

    StructLayout* current = nullptr;
    std::string line;
    while (std::getline(file, line)) {
        if (line.empty() || line[0] == '#') continue;

        if (line.substr(0, 7) == "struct ") {
            // "struct <name> <size>"
            std::istringstream iss(line.substr(7));
            struct_layouts_.push_back(StructLayout());
            current = &struct_layouts_.back();
            iss >> current->name >> current->total_size;
        } else if (current && (line[0] == ' ' || line[0] == '\t')) {
            // "  <field_name> <offset> <size> <is_pointer>"
            std::istringstream iss(line);
            FieldLayout f;
            int ptr_flag = 0;
            iss >> f.name >> f.offset >> f.size >> ptr_flag;
            f.is_pointer = (ptr_flag != 0);
            current->fields.push_back(f);
        }
    }

    // Build size→layout index (only for unique sizes)
    std::unordered_map<size_t, int> size_count;
    for (size_t i = 0; i < struct_layouts_.size(); i++)
        size_count[struct_layouts_[i].total_size]++;
    for (size_t i = 0; i < struct_layouts_.size(); i++) {
        size_t sz = struct_layouts_[i].total_size;
        if (size_count[sz] == 1)
            size_to_layout_[sz] = i;
    }

    std::cout << GREEN << "[lancet] Loaded " << struct_layouts_.size()
              << " struct layouts (" << size_to_layout_.size() << " unique-size)"
              << RESET << std::endl;
    for (const auto& s : struct_layouts_) {
        std::cout << GREEN << "  " << s.name << ": " << s.total_size << "B, "
                  << s.fields.size() << " fields" << RESET << std::endl;
    }
    return true;
}

const StructLayout* Ownership::find_struct_by_size(size_t alloc_size) const {
    auto it = size_to_layout_.find(alloc_size);
    if (it != size_to_layout_.end())
        return &struct_layouts_[it->second];
    return nullptr;
}
