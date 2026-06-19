#ifndef LANCET_OWNERSHIP_HPP
#define LANCET_OWNERSHIP_HPP

#include "pin.H"
#include <cstdint>
#include <map>
#include <unordered_map>
#include <vector>
#include <string>

#define HEAP_SUBJECT_ID       0
#define STACK_SUBJECT_ID      1
#define USER_WRITE_UNKNOWN   -3  // vo: user code wrote here but register pointee was lost

struct Subject {
    int64_t id;
    ADDRINT base;
    size_t size;
    Subject() : id(-1), base(0), size(0) {}
    Subject(int64_t id, ADDRINT base, size_t size) : id(id), base(base), size(size) {}
};

enum FreeResult { FREE_OK, FREE_NOT_FOUND, FREE_DOUBLE_FREE };

struct FieldLayout {
    std::string name;
    size_t offset;
    size_t size;
    bool is_pointer;
};

struct StructLayout {
    std::string name;
    size_t total_size;
    std::vector<FieldLayout> fields;
};

#include "log.hpp"

class Ownership {
public:
    Ownership();
    ~Ownership();
    void set_logger(Logger* log) { logger_for_overlap_ = log; }

    void init_regs(CONTEXT* ctx);
    void set_regions(ADDRINT stack_lo, ADDRINT stack_hi, ADDRINT heap_start, ADDRINT heap_end);

    // Cell ownership: who owns this memory cell (allocation-level)
    int64_t alloc_new_subject(ADDRINT base, size_t user_size);
    FreeResult free_subject(ADDRINT base);
    int64_t get_cell_owner(ADDRINT addr);
    const Subject* find_subject(ADDRINT addr);

    // Value ownership: whose pointer is stored at this address
    void update_value_owner(ADDRINT addr, int64_t owner_id);
    int64_t get_value_owner(ADDRINT addr);

    // Register pointee: which subject does the register reference
    void assign_reg_pointee(REG r, ADDRINT addr);
    void assign_reg_pointee_id(REG r, int64_t id);
    void dup_reg_pointee(REG dst, REG src);
    int64_t get_reg_pointee(REG r);
    void correct_reg_id(REG r, CONTEXT* ctx);

    // Debug
    void print_common_reg_pointee(std::string prefix);

    // Struct layout: load field-level definitions for sub-subject splitting
    bool load_struct_layouts(const std::string& path);
    size_t struct_layout_count() const { return struct_layouts_.size(); }

    // Subject lookup
    std::unordered_map<int64_t, Subject>* get_subject_map() { return &id2subject_; }
    ADDRINT get_stack_lo() const { return stack_lo_; }
    ADDRINT get_stack_hi() const { return stack_hi_; }

    Logger* logger_for_overlap_ = nullptr;

private:
    const StructLayout* find_struct_by_size(size_t alloc_size) const;
    // Range-based cell ownership: sorted by base address
    std::map<ADDRINT, Subject> cell_regions_;

    // Value ownership: sparse map for written addresses
    std::unordered_map<ADDRINT, int64_t> value_owners_;

    // Register pointee tracking: single ID per register
    std::unordered_map<REG, int64_t, std::hash<int>> reg_pointee_;

    // Subject ID → Subject metadata
    std::unordered_map<int64_t, Subject> id2subject_;

    // Recently-freed regions: when a region is freed then immediately reallocated,
    // the freed status is lost in range-based tracking. This shadow preserves it
    // so CROSSBOUNDARY from old subject → freed can still be detected.
    struct FreedRegion { ADDRINT base; size_t size; };
    std::vector<FreedRegion> recently_freed_;

    int64_t next_subject_id_;

    ADDRINT stack_lo_, stack_hi_;
    ADDRINT heap_start_, heap_end_;

    // Struct layouts for field-level sub-subject splitting (Approach A)
    std::vector<StructLayout> struct_layouts_;
    // Size → index into struct_layouts_ for fast lookup (only unique sizes)
    std::unordered_map<size_t, size_t> size_to_layout_;
};

#endif
