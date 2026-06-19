#ifndef LANCET_CONFIG_HPP
#define LANCET_CONFIG_HPP

#include <string>
#include <vector>

struct LancetConfig {
    bool no_log;
    bool no_reasoning;
    bool no_heap_analysis;
    bool debug_output;
    std::string target_lib;
    std::vector<std::string> skip_funcs;
    std::string log_dir;
    // Custom allocator function names (for programs with their own allocators)
    std::string alloc_func;   // default: "malloc"
    std::string free_func;    // default: "free"
    std::string calloc_func;  // default: "calloc"
    std::string realloc_func; // default: "realloc"
    int alloc_size_arg;       // which arg is size (0 for malloc, 1 for pool allocators)
    int free_addr_arg;        // which arg is address to free (0 for free, 1 for pool free)
};

extern LancetConfig gConfig;

#endif
