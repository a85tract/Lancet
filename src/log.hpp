#ifndef LANCET_LOG_HPP
#define LANCET_LOG_HPP

#include <fstream>
#include <sstream>
#include <iostream>
#include <string>

namespace detail {
template<typename T>
std::string stringify(const T& value) {
    std::stringstream ss;
    ss << value;
    return ss.str();
}

inline std::string concat_impl() { return ""; }

template<typename T, typename... Args>
std::string concat_impl(const T& first, const Args&... args) {
    return stringify(first) + concat_impl(args...);
}
} // namespace detail

class Logger {
public:
    Logger(const std::string& filename, bool enabled)
        : enabled_(enabled)
    {
        if (enabled_) {
            file_.open(filename);
            if (!file_.is_open())
                std::cerr << "Failed to open log: " << filename << std::endl;
        }
    }

    ~Logger() {
        flush();
        if (file_.is_open()) file_.close();
    }

    template<typename... Args>
    void log(const Args&... args) {
        if (!enabled_) return;
        buffer_ << detail::concat_impl(args...);
        // Flush frequently to survive abort()/SIGKILL from target process
        if (static_cast<size_t>(buffer_.tellp()) >= BUFFER_LIMIT) flush();
    }

    void flush() {
        if (file_.is_open() && buffer_.tellp() > 0) {
            file_ << buffer_.str();
            file_.flush();
            buffer_.str("");
        }
    }

private:
    bool enabled_;
    std::ofstream file_;
    std::ostringstream buffer_;
    static constexpr size_t BUFFER_LIMIT = 256 * 1024; // 256KB — flush often to survive crashes
};

#endif
