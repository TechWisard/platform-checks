#include <cstdio>
#include <cstring>

int main(int argc, char** argv) {
    if (argc == 2 && std::strcmp(argv[1], "--version") == 0) {
        std::fputs("Runtime fixture 1\n", stdout); return 0;
    }
    if (argc == 2 && std::strcmp(argv[1], "--help") == 0) {
        std::fputs("Runtime fixture usage\n", stdout); return 0;
    }
    std::fputs("Unsupported fixture argument.\n", stderr); return 64;
}
