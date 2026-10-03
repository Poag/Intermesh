#include <cstddef>
#include <cstdint>
#include <cstring>
class RNGClass { public: void rand(uint8_t *d, size_t n); };
RNGClass CryptRNG;
void RNGClass::rand(uint8_t *d, size_t n) { memset(d, 0x5a, n); }
