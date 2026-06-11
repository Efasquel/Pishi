/*
 * build: clang -o kaslr kaslr.c
 * run:   sudo ./kaslr
 *        sudo ./kaslr /path/to/BootKernelExtensions.kc   # also compute the slide
 *
 * Reads the KASLR-slid runtime address of sanitizer_cov_trace_pc from Pishi's
 * kext via PISHI_IOCTL_KASLR. When given the path to the Boot Kernel Collection
 * (BKC), it extracts the symbol's static (unslid) address with nm and prints
 * the resulting kernel slide.
 */

#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define DEVICE_NAME       "/dev/pishi"
#define PISHI_IOCTL_KASLR _IOR('K', 60, uint64_t)
#define SYMBOL            "_sanitizer_cov_trace_pc"

/*
 * On arm64e the kext returns a PAC-signed function pointer: the upper bits hold
 * the signature, the real VA lives in bits 47:0. Drop the signature and
 * sign-extend bit 47 to rebuild the canonical kernel address.
 */
static uint64_t strip_pac(uint64_t ptr)
{
    uint64_t va = ptr & 0x0000ffffffffffffULL;
    if (va & (1ULL << 47))
        va |= 0xffff000000000000ULL;
    return va;
}

/*
 * Run `nm` on the BKC and parse the static address of SYMBOL. nm prints lines
 * of the form "<hex addr> T _sanitizer_cov_trace_pc"; we read the first token
 * of the matching line. Returns 0 and sets *out on success, -1 on failure.
 */
static int static_addr_from_bkc(const char *bkc, uint64_t *out)
{
    char cmd[4096];
    int n = snprintf(cmd, sizeof(cmd),
                     "nm '%s' 2>/dev/null | grep ' %s$'", bkc, SYMBOL);
    if (n < 0 || (size_t)n >= sizeof(cmd)) {
        fprintf(stderr, "BKC path too long\n");
        return -1;
    }

    FILE *p = popen(cmd, "r");
    if (p == NULL) {
        perror("popen nm");
        return -1;
    }

    char line[256];
    int found = -1;
    if (fgets(line, sizeof(line), p) != NULL) {
        *out = strtoull(line, NULL, 16);
        found = 0;
    }
    pclose(p);

    if (found != 0)
        fprintf(stderr, "%s not found in %s\n", SYMBOL, bkc);
    return found;
}

int main(int argc, char **argv)
{
    int fd = open(DEVICE_NAME, O_RDWR);
    if (fd == -1) {
        perror("open " DEVICE_NAME);
        return 1;
    }

    uint64_t addr = 0;
    if (ioctl(fd, PISHI_IOCTL_KASLR, &addr) == -1) {
        perror("ioctl PISHI_IOCTL_KASLR");
        close(fd);
        return 1;
    }

    close(fd);
    addr = strip_pac(addr);
    printf("%s runtime address: 0x%llx\n", SYMBOL, addr);

    if (argc > 1) {
        uint64_t unslid = 0;
        if (static_addr_from_bkc(argv[1], &unslid) != 0)
            return 1;
        printf("%s static address:  0x%llx\n", SYMBOL, unslid);
        printf("kernel slide: 0x%llx\n", addr - unslid);
    }

    return 0;
}
