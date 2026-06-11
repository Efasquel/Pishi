/*
 * build: make pishi_check
 *        (or: clang -O2 -framework IOKit -framework CoreFoundation \
 *               -o pishi_check pishi_check.c)
 * run:   sudo ./pishi_check                                  # synthetic self-check
 *        sudo ./pishi_check -k 0x1 -s AppleJPEGDriver -t 0   # real IOKit test case
 *
 * Health check for Pishi.kext. It verifies the coverage pipeline end-to-end:
 *   1. /dev/pishi is present and openable      -> the kext is loaded and reachable
 *   2. PISHI_IOCTL_MAP returns a shared buffer -> coverage memory can be mapped
 *   3. coverage is recorded into that buffer    -> the sanitizer path is active
 *
 * Two ways to drive step 3:
 *
 *   synthetic (default): PISHI_IOCTL_TEST makes the kext call
 *     sanitizer_cov_trace_pc() itself (PC 0x4141). Deterministic and independent
 *     of any target kext, good for confirming the plumbing works.
 *
 *   real (-s <service>): open the target kext's IOKit user client and issue an
 *     IOConnectCallMethod sequence while Pishi records. This confirms coverage
 *     actually fires for a real driver interaction. You tell Pishi which kext to
 *     watch with -k (the kext_id bitmask from kext.h), and tell IOServiceOpen
 *     which user client to create with -s (service name) and -t (user client type).
 *     A non-zero kcov_pos afterwards means coverage was activated for that kext.
 */

#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <IOKit/IOKitLib.h>
#include <mach/mach.h>

#define DEVICE_NAME       "/dev/pishi"
#define PISHI_IOCTL_MAP   _IOWR('K', 8, struct pishi_buf_desc)
#define PISHI_IOCTL_START _IOW('K', 10, uint16_t)
#define PISHI_IOCTL_STOP  _IO('K', 20)
#define PISHI_IOCTL_UNMAP _IO('K', 30)
#define PISHI_IOCTL_TEST  _IO('K', 40)

#define MAX_SCALARS       16

struct pishi_buf_desc {
    uintptr_t ptr; /* ptr to shared coverage buffer [out] */
    size_t    sz;  /* size of shared buffer          [out] */
};

/* Mirror of struct kcov in the kext: a position counter followed by PCs. */
struct pishi_cov {
    uint64_t  kcov_pos;
    uintptr_t kcov_area[0];
};

struct options {
    uint16_t    kext;       /* kext_id bitmask to instrument */
    int         injects;    /* synthetic-mode PISHI_IOCTL_TEST count */
    const char *service;    /* IOService name; NULL = synthetic self-check */
    uint32_t    uc_type;    /* user client type for IOServiceOpen */
    uint32_t    selector;   /* IOConnectCallMethod selector */
    uint64_t    scalars[MAX_SCALARS];
    uint32_t    nscalars;
};

static void usage(const char *prog)
{
    printf(
        "usage: %s [-k mask] [-s service -t type [-S selector] [scalars...]] [-n injects]\n"
        "\n"
        "Health check for Pishi.kext: verifies the device is reachable, the\n"
        "coverage buffer can be mapped, and coverage is recorded into it.\n"
        "\n"
        "options:\n"
        "  -k, --kext <mask>      kext_id bitmask telling Pishi which kext(s) to\n"
        "                         instrument. each bit is a kext from kext.h, e.g.\n"
        "                         0x1 = COM_APPLE_DRIVER_APPLEJPEGDRIVER.\n"
        "                         default: 0xffff (all kexts).\n"
        "  -s, --service <name>   IOService name for IOServiceOpen. supplying this\n"
        "                         runs a REAL test case against that user client\n"
        "                         instead of the synthetic self-check.\n"
        "  -t, --type <n>         user client type for IOServiceOpen. default: 0.\n"
        "  -S, --selector <n>     external method selector for IOConnectCallMethod.\n"
        "                         default: 0.\n"
        "  scalars...             optional uint64 scalar inputs for the method\n"
        "                         (hex/dec/octal), up to %d values.\n"
        "  -n, --injects <n>      synthetic-mode only: number of PISHI_IOCTL_TEST\n"
        "                         events to fire. default: 1, minimum: 1.\n"
        "  -h, --help             show this help and exit.\n"
        "\n"
        "examples:\n"
        "  sudo %s                                   # synthetic self-check, all kexts\n"
        "  sudo %s -k 0x1 -n 8                        # 8 synthetic events for one kext\n"
        "  sudo %s -k 0x1 -s AppleJPEGDriver -t 0     # real IOKit test case\n"
        "  sudo %s -k 0x1 -s AppleJPEGDriver -S 3 0x10 0x20  # selector 3, two scalars\n",
        prog, MAX_SCALARS, prog, prog, prog, prog);
}

/*
 * Run a real test case: open the target kext's IOKit user client and issue an
 * IOConnectCallMethod. Returns 0 if the sequence was driven (regardless of the
 * method's own return code, since even an "error" path exercises kext code),
 * -1 if the user client could not be reached at all.
 */
static int run_iokit_testcase(const char *service, uint32_t type,
                              uint32_t selector,
                              const uint64_t *scalars, uint32_t nscalars)
{
    io_service_t svc = IOServiceGetMatchingService(kIOMainPortDefault,
                                                   IOServiceMatching(service));
    if (svc == IO_OBJECT_NULL) {
        fprintf(stderr, "[FAIL] no IOService matching '%s'\n", service);
        return -1;
    }

    io_connect_t conn = IO_OBJECT_NULL;
    kern_return_t kr = IOServiceOpen(svc, mach_task_self(), type, &conn);
    IOObjectRelease(svc);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "[FAIL] IOServiceOpen('%s', type=%u): 0x%x\n",
                service, type, kr);
        return -1;
    }
    printf("[ OK ] opened user client for '%s' (type %u)\n", service, type);

    kr = IOConnectCallScalarMethod(conn, selector, scalars, nscalars,
                                   NULL, NULL);
    printf("[ .. ] IOConnectCallMethod(selector=%u, %u scalars) -> 0x%x\n",
           selector, nscalars, kr);

    IOServiceClose(conn);
    return 0;
}

/*
 * Parse argv into *o. Returns -1 to proceed, or an exit code to return from
 * main immediately (0 after printing --help, 2 on a usage error).
 */
static int parse_args(int argc, char **argv, struct options *o)
{
    /* Default to every kext bit set so the synthetic test event always matches. */
    o->kext = 0xffff;
    o->injects = 1;
    o->service = NULL;
    o->uc_type = 0;
    o->selector = 0;
    o->nscalars = 0;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (strcmp(a, "-h") == 0 || strcmp(a, "--help") == 0) {
            usage(argv[0]);
            return 0;
        } else if (strcmp(a, "-k") == 0 || strcmp(a, "--kext") == 0) {
            if (++i >= argc) goto missing;
            o->kext = (uint16_t)strtoul(argv[i], NULL, 0);
        } else if (strcmp(a, "-s") == 0 || strcmp(a, "--service") == 0) {
            if (++i >= argc) goto missing;
            o->service = argv[i];
        } else if (strcmp(a, "-t") == 0 || strcmp(a, "--type") == 0) {
            if (++i >= argc) goto missing;
            o->uc_type = (uint32_t)strtoul(argv[i], NULL, 0);
        } else if (strcmp(a, "-S") == 0 || strcmp(a, "--selector") == 0) {
            if (++i >= argc) goto missing;
            o->selector = (uint32_t)strtoul(argv[i], NULL, 0);
        } else if (strcmp(a, "-n") == 0 || strcmp(a, "--injects") == 0) {
            if (++i >= argc) goto missing;
            o->injects = atoi(argv[i]);
        } else if (a[0] == '-' && a[1] != '\0') {
            fprintf(stderr, "%s: unknown option '%s'\n", argv[0], a);
            return 2;
        } else {
            /* positional: a scalar input for IOConnectCallMethod */
            if (o->nscalars >= MAX_SCALARS) {
                fprintf(stderr, "%s: too many scalars (max %d)\n",
                        argv[0], MAX_SCALARS);
                return 2;
            }
            o->scalars[o->nscalars++] = strtoull(a, NULL, 0);
        }
        continue;
missing:
        fprintf(stderr, "%s: option '%s' requires an argument\n", argv[0], a);
        return 2;
    }

    if (o->injects < 1)
        o->injects = 1;
    if (o->service == NULL && o->nscalars > 0)
        fprintf(stderr, "[warn] scalars ignored without -s/--service\n");

    return -1;
}

int main(int argc, char **argv)
{
    struct options opt;
    int rc = parse_args(argc, argv, &opt);
    if (rc >= 0)
        return rc;

    uint16_t    kext = opt.kext;
    int         injects = opt.injects;
    const char *service = opt.service;

    /* 1. Reachability: the device node only exists while the kext is loaded. */
    int fd = open(DEVICE_NAME, O_RDWR);
    if (fd == -1) {
        perror("[FAIL] open " DEVICE_NAME);
        fprintf(stderr, "       is Pishi.kext loaded? (kmutil/kextstat)\n");
        return 1;
    }
    printf("[ OK ] %s is reachable\n", DEVICE_NAME);

    /* 2. Map the shared coverage buffer. */
    struct pishi_buf_desc desc = {0};
    if (ioctl(fd, PISHI_IOCTL_MAP, &desc) == -1) {
        perror("[FAIL] ioctl PISHI_IOCTL_MAP");
        close(fd);
        return 1;
    }
    if (desc.ptr == 0 || desc.sz == 0) {
        fprintf(stderr, "[FAIL] MAP returned an empty buffer (ptr=%p sz=%zu)\n",
                (void *)desc.ptr, desc.sz);
        close(fd);
        return 1;
    }
    struct pishi_cov *cov = (struct pishi_cov *)desc.ptr;
    printf("[ OK ] coverage buffer mapped at %p (%zu bytes)\n",
           (void *)desc.ptr, desc.sz);

    /* 3. Enable instrumentation for the requested kext bitmask. */
    if (ioctl(fd, PISHI_IOCTL_START, &kext) == -1) {
        perror("[FAIL] ioctl PISHI_IOCTL_START");
        close(fd);
        return 1;
    }
    printf("[ OK ] instrumentation started for kext_id mask 0x%x\n", kext);

    /* Drive the kernel-side coverage path. */
    int driven;
    if (service != NULL) {
        printf("[ .. ] running real test case against '%s'\n", service);
        driven = run_iokit_testcase(service, opt.uc_type, opt.selector,
                                    opt.scalars, opt.nscalars);
    } else {
        for (driven = 0; driven == 0 && injects-- > 0; )
            if (ioctl(fd, PISHI_IOCTL_TEST, 0) == -1) {
                perror("[FAIL] ioctl PISHI_IOCTL_TEST");
                driven = -1;
            }
    }

    /* Stop before reading so no further events race the collection. */
    if (ioctl(fd, PISHI_IOCTL_STOP, 0) == -1)
        perror("[warn] ioctl PISHI_IOCTL_STOP");

    if (driven != 0) {
        ioctl(fd, PISHI_IOCTL_UNMAP, 0);
        close(fd);
        return 1;
    }

    /* Verify the kext actually wrote coverage entries into the buffer. */
    uint64_t collected = cov->kcov_pos;
    if (collected == 0) {
        fprintf(stderr,
                "[FAIL] no coverage collected: the sanitizer path did not run\n");
        if (service != NULL)
            fprintf(stderr,
                    "       is kext_id 0x%x the right bit for '%s', and is the\n"
                    "       kext actually instrumented?\n", kext, service);
        ioctl(fd, PISHI_IOCTL_UNMAP, 0);
        close(fd);
        return 1;
    }

    printf("[ OK ] collected %llu coverage entr%s:\n",
           collected, collected == 1 ? "y" : "ies");
    for (uint64_t i = 0; i < collected; i++)
        printf("       [%llu] 0x%lx\n", i, cov->kcov_area[i]);

    ioctl(fd, PISHI_IOCTL_UNMAP, 0);
    close(fd);
    printf("[PASS] coverage is active for kext_id mask 0x%x\n", kext);
    return 0;
}
