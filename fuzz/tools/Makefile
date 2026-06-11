CC       = clang
CFLAGS   = -Wall -Wextra -O2
TARGETS  = kaslr pishi_check

# pishi_check uses IOKit to drive a real user-client test case.
pishi_check: LDLIBS = -framework IOKit -framework CoreFoundation

.PHONY: all clean

all: $(TARGETS)

%: %.c
	$(CC) $(CFLAGS) -o $@ $< $(LDLIBS)

clean:
	rm -f $(TARGETS)
