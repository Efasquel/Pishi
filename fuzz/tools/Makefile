CC       = clang
CFLAGS   = -Wall -Wextra -O2
TARGETS  = kaslr

.PHONY: all clean

all: $(TARGETS)

%: %.c
	$(CC) $(CFLAGS) -o $@ $< $(LDLIBS)

clean:
	rm -f $(TARGETS)
