CC_MACOS = aarch64-linux-musl-gcc
CC_LINUX = aarch64-linux-gnu-gcc
CFLAGS = -static -O2

all: exploit exploit_utm exploit_linux

# macOS targets (cross-compiled with musl)
exploit: exploit.c
	$(CC_MACOS) $(CFLAGS) -o $@ $<

exploit_utm: exploit_utm.c
	$(CC_MACOS) $(CFLAGS) -o $@ $<

# Linux aarch64 target
exploit_linux: exploit_linux.c
	$(CC_LINUX) $(CFLAGS) -o $@ $<

clean:
	rm -f exploit exploit_utm exploit_linux
