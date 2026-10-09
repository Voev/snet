# Makefile for building XDP BPF programs.
#
# Targets:
#   make            - build xdp_redirect.bpf.o
#   make clean      - remove build artifacts
#   make dump       - print disassembly and section headers
#   make install    - copy the object into the config directory

# ---- Toolchain ----------------------------------------------------------

CLANG      ?= clang
LLVM_STRIP ?= llvm-strip
BPFTOOL    ?= bpftool

# Multiarch include path is required by linux/types.h which pulls in
# <asm/types.h>. Debian/Ubuntu keep it under /usr/include/<triplet>.
MULTIARCH  := $(shell $(CC) -dumpmachine 2>/dev/null || gcc -dumpmachine)

# ---- Paths --------------------------------------------------------------

SRC        := xdp_redirect.bpf.c
OBJ        := xdp_redirect.bpf.o

# Where to copy the object after a successful build. Adjust to match the
# value of bpf_obj_path in your driver configuration.
INSTALL_DIR ?= .

# ---- Flags --------------------------------------------------------------

BPF_CFLAGS := -target bpf \
              -O2 -g \
              -Wall -Wextra \
              -Wno-unused-parameter \
              -fno-stack-protector \
              -idirafter /usr/include/$(MULTIARCH) \
              -I/usr/include/$(MULTIARCH)

# vmlinux.h is not used here; the program relies on uapi headers only.
# If you switch to CO-RE (vmlinux.h + bpf_core_read), add:
#   -D__TARGET_ARCH_x86 -I$(VMLINUX_DIR)

# ---- Rules --------------------------------------------------------------

.PHONY: all clean dump install

all: $(OBJ)

$(OBJ): $(SRC)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	@echo "built: $@"

# Strip debug info to shrink the object (optional, keep -g for vmlinux.h).
strip: $(OBJ)
	$(LLVM_STRIP) -g $< -o $@
	@echo "stripped: $@"

# Inspect the resulting object: section headers and disassembly.
dump: $(OBJ)
	@echo "=== sections ==="
	@$(BPFTOOL) gen object $< /dev/null 2>/dev/null || true
	@llvm-objdump -h $<
	@echo
	@echo "=== disassembly ==="
	@llvm-objdump -d $<

clean:
	rm -f $(OBJ) $(OBJ).stripped

install: $(OBJ)
	install -D -m 0644 $(OBJ) $(INSTALL_DIR)/$(OBJ)
	@echo "installed: $(INSTALL_DIR)/$(OBJ)"