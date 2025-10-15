# Makefile pour assembler et lier vault (NASM x86-64)
ASM      = nasm
ASMFLAGS = -felf64
LD       = ld

SRCS     = main.asm auth_check.asm add_password.asm show_passwords.asm common_data.asm
OBJS     = $(SRCS:.asm=.o)
TARGET   = vault

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS)
	$(LD) -o $@ $(OBJS)
	# supprime les .o après build (optionnel) :
	rm -f $(OBJS)

%.o: %.asm
	$(ASM) $(ASMFLAGS) $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)
