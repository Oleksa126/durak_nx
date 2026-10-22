.section .rodata
.balign 4
.global loading_screen_bin
loading_screen_bin:
.incbin "data/loading_screen.bin"
.section .note.GNU-stack,"",@progbits
