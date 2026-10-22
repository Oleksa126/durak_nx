/* AAPCS64: preserve original arguments/MethodInfo and LR on fallback. The
 * displaced four instructions are exclusively stack stores, verified in ELF.
 * Fallback tail-enters the guest: its normal exception frames remain intact. */
.text
.align 2
.macro guard name, helper, continuation
.global \name
.type \name, %function
\name:
  .cfi_startproc
  stp x0, x1, [sp, #-32]!
  .cfi_def_cfa_offset 32
  stp x2, x30, [sp, #16]
  .cfi_offset 30, -8
  bl \helper
  cbz x1, 1f
  ldr x30, [sp, #24]
  add sp, sp, #32
  .cfi_remember_state
  .cfi_def_cfa_offset 0
  .cfi_restore 30
  ret
1:
  .cfi_restore_state
  ldp x0, x1, [sp]
  ldp x2, x30, [sp, #16]
  add sp, sp, #32
  .cfi_def_cfa_offset 0
  .cfi_restore 30
  adrp x16, \continuation
  ldr x16, [x16, :lo12:\continuation]
.endm
.macro guard_end name
  br x16
  .cfi_endproc
  .size \name, .-\name
.endm

guard durak_static_table_guard, durak_static_table, durak_static_table_continue
  sub sp, sp, #0x90
  str x30, [sp, #0x40]
  stp x26, x25, [sp, #0x50]
  stp x24, x23, [sp, #0x60]
guard_end durak_static_table_guard

guard durak_static_row_guard, durak_static_row, durak_static_row_continue
  sub sp, sp, #0x40
  stp x30, x23, [sp, #0x10]
  stp x22, x21, [sp, #0x20]
  stp x20, x19, [sp, #0x30]
guard_end durak_static_row_guard

guard durak_static_text_guard, durak_static_text, durak_static_text_continue
  sub sp, sp, #0x50
  stp x30, x23, [sp, #0x20]
  stp x22, x21, [sp, #0x30]
  stp x20, x19, [sp, #0x40]
guard_end durak_static_text_guard
