.code

;
; Erik3000
; https://www.unknowncheats.me/forum/anti-cheat-bypass/658736-universal-ac-bypass.html
;

extern nmi_handler_original:proc
extern nmi_handler:proc

extern pagefault_handler_original:proc
extern pagefault_handler:proc

save_general_regs macro
	push rax
	push rbx
	push rcx
	push rdx
	push rsi
	push rdi
	push rbp
	push r8
	push r9
	push r10
	push r11
	push r12
	push r13
	push r14
	push r15
endm

restore_general_regs macro
	pop r15
	pop r14
	pop r13
	pop r12
	pop r11
	pop r10
	pop r9
	pop r8
	pop rbp 
	pop rdi
	pop rsi
	pop rdx
	pop rcx
	pop rbx
	pop rax
endm

asm_nmi_handler proc
	save_general_regs


	;
	; enable interrupts
	;
	mov rax, QWORD PTR [rsp + 88h] ; load rflags
	or rax, 200h                   ; set interrupt enable flag
	mov QWORD PTR [rsp + 88h], rax ; save rflags

	;
	; call nmi handler
	;
	sub rsp, 40h
	call nmi_handler
	add rsp, 40h



	restore_general_regs
	jmp qword ptr [nmi_handler_original]


asm_nmi_handler endp

asm_pagefault_handler proc
	save_general_regs


	;
	; enable interrupts
	;
	mov rax, QWORD PTR [rsp + 90h]  ; load rflags
	or rax, 200h                    ; set interrupt enable flag
	mov QWORD PTR [rsp + 90h], rax  ; save rflags

	;
	; error code as first parameter
	;
	mov rcx, [rsp + 88h]           ; error code

	;
	; call pagefault handler
	;
	sub rsp, 40h
	call pagefault_handler
	add rsp, 40h

	;
	; return 0 -> jmp to original handler
	;
	test rax, rax
	je   E0

	;
	; continue execution
	;
	restore_general_regs
	add rsp, 8 ; skip error code
	iretq


E0:
	;
	; windows page fault handler
	;
	restore_general_regs
	jmp qword ptr [pagefault_handler_original]

asm_pagefault_handler endp

end


