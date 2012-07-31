
.CODE

; Per funzioni con meno di 4 parametri
CALLSTUB1 PROC
; Marker dell'hook	
	nop
	nop
	jmp		@end_marker1
@end_marker1:

	mov rcx, rcx
	mov r9, r8
	mov r8, rdx
	mov	rdx, rcx
	mov rcx, 6969696969696969h	; Puntatore ai dati 	
	mov	rax, 6767676767676767h	; Indirizzo della funzione hook
	jmp rax
		
	ret
CALLSTUB1 ENDP


; Per funzioni con 4 parametri o piu'
CALLSTUB2 PROC
; Marker dell'hook	
	nop
	nop
	jmp		@end_marker2
@end_marker2:

	mov rax, r9		; rax e' usata per appoggio	
	mov r9, r8
	mov r8, rdx
	mov	rdx, rcx
	
	push rsi
	push rdi
	push rbp
	mov rbp, rsp
	
	mov rcx, 66666666h  ; Numero di parametri della funzione
	sub rcx, 4			; Numero di parametri gia' presenti sullo stack
	lea rsi, [rsp+40h]	; Puntatore al primo parametro sullo stack
	
	mov rdi, rsp
	shl rcx, 3
	sub rdi, rcx
	shr rcx, 3			; rdi punta ai nuovi parametri
	mov rsp, rdi
	
	rep movsq			; Copio i parametri
	push rax			; r9 va sullo stack
	sub rsp, 20h
	
	mov rcx, 6969696969696969h	; Puntatore ai dati 	
	mov	rax, 6767676767676767h	; Indirizzo della funzione hook
	call rax
	
	mov rsp, rbp
	pop rbp
	pop rdi
	pop rsi
	
	ret
CALLSTUB2 ENDP



ORIGINALCODE PROC
; Marker dell'hook	
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop

	push rax
	push rax
	mov rax, 6868686868686868h 
	mov [rsp+8], rax
	pop rax 
	ret ; salta a 686868686868h senza sporcare i registri
ORIGINALCODE ENDP


END