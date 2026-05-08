#
#Program name: main
#Author: Team 7
#Date: 5.2.26 
#Purpose: To implement the RSA algorithm by generating a private and public key, then encrypting and decrypting a message
#



.text
.global main

main:

#Menu selection written by Jacob Parsky

#push the stack
SUB sp, sp, #16
STR lr, [sp, #0]
STR r4, [sp, #4]
STR r5, [sp, #8]

#Prompt for input
LDR r0, =mainMenu
BL printf

#scanf
LDR r0, =format
LDR r1, =selection
BL scanf

#Save selection in r4
LDR r1, =selection
LDR r1, [r1]

MOV r4, r1

#LDR r0, =outCheck
#BL printf

BL keys

#Check option

#Block for getting private and public keys. Written by Jacob Parsky

keys:
CMP r4, #1
    BNE encryptMain

LDR r0, =getPAndQ
BL printf


getInput:
LDR r0, =getIntOne
BL printf

LDR r0, =format
LDR r1, = intOne
BL scanf

LDR r0, =intOne
LDR r0, [r0]

MOV r4, r0

#Check if positive
CMP r0, #0
    BLT invalidInput

#Check if greater than 49
#CMP r0, #50
    #BGE invalidInput

#Check if prime
BL checkPrime

CMP r0, #1
   BNE invalidInput

B inputTwo


inputTwo:
LDR r0, =getIntTwo
BL printf

LDR r0, =format
LDR r1, =intTwo
BL scanf

LDR r0, =intTwo
LDR r0, [r0]

MOV r5, r0

#Check if positive
CMP r0, #0
    BLT invalidInput

#check if greater than 49
#CMP r0, #50
    #BGE invalidInput

#Check if prime
BL checkPrime

CMP r0, #1
     BNE invalidInput

#Check if product is greater than 127
MUL r3, r4, r5

CMP r3, #127
    BLT notLargeEnough

MOV r0, r4
MOV r1, r5

BL cpubexp

B pop

notLargeEnough:
LDR r0, =notLargeOut
BL printf
B getInput

invalidInput:
LDR r0, =getPAndQ
BL printf
B getInput

#END keys


#START encryptMain

encryptMain:
CMP r4, #2
    BNE decryptMain

#convert to hexadecimal 
BL encrypt

B pop

#START decryptMain

decryptMain:
BL decrypt


B pop

pop:
#pop the stack
LDR lr, [sp, #0]
LDR r4, [sp, #4]
LDR r5, [sp, #8]
ADD sp, sp, #16
MOV pc, lr

.data
mainMenu: .asciz "Enter 1 to generate private and public keys.\nEnter 2 to encrypt a message.\nEnter 3 to decrypt a message.\n"
format: .asciz "%d"
selection: .word 0
keyOutput: .asciz "You entered %d\n"
outCheck: .asciz "\nYou entered: %d\n"
getPAndQ: .asciz "\nPlease enter two prime, positive integers whose product is greater than 127.\n"
getIntOne: .asciz "\nPlease enter the first integer.\n"
intOne: .word 0
getIntTwo: .asciz "\nPlease enter the second integer.\n"
intTwo: .word 0
hexFormat: .asciz "\nYour message is now: \"%s\"\n"
hexOutput: .space 100
notLargeOut: .asciz "\nThe product of the two integers must be greater than 127.\n"
    
