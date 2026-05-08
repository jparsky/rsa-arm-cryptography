#
#Program Name: funcLib
#Authors: Jacob Parsky, Arafat Chowdhury, Christian Walter, Brandon Jaikaran, Wenhan Li
#Date: 5.2.26
#Purpose: To serve as an accesible function library for the following functions, used to implement the RSA algorithm in ARM assembly
#    gcd: to find the greatest common divisor of two integers
#	Input: Two integers
#	OUtput: the greatest common divisor of the two inputs
#    pow: to perform exponentiation
#	Input: two integers, a base and an exponent
#	Output: the integer result of the base raised to the exponent
#    modulo: to perform the modulus operation
#	Input: Two positive integers, p and q
#	Output: the modulus n, which is the product of the two inputs
#    checkPrime: to check if an integer is prime
#	Input: An integer
#	Output: 0 if not prime, 1 if prime. Also a message stating whether or not the input is prime.
#    cpubexp: function for all calculations related to the public key exponent
#	Input: Two positive integers, p and q
#	Output: the public key which must be greater than 1 and less than the totient of p and q, as well as co-prime to the totient of p and q
#    cprivexp: function for all calculations related to the private key exponent
#	Input: three integers, the totient (t) of n (which is the modulus of p and q, the public key exponent, and some integer x
#	Output: the private key exponent d, such that d=(1+x*t(n))/e.
#

.extern fopen
.extern fprintf
.extern fclose

.global gcd
.global pow
.global modulo
.global checkPrime
.global cpubexp
.global cprivexp
.global encrypt
.global decrypt

.text
gcd:

#push the stack
SUB sp, sp, #12
STR lr, [sp, #0]
STR r4, [sp, #4]
STR r5, [sp, #8]

#Store first number in r4 and second number in r5, counter in r6
MOV r4, r0
MOV r5, r1



divisorLoop:
#check if modulo is 0 and exit
CMP r5, #0
    BEQ finish

#Call modulo function to get remainder
    MOV r0, r4
    MOV r1, r5
    BL modulo

    MOV r4,r5
    MOV r5, r0

    B divisorLoop

    finish: 
    CMP r4, #1
        BEQ coPrime

    notCoPrime:
    LDR r0, =notCoPrimeOut
    BL printf
    MOV r0, #0

    #pop the stack
    LDR lr, [sp, #0]
    LDR r4, [sp, #4]
    LDR r5, [sp, #8]
    ADD sp, sp, #12
    MOV pc, lr

    coPrime:
    MOV r0, #1

    #pop the stack
    LDR lr, [sp, #0]
    LDR r4, [sp, #4]
    LDR r5, [sp, #8]
    ADD sp, sp, #12
    MOV pc, lr

.data
notCoPrimeOut: .asciz "\nYour input is not co-prime with the totient. Try again\n"

#END gcd

.text
pow:

    #push stack
    SUB sp, sp, #20
    STR lr, [sp, #0]
    STR r4, [sp, #4]
    STR r5, [sp, #8]
    STR r6, [sp, #12]
    STR r7, [sp, #16]

    #Store base in r4, exponent in r5, counter in r6, modulus in r7
    MOV r4, r0
    MOV r5, r1
    MOV r6, #1
    MOV r7, r2

    expoLoop:
    #Check if counter is equal to exponent and stop if it is
    CMP r6, r5
        BGE endExpo
    
    #Multiply base by itself and update counter
    MUL r0, r0, r4
    	
    MOV r1, r7
    BL modulo

    ADD r6, r6, #1
    B expoLoop

    endExpo:

    #pop stack
    LDR lr, [sp, #0]
    LDR r4, [sp, #4]
    LDR r5, [sp, #8]
    LDR r6, [sp, #12]
    LDR r7, [sp, #16]
    ADD sp, sp, #20
    MOV pc, lr

.data

#END pow

.text
modulo:
   
    #push stack
    SUB sp, sp, #12
    STR lr, [sp, #0]
    STR r4, [sp, #4]
    STR r5, [sp, #8]

    #Store input
    MOV r5, r0
    MOV r4, r1

    #divide
    MOV r0, r5
    MOV r1, r4
    BL __aeabi_idiv

    #Multiply the result by the divisor, then subtract from original number to get remainder
    MOV r2, r0
    MUL r1, r1, r2
    SUB r0, r5, r1

    #pop stack
    LDR lr, [sp, #0]
    LDR r4, [sp, #4]
    LDR r5, [sp, #8]
    ADD sp, sp, #12
    MOV pc, lr

.data

#END modulo
    
#START checkPrime. Function written by Jacob Parsky

.text
checkPrime: 

    #push the stack
    SUB sp, sp, #12
    STR lr, [sp, #0]
    STR r4, [sp, #4]
    STR r5, [sp, #8]

    #check if less than 3, treat as not prime
    CMP r0, #2
        BLE not_valid 

    MOV r5, r0   
    MOV r4, #2   

primeLoop:

    #Check if counter has reached the input
    CMP r4, r5
    BGE isPrime

    #Perform the modulo function
    MOV r0, r5
    MOV r1, r4
    BL modulo

    #If remainder is 0, then it can't be prime
    CMP r0, #0
    BEQ not_prime

    #Update counter
    ADD r4, r4, #1

    B primeLoop



    not_prime:
        MOV r0, #0
        #pop stack
	LDR lr, [sp, #0]
	LDR r4, [sp, #4]
	LDR r5, [sp, #8]
	ADD sp, sp, #12
	MOV pc, lr
    
    isPrime:

        MOV r0, #1
        #pop stack
        LDR lr, [sp, #0]
	LDR r4, [sp, #4]
	LDR r5, [sp, #8]
	ADD sp, sp, #12
	MOV pc, lr

    not_valid:

        MOV r0, #0
        #pop stack
	LDR lr, [sp, #0]
	LDR r4, [sp, #4]
	LDR r5, [sp, #8]
	ADD sp, sp, #12
	MOV pc, lr

.data


#END checkPrime

#START cpubexp. Function written by Jacob Parsky

.text
cpubexp:

    
    #Register dictionary
    #r4=p
    #r5=q
    #r6=modulus n
    #r7 = totient(n)=(p-1)*(q-1)
    #r8 = public key exponent e

    #push stack
    SUb sp, sp, #4
    STR lr, [sp]


    #Store p and q
    MOV r4, r0
    MOV r5, r1

    #Calculate modulus n, n=p*q, and store
    MUL r6, r4, r5
    
    #print modulus
    MOV r1, r6
    LDR r0, =modulusOut
    BL printf

    #Calculate totient (p-1)*(q-1) and store
    SUB r0, r4, #1
    SUB r1, r5, #1

    MUL r7, r1, r0

    B getE
    
    getE:

    #Prompt for public key exponent, e
    LDR r0, =promptForE
    MOV r1, r7
    BL printf

    #Scanf
    LDR r0, =format
    LDR r1, =inputE
    BL scanf

    #Load value and store
    LDR r1, =inputE
    LDR r1, [r1]
    MOV r8, r1

    #Check if greater than 1
    CMP r1, #1
        BLE invalid

    #Check if less than totient
    CMP r8, r7
        BGE invalid
 
    #Check if co-prime
    MOV r0, r7
    MOV r1, r8
    BL gcd

    CMP r0, #1
       BNE notCoPrime2

    #Display public key
    MOV r1, r8
    LDR r0, =outputE
    BL printf

    #Call private key function
    MOV r0, r7
    MOV r1, r8

    BL cprivexp

    B pop

    notCoPrime2:
    B getE

    invalid:
    B getE
    
    pop:
    #pop the stack
    LDR lr, [sp]
    ADD sp, sp, #4
    MOV pc, lr
    

.data
promptForE: .asciz "Please input a small positive value greater than 1, but less than, and co-prime to %d\n"
format: .asciz "%d"
inputE: .word 0
outputE: .asciz "Your public key exponent is: %d.\n"
modulusOut: .asciz "\nYour modulus is: %d\n"


#END cpubexp

#START cprivexp. Function written by Jacob Parsky

.text 
cprivexp: 

#Register dictionary
# r4- totient
# r5 - e
# r6 - counter

    #push stack
    SUB sp, sp, #4
    STR lr, [sp]

    #STore values
    MOV r4, r0
    MOV r5, r1
    MOV r6, #1

    findExpD:
    #Try private key d
    MOV r0, r6
    MUL r0, r0, r5
    MOV r1, r4
    BL modulo

    CMP r0, #1
        BEQ foundD
 
    ADD r6, r6, #1
    B findExpD

    foundD:
    MOV r1, r6
    LDR r0, =privateKeyOut
    BL printf

    MOV r0, r8
   
    #pop the stack
    LDR lr, [sp]
    ADD sp, sp, #4
    MOV pc, lr
    

.data
xOutput: .asciz "\nPlease input some small integer, x:\n"
formatX: .asciz "%d"
inputX: .word 0
privateKeyOut: .asciz "\nYour private key exponent, d, is: %d\n"

#END cprivexp

#START encrypt

.text
encrypt:

#Register Dictionary
#r4 - currentCharacter
#r5 - modulus n
#r6 - public key exponent e
#r7 - messageToEncrypt
  

#push stack
SUB sp, sp, #16
STR lr, [sp, #0]
STR r4, [sp, #4]
STR r5, [sp, #8]
STR r6, [sp, #12]

#prompt for message
LDR r0, =encryptPrompt
BL printf

#scan message
LDR r0, =encryptFormat
LDR r1, =messageToEncrypt
BL scanf

#Confirm scan
#LDR r0, =encryptCheck
#LDR r1, =messageToEncrypt
#BL printf

#Prompt for modulus n
LDR r0, =modulusPrompt
BL printf

#Scan modulus n and store in r5
LDR r0, =modulusFormat
LDR r1, =modulusIn
BL scanf

LDR r5, =modulusIn
LDR r5, [r5]

#Scan for public key exponent and store in r6
LDR r0, =expoPrompt
BL printf

LDR r0, =expoFormat
LDR r1, =expoIn
BL scanf

LDR r6, =expoIn
LDR r6, [r6]

#Initalize counter
#MOV r7, #0


#Load string
LDR r7, =messageToEncrypt

#Open ecrypted.txt
LDR r0, =fileName
LDR r1, =fileMode
BL fopen

#Store file in r10
MOV r10, r0 

#Loop through string

stringLoop:
#Load first character
LDRB r3, [r7]

#Store in r8
MOV r8, r3

#Check if last character
CMP r3, #0
    BEQ doneString

SUB sp, sp, #4
STR r7, [sp]

#SUB r3, r3, #64

#Print in dec
#LDR r0, =decCharFormat
#MOV r1, r3
#BL printf

LDR r7, [sp]
ADD sp, sp, #4

#raise ascii value of character to expo 
MOV r1, r6
MOV r0, r8
MOV r2, r5
BL pow

#MOV r1, r5
#BL modulo

MOV r9, r0

#Save to encrypted.txt
MOV r0, r10
LDR r1, =fileFormat
MOV r2, r9
BL fprintf

#LDR r0, =outputCheck
#MOV r1, r9
#BL printf

ADD r7, r7, #1
B stringLoop

doneString:

LDR r0, =encryptedOut
BL printf

MOV r0, r10
BL fclose

#pop the stack
LDR lr, [sp, #0]
LDR r4, [sp, #4]
LDR r5, [sp, #8]
LDR r6, [sp, #12]
ADD sp, sp, #16
MOV pc, lr


.data
encryptPrompt: .asciz "\nEnter a message to encrypt: \n"
encryptFormat: .asciz " %39[^\n]"
messageToEncrypt: .space 40
encryptCheck: .asciz "\nYou entered: \"%s\"\n"
charCheck: .asciz "\n%c\n"
modulusPrompt: .asciz "\nPlease enter your modulus n: \n"
modulusFormat: .asciz "%d"
modulusIn: .word 0
expoPrompt: .asciz "\nPlease enter your public key exponent: \n"
expoFormat: .asciz "%d"
expoIn: .word 0
decCharFormat: .asciz "\n%d \n"
expoOut: .asciz "\nThe result is: %d\n"
outputCheck: .asciz "\nThe result is %d\n"
fileName: .asciz "encrypted.txt"
fileMode: .asciz "w"
fileFormat: .asciz "%d "
encryptedOut: .asciz "\nYour message has been encrypted\n"

#END encrypt

#START decrypt

#Register dictionary
#    r4 - private key d
#    r5 - modulus n

.text
decrypt:
#push the stack
SUB sp, sp, #16
STR lr, [sp, #0]
STR r4, [sp, #4]
STR r5, [sp, #8]
STR r6, [sp, #12]

#Get modulus
LDR r0, =modPrompt2
BL printf

LDR r0, =privFormat
LDr r1, =privKey
BL scanf

LDR r4, =privKey
LDR r4, [r4]

#open encrypted.txt
LDR r0, =fileNameDec
LDR r1, =readMode
BL fopen

MOV r10, r0

#open plaintext.txt
LDR r0, =plainText
LDR r1, =writeMode
BL fopen

MOV r11, r0


readLoop:
MOV r0, r10
LDR r1, =readFormat
LDR r2, =readChar
BL fscanf

CMP r0, #1
    BNE doneRead

LDR r3, =readChar
LDR r3, [r3]

#LDR r0, =outCheckNum
#MOV r1, r3
#BL printf

MOV r8, r3

MOV r0, r8
MOV r1, r4
MOV r2, r5
BL pow

MOV r1, r5

MOV r9, r0


LDR r0, =charOut
MOV r1, r9
BL printf

MOV r0, r11
LDR r1, =charFormat
MOV r2, r9
BL fprintf

B readLoop

doneRead:

#clean up print
LDR r0, =makeSpace
BL printf


#close .txt files
MOV r0, r10
BL fclose

MOV r0, r11
BL fclose

#pop the stack 
LDR lr, [sp, #0]
LDR r4, [sp, #4]
LDR r5, [sp, #8]
LDR r6, [sp, #12]
ADD sp, sp, #16
MOV pc, lr

.data
fileNameDec: .asciz "encrypted.txt"
readMode: .asciz "r"
readFormat: .asciz "%d"
readChar: .word 0
modFormat: .asciz "%d"
modPrompt2: .asciz "\nEnter the modulus n: \n"
mod2: .word 0
privPrompt: .asciz "\nEnter the private key exponent, d\n"
privFormat: .asciz "%d"
privKey: .word 0
charFormat: .asciz "%c"
charOut: .asciz "%c"
outCheckNum: .asciz "\nThe character is: %d\n"
makeSpace: .asciz "\n"
plainText: .asciz "plaintext.txt"
writeMode: .asciz "w"

#END decrypt
#
#Program Name: funcLib
#Authors: Jacob Parsky, Arafat Chowdhury, Christian Walter, Brandon Jaikaran, Wenhan Li
#Date: 5.2.26
#Purpose: To serve as an accesible function library for the following functions, used to implement the RSA algorithm in ARM assembly
#    gcd: to find the greatest common divisor of two integers
#	Input: Two integers
#	OUtput: the greatest common divisor of the two inputs
#    pow: to perform exponentiation
#	Input: two integers, a base and an exponent
#	Output: the integer result of the base raised to the exponent
