# RSA Cryptography System — ARM Assembly

## Overview

This project implements a basic RSA encryption and decryption system in ARM Assembly. The program was developed for a Linux/Raspberry Pi environment and demonstrates low-level programming, modular arithmetic, key generation, memory management, and debugging in assembly.

## Features

- Generates RSA public and private key components
- Performs modular arithmetic operations
- Checks for prime numbers
- Computes greatest common divisors for coprimality checks
- Encrypts and decrypts integer-based messages
- Uses modular function design across multiple assembly files

## Technologies Used

- ARM Assembly
- Linux
- Raspberry Pi
- GCC / GNU assembler
- Bash terminal

## What I Learned

This project strengthened my understanding of low-level programming, register usage, stack management, control flow, memory access, modular arithmetic, and debugging segmentation faults in a Linux environment.

## Project Context

This project was completed as part of a computer organization course. I completed the design, implementation, debugging, and integration of the RSA system.

## How to Build and Run

If using GCC on a Raspberry Pi or ARM Linux environment:

```bash
gcc -o rsa src/main.s src/funcLib.s
./rsa
