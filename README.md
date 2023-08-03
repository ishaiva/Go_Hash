# File Hash Calculator

![Python](https://img.shields.io/badge/python-3.x-blue.svg)

File Hash Calculator is a Python script that allows you to calculate the hash of a file using various hash algorithms. It provides an interactive command-line interface for selecting the file and hash algorithms, and displays the calculated hashes along with relevant information about the selected algorithms.

## Table of Contents

- [Features](#features)
- [Supported Hash Algorithms](#supported-hash-algorithms)
- [Usage](#usage)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage Example](#usage-example)
- [License](#license)

## Features

- Calculate the hash of a file using various hash algorithms.
- Display information about each selected hash algorithm, such as description, usage, applications, and whether it is used in databases.
- Interactive command-line interface for easy user interaction.

## Supported Hash Algorithms

The script supports the following hash algorithms:

- MD5
- SHA-1
- SHA-256
- SHA-512
- SHA-3 (256-bit and 512-bit)
- BLAKE2b
- BLAKE2s
- Whirlpool
- RIPEMD-160
- CRC32
- MurmurHash3-32
- SHAKE128
- SHAKE256
- bcrypt
- Argon2
- scrypt

## Usage

To use the File Hash Calculator, follow these steps:

1. Clone or download the repository to your local machine.
2. Open a terminal or command prompt and navigate to the project directory.
3. Run the script with Python 3.x: `python Hash.py`

The script will prompt you to enter the path to the file you want to calculate the hash for. Then, you can select one or more hash algorithms from the list of supported algorithms by entering their corresponding numbers separated by commas. The calculated hashes and algorithm information will be displayed for each selected algorithm.

## Requirements

- Python 3.x

## Installation

You don't need to install anything separately to use the File Hash Calculator. Just make sure you have Python 3.x installed on your system.

## Usage Example

1. Calculate the hash of a file:

$ python Hash.py

=== File Hash Calculator ===
('q' to quit) Enter the path to the file: /path/to/your/file.txt

Available hash algorithms:

    MD5
    SHA-1
    SHA-256
    ...

Enter the numbers of the hash algorithms (separated by commas), or 'q' to quit: 1,3,5

=== Results ===

    Hash Algorithm: MD5
    Description: MD5 (Message Digest Algorithm 5)
    Usage: MD5 is commonly used for checksums and integrity verification.
    Applications: It was widely used in legacy systems for various applications, including file integrity checks and password storage. However, it is now considered insecure for cryptographic purposes due to vulnerabilities found in the algorithm.
    Used in databases: Yes

Hash of the file using MD5:
c4ca4238a0b923820dcc509a6f75849b

    Hash Algorithm: SHA-256
    Description: SHA-256 (Secure Hash Algorithm 256-bit)
    Usage: SHA-256 is widely used in various cryptographic applications.
    Applications: It is used in digital signatures, certificate generation, secure communications, and blockchain technology. SHA-256 provides a higher level of security compared to MD5 and SHA-1.
    Used in databases: Yes

Hash of the file using SHA-256:
f3bca7db26e4d3a2169e7a691b0e64094ad1d5eb1e25251e8c30e98a79ac0b08

    Hash Algorithm: SHA-3 (256-bit)
    Description: SHA-3 (Secure Hash Algorithm 3 - 256-bit)
    Usage: SHA-3 is the latest member of the Secure Hash Algorithm family.
    Applications: It is used in cryptographic applications requiring high security and resistance to attacks. SHA-3 is designed to provide better security properties and avoid the vulnerabilities found in SHA-1 and SHA-2.
    Used in databases: Yes

Hash of the file using SHA-3 (256-bit):
a5df1747de9bea3d48697bfe08f0df54c18d2a8431062218b3caec877bdc38ac

csharp


## License

This project is licensed under the [MIT License](LICENSE).
# Go_Hash
