import hashlib
import bcrypt
import argon2
import argon2.exceptions

def calculate_hash(file_path, hash_algorithm):
    """Calculate the hash of a file using the specified hash algorithm."""
    try:
        with open(file_path, 'rb') as file:
            data = file.read()
            if hash_algorithm.startswith('shake'):
                return hashlib.new(hash_algorithm, data).hexdigest(512)
            elif hash_algorithm == 'bcrypt':
                salt = bcrypt.gensalt()
                return bcrypt.hashpw(data, salt).decode('utf-8')
            elif hash_algorithm == 'argon2':
                hash_engine = argon2.PasswordHasher()
                return hash_engine.hash(data).split('$')[-1]
            else:
                hasher = hashlib.new(hash_algorithm)
                hasher.update(data)
                return hasher.hexdigest()
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
    except argon2.exceptions.Argon2Error as e:
        print(f"Argon2 Error: {e}")
    except Exception as e:
        print(f"Error: {e}")
    return None

def get_hash_info(hash_algorithm):
    """Get information about the hash algorithm and its common usage."""
    hash_info = {
        'md5': {
            'description': 'MD5 (Message Digest Algorithm 5)',
            'usage': 'MD5 is commonly used for checksums and integrity verification.',
            'applications': 'It was widely used in legacy systems for various applications, including file integrity checks and password storage. However, it is now considered insecure for cryptographic purposes due to vulnerabilities found in the algorithm.',
            'used_in_database': True
        },
        'sha1': {
            'description': 'SHA-1 (Secure Hash Algorithm 1)',
            'usage': 'SHA-1 was historically used for security, digital signatures, and certificates.',
            'applications': 'It was commonly used in cryptographic protocols and applications, including SSL/TLS certificates and digital signatures. However, vulnerabilities have been found in SHA-1, making it unsuitable for secure cryptographic use.',
            'used_in_database': True
        },
        'sha256': {
            'description': 'SHA-256 (Secure Hash Algorithm 256-bit)',
            'usage': 'SHA-256 is widely used in various cryptographic applications.',
            'applications': 'It is used in digital signatures, certificate generation, secure communications, and blockchain technology. SHA-256 provides a higher level of security compared to MD5 and SHA-1.',
            'used_in_database': True
        },
        'sha512': {
            'description': 'SHA-512 (Secure Hash Algorithm 512-bit)',
            'usage': 'SHA-512 is similar to SHA-256 but with a larger output size.',
            'applications': 'It is used in digital signatures, certificate generation, secure communications, and password hashing. The larger output size provides better resistance against attacks.',
            'used_in_database': True
        },
        'sha3_256': {
            'description': 'SHA-3 (Secure Hash Algorithm 3 - 256-bit)',
            'usage': 'SHA-3 is the latest member of the Secure Hash Algorithm family.',
            'applications': 'It is used in cryptographic applications requiring high security and resistance to attacks. SHA-3 is designed to provide better security properties and avoid the vulnerabilities found in SHA-1 and SHA-2.',
            'used_in_database': True
        },
        'sha3_512': {
            'description': 'SHA-3 (Secure Hash Algorithm 3 - 512-bit)',
            'usage': 'SHA-3 is the latest member of the Secure Hash Algorithm family with a larger output size.',
            'applications': 'It is used in cryptographic applications requiring high security and resistance to attacks. The larger output size provides additional security properties.',
            'used_in_database': True
        },
        'blake2b': {
            'description': 'BLAKE2 (cryptographic hash function - b variant)',
            'usage': 'BLAKE2b is faster than most cryptographic hash functions with similar security.',
            'applications': 'It is used in digital signatures, certificate generation, content distribution, and more. BLAKE2b is a popular choice due to its speed and security properties.',
            'used_in_database': False
        },
        'blake2s': {
            'description': 'BLAKE2 (cryptographic hash function - s variant)',
            'usage': 'BLAKE2s is faster than most cryptographic hash functions with similar security.',
            'applications': 'It is similar to BLAKE2b but optimized for systems with constrained memory. BLAKE2s is used in applications that require a smaller memory footprint.',
            'used_in_database': False
        },
        'whirlpool': {
            'description': 'Whirlpool (cryptographic hash function)',
            'usage': 'Whirlpool is designed for high security and resistance to attacks.',
            'applications': 'It is used in digital signatures, certificate generation, and secure communications. Whirlpool provides a higher level of security and is a good choice when stronger cryptographic properties are required.',
            'used_in_database': False
        },
               'ripemd160': {
            'description': 'RIPEMD (RACE Integrity Primitives Evaluation Message Digest) 160-bit',
            'usage': 'RIPEMD is used in cryptographic protocols and applications.',
            'applications': 'It is used for secure communications, content distribution, and digital signatures. RIPEMD-160 produces a shorter hash compared to SHA-256 and SHA-512.',
            'used_in_database': False
        },
        'crc32': {
            'description': 'CRC32 (Cyclic Redundancy Check 32-bit)',
            'usage': 'CRC32 is mainly used for data integrity checks and error detection.',
            'applications': 'It is used for checksums in data transmission and storage integrity verification. CRC32 is not suitable for cryptographic purposes due to its simplicity and vulnerabilities.',
            'used_in_database': False
        },
        'murmurhash3_32': {
            'description': 'MurmurHash3 (non-cryptographic hash function - 32-bit)',
            'usage': 'MurmurHash3 is a fast hash function suitable for non-security-critical tasks.',
            'applications': 'It is used in hash table implementations, hash-based lookups, and non-cryptographic use cases. MurmurHash3-32 produces a 32-bit hash value.',
            'used_in_database': False
        },
        'shake_128': {
            'description': 'SHAKE128 (Secure Hash Algorithm based on KECCAK - 128-bit)',
            'usage': 'SHAKE128 is used for generating variable-length hash outputs.',
            'applications': 'It is used in applications requiring variable-length hashes and XOF (Extendable Output Function). SHAKE128 is a member of the SHA-3 family.',
            'used_in_database': False
        },
        'shake_256': {
            'description': 'SHAKE256 (Secure Hash Algorithm based on KECCAK - 256-bit)',
            'usage': 'SHAKE256 is used for generating variable-length hash outputs.',
            'applications': 'It is used in applications requiring variable-length hashes and XOF (Extendable Output Function). SHAKE256 is a member of the SHA-3 family.',
            'used_in_database': False
        },
        'bcrypt': {
            'description': 'bcrypt (Adaptive Blowfish Password Hashing)',
            'usage': 'bcrypt is commonly used for securely hashing passwords.',
            'applications': 'It is used for storing and verifying passwords in a secure manner to resist brute-force attacks. bcrypt is adaptive, allowing the computational cost to be increased over time.',
            'used_in_database': True
        },
        'argon2': {
            'description': 'Argon2 (Password Hashing Competition winner)',
            'usage': 'Argon2 is a highly memory-hard password hashing function.',
            'applications': 'It is used for secure password storage with resistance to GPU and ASIC attacks. Argon2 won the Password Hashing Competition in 2015.',
            'used_in_database': True
        },
        'scrypt': {
            'description': 'Scrypt (Memory-hard key derivation function)',
            'usage': 'Scrypt is a memory-hard key derivation function to deter large-scale custom hardware attacks.',
            'applications': 'It is used in cryptocurrencies (e.g., Litecoin, Dogecoin) and other secure authentication systems. Scrypt requires a significant amount of memory, making it more expensive to implement custom hardware attacks.',
            'used_in_database': False
        }
    }
    
    return hash_info.get(hash_algorithm.lower())

def main():
    print('''\n
____ ____     _  _ ____ ____ _  _ 
| __ |  |     |__| |__| [__  |__| 
|__] |__| ___ |  | |  | ___] |  | 
                                     
    \n''')
    print("\033[34m=== File Hash Calculator ===\033[0m")
    file_path = input("('q' to quit) Enter the path to the file: ")

    if file_path.lower() == 'q':
        print("][Exiting the program.")
        return

    hash_algorithms = [
        'md5', 'sha1', 'sha256', 'sha512', 'sha3_256', 'sha3_512',
        'blake2b', 'blake2s', 'whirlpool', 'ripemd160', 'crc32',
        'murmurhash3_32', 'shake_128', 'shake_256', 'bcrypt', 'argon2', 'scrypt'
    ]

    print("\nAvailable hash algorithms:")
    for idx, algorithm in enumerate(hash_algorithms, 1):
        print(f"{idx}. {algorithm}")

    selected_algorithms = input("Enter the numbers of the hash algorithms (separated by commas), or 'q' to quit: ")

    if selected_algorithms.lower() == 'q':
        print("Exiting the program.")
        return

    selected_algorithms = [hash_algorithms[int(num) - 1] for num in selected_algorithms.split(',')]

    print("\n=== Results ===")
    for idx, algorithm in enumerate(selected_algorithms, 1):
        hash_info = get_hash_info(algorithm)
        if hash_info:
            print(f"\n \033[95m{idx}. Hash Algorithm: {algorithm.upper()} \033[0m")
            print(f"\033[33mDescription: {hash_info['description']}\033[0m")
            print(f"\033[33mUsage: {hash_info['usage']}\033[0m")
            print(f"\033[33mApplications: {hash_info['applications']}\033[0m")
            if hash_info['used_in_database']:
                print("Used in databases:\033[32m Yes\033[0m")
            else:
                print("Used in databases:\033[31m No\033[0m")

            print(f"\nHash of the file using\033[35m {algorithm.upper()}\033[0m:")
            file_hash = calculate_hash(file_path, algorithm)
            if file_hash:
                print('\033[96m' + file_hash + '\033[97m')
            else:
                print("Error calculating hash.")

            print("\n-----------------------------------------------------------")
        else:
            print(f"Hash algorithm '{algorithm}' is not supported.")

if __name__ == "__main__":
    main()



