import hmac, hashlib
import streamlit as st

def xor_bytes(a, b):
    """XOR two byte strings."""
    return bytes(x ^ y for x, y in zip(a, b))

# Function to pad the plaintext message
def pad(plaintext, block_size):
    """Apply PKCS#7 padding."""
    padding_len = block_size - (len(plaintext) % block_size)
    return plaintext + bytes([padding_len] * padding_len)

# Function to unpad the decrypted message (reverse of padding)
def unpad(padded_text, key):
    """Remove PKCS#7 padding."""
    padding_len = padded_text[-1]
    hmac_len = 32

    # Check for invalid padding first before unpadding
    if padding_len == 0 or padding_len > len(padded_text):
        raise ValueError("Invalid padding!")
    if padded_text[-padding_len:] != bytes([padding_len] * padding_len):
        raise ValueError("Invalid padding!")
    # Valid padding
    # raw_plaintext + hmac + padding
    else:
        raw_plaintext = padded_text[0:len(padded_text) - hmac_len - padding_len]
        hash_value = padded_text[len(raw_plaintext):-padding_len]
        print("hash received:", hash_value)
        original_hash = hmac.new(key, raw_plaintext, hashlib.sha256).digest()
        print("original hash:", original_hash)

        # Matching HMAC == Valid HMAC, and otherwise
        if hash_value == original_hash:
            print("Server: HMAC valid!")
            return raw_plaintext
        else:
            return "Server: HMAC invalid!"

# Simulated CBC encryption function
def cbc_encrypt(plaintext, key, iv, block_size):
    """Encrypt using CBC mode."""
    # Get the hash code (HMAC) of the raw plaintext data
    hash_value = hmac.new(key, plaintext, hashlib.sha256).digest()
    print("HMAC:", hash_value, "-", len(hash_value), "bits")

    # Appends the HMAC to the raw plaintext data
    combined_plaintext = plaintext + hash_value
    print("plaintext:", combined_plaintext)

    # Pad the plaintext message
    padded_plaintext = pad(combined_plaintext, block_size)
    print("padded_plaintext:", padded_plaintext)

    previous = iv
    ciphertext = b""

    # Iterate over the ciphertext in blocks
    for i in range(0, len(padded_plaintext), block_size):
        block = padded_plaintext[i : i + block_size]
        cipher_block = xor_bytes(previous, block)  # Encrypt using XOR
        ciphertext += cipher_block
        previous = cipher_block

    return ciphertext

# Simulated CBC decryption function
def cbc_decrypt(ciphertext, key, iv, block_size):
    """Decrypt using CBC mode."""
    blocks = [iv]  # Initialize blocks with IV
    decrypted_message = b""

    # Iterate over the ciphertext in blocks
    for i in range(0, len(ciphertext), block_size):
        block = ciphertext[i : i + block_size]
        decrypted_block = xor_bytes(block, blocks[-1])  # Decrypt using XOR
        decrypted_message += decrypted_block
        blocks.append(block)  # Add the current block to the list of blocks for XOR with next block

    # Unpad the decrypted message and validate HMAC of original plaintext
    return unpad(decrypted_message, key)

def server_check_padding(modified_block, target_block, padding_value):
    # modified_block = C8's block
    # target_block = D8's block
    # plaintext_block = P8's block
    decrypted_byte = xor_bytes(modified_block, target_block)

    if isinstance(decrypted_byte, (bytes, bytearray)):
        decrypted_byte = list(decrypted_byte)

    # Extract out the padding bytes for Oracle check
    last_bytes = decrypted_byte[-padding_value:]
    # Valid padding: Padding value represents the number of padding bytes
    if last_bytes == [padding_value] * padding_value:
        return True
    else:
        raise ValueError("Oracle: Invalid padding!")

# Function to simulate POODLE attack on the SSL 3.0 connection between client (Alice) and server
def poodle_attack(ciphertext, iv, block_size, key):
    # modified_block = C8's block
    # target_block = D8's block
    # plaintext_block = P8's block
    # previous_block = IV
    decrypted_message = bytearray()

    # Split into blocks, including IV
    blocks = [iv] + [
        ciphertext[i : i + block_size] for i in range(0, len(ciphertext), block_size)
    ]

    # Start from the last block and work backwards
    # Range from (len(blocks)-1) down to 1 (excluding 0 since we don't decrypt IV)
    for block_index in range(len(blocks) - 1, 0, -1):

        decrypted_block = bytearray(block_size)
        plaintext_block = bytearray(block_size)
        target_block = blocks[block_index]
        previous_block = bytearray(blocks[block_index - 1])

        # Process each byte in the block from right to left
        for byte_index in range(block_size - 1, -1, -1):
            padding_value = block_size - byte_index
            found = False

            # Try all possible byte values
            for guess in range(256):
                modified_block = previous_block[:]
                modified_block[byte_index] = guess

                # Update bytes that we've already found to maintain valid padding
                for i in range(byte_index + 1, block_size):
                    # E.g. D8 = C8 xor P8
                    decrypted_block[i] = previous_block[i] ^ padding_value

                    # E.g. C8 = D8 xor P8
                    modified_block[i] = decrypted_block[i] ^ plaintext_block[i]

                try:
                    # Oracle check function
                    server_check = server_check_padding(
                        modified_block, 
                        target_block, 
                        padding_value
                    )

                    if server_check == True:
                        # Example:
                        # D8 xor C8 = 0x01
                        # D8 = C8 xor 0x01
                        decrypted_block[byte_index] = (modified_block[byte_index] ^ padding_value)
                        
                        # Example:
                        # P8 xor original C8 = D8
                        # P8 = D8 xor original C8
                        plaintext_block[byte_index] = (decrypted_block[byte_index] ^ previous_block[byte_index])

                        st.write(
                            "Block No: ",
                            block_index,
                            ". Decrypted byte: ",
                            byte_index,
                            " . Value is ",
                            chr(plaintext_block[byte_index]),
                        )
                        found = True
                        break

                except ValueError:
                    continue

            if not found:
                raise ValueError(
                    f"Failed to decrypt byte {byte_index} in block {block_index}"
                )

        # Insert the decrypted block at the beginning of our message
        # This maintains correct order since we're decrypting from end to start
        decrypted_message[0:0] = plaintext_block

    # Unpad the decrypted message and validate HMAC of original plaintext
    return unpad(bytes(decrypted_message), key)