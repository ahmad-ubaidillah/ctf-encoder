# CTF Encoder/Decoder Tool

A versatile Python GUI tool for decoding various encoding schemes commonly encountered in CTF (Capture The Flag) challenges. Supports multiple encoding formats and cipher techniques.

---

## Features

- Decode multiple encoding schemes in one click
- Supports Base64, Base32, Base85, Base58, Hex, URL, Quoted-printable, HTML entities, and UUencode
- Supports cipher techniques: ROT13, ROT5, Atbash, Caesar Shift (1-25), XOR Brute-force, Vigenère, Rail Fence (2-5 rails)
- Morse code decoding
- Simple substitution cipher decoding
- Automatic flag pattern detection
- Dark theme interface

## Supported Encoding Methods

1. **Base Decodings**
   - Base64
   - Base32
   - Base85
   - Base58

2. **Hexadecimal**
   - Hex Decode

3. **URL Encoding**
   - URL Decode (once)
   - URL Decode (twice)

4. **Other Standard Encodings**
   - Quoted-printable
   - HTML entities
   - UUencode

5. **Cipher Techniques**
   - ROT13
   - ROT5 (digits)
   - Atbash
   - Caesar Shift (1-25)
   - XOR Brute-force (all possible keys)
   - Vigenère Cipher
   - Rail Fence Cipher (2-5 rails)

6. **Miscellaneous**
   - Morse Code
   - Simple Substitution Cipher

## Requirements

- Python 3.8+
- Supported on Windows, macOS, and Linux

## Installation

1. **Clone this repository:**
   ```bash
   git clone https://github.com/your-username/ctf-encoder.git
   cd ctf-encoder
   ```

2. **Create and activate a virtual environment:**
   ```bash
    python3 -m venv venv
    # Activate on Windows:
    venv\Scripts\activate
    # Activate on macOS/Linux:
    source venv/bin/activate
   ```

3. **Install the dependencies:**

   ```bash
    pip3 install -r requirements.txt
   ```

4. **Install tkinter on Linux / Mac (Optional, If you doesn't have it):**

   ```bash
   sudo apt update
   sudo apt install python3-tk
   ```

5. **Run the tool:**

   ```bash
    python ctf_encoder.py
   ```

6. **The Logic:**
   This app will decode your encoded text using multiple encoding formats and cipher techniques. It will then search through all the decoded results using the flag you’ve set and display any matching flags found.


7. **Instructions:**
   **In the GUI:**
   - Enter encoded text in the input box
   - Enable Vigenère cipher (if needed) and enter key
   - Enable substitution cipher (if needed) and enter alphabets
   - Set flag patterns (comma-separated regex patterns)
   - Click "Decode" to see results

   **Results will show:**
   - All possible decoded variants
   - Flag matches highlighted in green with 🔥 icon
   - Click "Copy Flag" in popup to copy found flags

**Example:**

   **Caesar Cipher:**
   - Encode: PKU_JAM{ZalNhU0_Jv0sly}
   - Flag: IDN_CTF{}, IDN_FLAG{}
   - Result:IDN_CTF{SteGaN0_Co0ler}

   **Vigenère Cipher:**
   - Encode: QGA_OTS{v067j1723qk40f5v33z656afwse60kdf67u9606}
   - Flag: IDN_CTF{}, IDN_FLAG{}
   - Vigenère Cipher = True (enable it with mark the Vigenère Cipher)
   - Vigenère key: idnmantab
   - Result:IDN_CTF{c067j1723pc40c5i33n656asdsd60cas67i9606}

   **Substitution Cipher:**
   - Encode: ORF_EZY{ziol_ol_g_yqsx_wxz_lg_tq_ln}
   - Flag: IDN_CTF{}, IDN_FLAG{}
   - Substitution Cipher = True (enable it with mark the substitution Cipher)
   - Plain Text: ABCDEFGHIJKLMNOPQRSTUVWXYZ
   - Substituted Text: QWERTYUIOPASDFGHJKLZXCVBNM
   - Result:IDN_CTF{this_is_o_falu_but_so_easy} (in real CTF on IDN it need to convert using uppercase)