import tkinter as tk
from tkinter import ttk, messagebox
from tkinter.scrolledtext import ScrolledText
import base64
import binascii
import codecs
import re
import string
import base58
import quopri
import html
import urllib.parse
from chardet import detect

def try_decode_utf(text):
    if isinstance(text, bytes):
        enc = detect(text)['encoding'] or 'utf-8'
        try:
            return text.decode(enc)
        except:
            return text.decode('utf-8', errors='ignore')
    return text

def base64_decode(text):
    try:
        while len(text) % 4 != 0:
            text += '='
        return base64.b64decode(text).decode('utf-8', errors='ignore')
    except Exception:
        return None

def base32_decode(text):
    try:
        while len(text) % 8 != 0:
            text += '='
        return base64.b32decode(text).decode('utf-8', errors='ignore')
    except Exception:
        return None

def base85_decode(text):
    try:
        return base64.b85decode(text).decode('utf-8', errors='ignore')
    except Exception:
        return None

def base58_decode(text):
    try:
        return base58.b58decode(text).decode('utf-8', errors='ignore')
    except Exception:
        return None

def hex_decode(text):
    try:
        text = text.strip()
        if text.startswith('0x') or text.startswith('0X'):
            text = text[2:]
        text = text.replace(" ", "").replace("\n", "")
        return bytes.fromhex(text).decode('utf-8', errors='ignore')
    except Exception:
        return None

def url_decode(text):
    try:
        return urllib.parse.unquote(text)
    except Exception:
        return None

def url_double_decode(text):
    try:
        once = urllib.parse.unquote(text)
        twice = urllib.parse.unquote(once)
        return twice
    except Exception:
        return None

def quoted_printable_decode(text):
    try:
        return quopri.decodestring(text).decode('utf-8', errors='ignore')
    except Exception:
        return None

def html_entity_decode(text):
    try:
        return html.unescape(text)
    except Exception:
        return None

def uudecode(text):
    try:
        return binascii.a2b_uu(text).decode('utf-8', errors='ignore')
    except Exception:
        return None

def rot13(text):
    return text.translate(str.maketrans(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
        "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm"))

def rot5(text):
    result = []
    for c in text:
        if c.isdigit():
            result.append(str((int(c) + 5) % 10))
        else:
            result.append(c)
    return ''.join(result)

def atbash(text):
    result = []
    for c in text:
        if c.isalpha():
            if c.isupper():
                result.append(chr(90 - (ord(c) - 65)))
            else:
                result.append(chr(122 - (ord(c) - 97)))
        else:
            result.append(c)
    return ''.join(result)

def morse_decode(text):
    MORSE_CODE_DICT = {
        '.-':'A', '-...':'B', '-.-.':'C', '-..':'D', '.':'E',
        '..-.':'F', '--.':'G', '....':'H', '..':'I', '.---':'J',
        '-.-':'K', '.-..':'L', '--':'M', '-.':'N', '---':'O',
        '.--.':'P', '--.-':'Q', '.-.':'R', '...':'S', '-':'T',
        '..-':'U', '...-':'V', '.--':'W', '-..-':'X', '-.--':'Y',
        '--..':'Z', '-----':'0', '.----':'1', '..---':'2', '...--':'3',
        '....-':'4', '.....':'5', '-....':'6', '--...':'7', '---..':'8',
        '----.':'9'
    }
    words = text.strip().split('   ')
    decoded = []
    for word in words:
        chars = word.split()
        decoded_word = ''.join(MORSE_CODE_DICT.get(c, '') for c in chars)
        decoded.append(decoded_word)
    return ' '.join(decoded)

def caesar_shift(text, shift):
    result = []
    for c in text:
        if c.isalpha():
            base = 65 if c.isupper() else 97
            shifted = (ord(c) - base + shift) % 26 + base
            result.append(chr(shifted))
        else:
            result.append(c)
    return ''.join(result)

def substitution_decode(text, plain_alphabet, substituted_alphabet):
    """Decode text using a simple substitution cipher with the given alphabets."""
    if not plain_alphabet or not substituted_alphabet or len(plain_alphabet) != len(substituted_alphabet):
        return None
    
    # Create a mapping from each character in the substituted alphabet to the corresponding character in the plain alphabet
    # We need to handle both uppercase and lowercase
    mapping = {}
    
    # Add uppercase mappings
    for i in range(len(substituted_alphabet)):
        if i < len(plain_alphabet):
            sub_char = substituted_alphabet[i].upper()
            plain_char = plain_alphabet[i].upper()
            mapping[sub_char] = plain_char
    
    # Add lowercase mappings
    for i in range(len(substituted_alphabet)):
        if i < len(plain_alphabet):
            sub_char = substituted_alphabet[i].lower()
            plain_char = plain_alphabet[i].lower()
            mapping[sub_char] = plain_char
    
    # Apply the mapping
    result = []
    for char in text:
        if char in mapping:
            result.append(mapping[char])
        else:
            result.append(char)  # Keep non-alphabet characters as is
    
    return ''.join(result)

def xor_bruteforce(text):
    results = []
    bytes_data = text.encode('latin1', errors='ignore')
    for key in range(256):
        try:
            decoded = ''.join(chr(b ^ key) for b in bytes_data)
            if sum(c in string.printable for c in decoded) / max(len(decoded), 1) > 0.85:
                results.append((key, decoded))
        except:
            continue
    return results

def vigenere_decrypt(ciphertext, key):
    if not key:
        return None
    key = key.lower()
    plaintext = []
    key_len = len(key)
    key_index = 0
    for char in ciphertext:
        if char.isalpha():
            offset = ord('a') if char.islower() else ord('A')
            k = ord(key[key_index % key_len]) - ord('a')
            p = (ord(char) - offset - k) % 26
            plaintext.append(chr(p + offset))
            key_index += 1
        else:
            plaintext.append(char)
    return ''.join(plaintext)

def check_flag_patterns(text, patterns):
    for p in patterns:
        p = p.strip()
        if not p:
            continue
        regex = re.escape(p).replace('\\{\\}', '.*')
        if re.search(regex, text):
            return True
    return False

def all_decode_methods(text, vigenere_key, patterns, sub_plain=None, sub_cipher=None):
    results = []

    # Direct text
    results.append(('Original', text))

    # Simple Substitution Cipher
    if sub_plain and sub_cipher:
        sub_decoded = substitution_decode(text, sub_plain, sub_cipher)
        if sub_decoded and sub_decoded != text:
            results.append(('Simple Substitution', sub_decoded))

    # Base decodes
    for fn, name in [(base64_decode, 'Base64'),
                     (base32_decode, 'Base32'),
                     (base85_decode, 'Base85'),
                     (base58_decode, 'Base58'),
                     (hex_decode, 'Hex'),
                     (url_decode, 'URL decode once'),
                     (url_double_decode, 'URL decode twice'),
                     (quoted_printable_decode, 'Quoted-printable'),
                     (html_entity_decode, 'HTML entities'),
                     (uudecode, 'UUdecode')]:
        decoded = fn(text)
        if decoded and decoded != text:
            results.append((name, decoded))

    # Rotations/shifts
    rot13_decoded = rot13(text)
    if rot13_decoded != text:
        results.append(('ROT13', rot13_decoded))

    rot5_decoded = rot5(text)
    if rot5_decoded != text:
        results.append(('ROT5 (digit)', rot5_decoded))

    atbash_decoded = atbash(text)
    if atbash_decoded != text:
        results.append(('Atbash', atbash_decoded))

    for shift in range(1, 26):
        shifted = caesar_shift(text, shift)
        if shifted != text:
            results.append((f'Caesar shift {shift}', shifted))

    if all(c in '.- |0123456789' for c in text):
        morse_decoded = morse_decode(text)
        if morse_decoded and morse_decoded != text:
            results.append(('Morse decode', morse_decoded))

    if len(text) <= 50:
        xor_results = xor_bruteforce(text)
        for key, decoded in xor_results:
            results.append((f'XOR key={key}', decoded))

    # Vigenère
    if vigenere_key:
        vig_decoded = vigenere_decrypt(text, vigenere_key)
        if vig_decoded and vig_decoded != text:
            results.append(('Vigenère', vig_decoded))

    # Check for rail fence (2-5 rails)
    for rails in range(2, 6):
        try:
            fence = [['' for _ in range(len(text))] for _ in range(rails)]
            rail = 0
            var = 1
            for i in range(len(text)):
                fence[rail][i] = text[i]
                rail += var
                if rail == rails - 1:
                    var = -1
                elif rail == 0:
                    var = 1
            decoded = []
            for r in fence:
                decoded.extend(r)
            decoded = ''.join(decoded)
            if decoded != text:
                results.append((f'Rail Fence {rails} rails', decoded))
        except:
            continue

    # Filter duplicates
    seen = set()
    filtered = []
    for n, r in results:
        if r not in seen:
            filtered.append((n, r))
            seen.add(r)
    return filtered

class CTFDecoderGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("CTF Decoder Tool")
        self.geometry("800x600")
        self.configure(bg="#1e1e2e")

        # Configure dark theme for all widgets
        style = ttk.Style(self)
        style.theme_use('clam')
        
        # Configure colors for all widget types
        style.configure(".", background="#1e1e2e", foreground="#ffffff")
        style.configure("TLabel", background="#1e1e2e", foreground="#ffffff")
        style.configure("TButton", background="#313244", foreground="#ffffff")
        style.map("TButton", 
                  background=[('active', '#45475a')],
                  foreground=[('active', '#ffffff')])
        style.configure("TEntry", fieldbackground="#313244", foreground="#ffffff", insertcolor="#ffffff")
        style.configure("TFrame", background="#1e1e2e")
        style.configure("TCheckbutton", background="#1e1e2e", foreground="#ffffff")
        style.map("TCheckbutton",
                  background=[('active', '#1e1e2e')],
                  foreground=[('active', '#ffffff')])

        # Input
        input_frame = ttk.Frame(self)
        input_frame.pack(fill='x', padx=10, pady=(10, 0))
        
        ttk.Label(input_frame, text="Encoded Text:").pack(side='left')
        clear_btn = ttk.Button(input_frame, text="Clear", width=5, 
                               command=lambda: self.text_encoded.delete("1.0", "end"))
        clear_btn.pack(side='right')
        
        self.text_encoded = tk.Text(self, height=4, bg="#313244", fg="#ffffff", insertbackground="#ffffff", wrap='word')
        self.text_encoded.pack(fill='x', padx=10, pady=(0, 10))

        # Vigenère Cipher Section
        self.use_vigenere = tk.BooleanVar(value=False)
        vigenere_check_frame = ttk.Frame(self)
        vigenere_check_frame.pack(fill='x', padx=10, pady=(0, 5))
        
        self.vigenere_check = ttk.Checkbutton(
            vigenere_check_frame, 
            text="Use Vigenère Cipher", 
            variable=self.use_vigenere,
            command=self.toggle_vigenere
        )
        self.vigenere_check.pack(side='left')
        
        vigenere_frame = ttk.Frame(self)
        vigenere_frame.pack(fill='x', padx=10, pady=(0, 10))
        
        ttk.Label(vigenere_frame, text="Vigenère Key:").pack(side='left')
        self.entry_vigenere = ttk.Entry(vigenere_frame, state='disabled')
        self.entry_vigenere.pack(side='left', fill='x', expand=True, padx=(5, 5))
        
        clear_vigenere_btn = ttk.Button(vigenere_frame, text="Clear", width=5,
                                       command=lambda: self.entry_vigenere.delete(0, "end"))
        clear_vigenere_btn.pack(side='right')

        # Simple Substitution Cipher Section
        self.use_substitution = tk.BooleanVar(value=False)
        sub_check_frame = ttk.Frame(self)
        sub_check_frame.pack(fill='x', padx=10, pady=(0, 5))
        
        self.sub_check = ttk.Checkbutton(
            sub_check_frame, 
            text="Use Substitution Cipher", 
            variable=self.use_substitution,
            command=self.toggle_substitution
        )
        self.sub_check.pack(side='left')
        
        sub_plain_frame = ttk.Frame(self)
        sub_plain_frame.pack(fill='x', padx=10, pady=(0, 5))
        
        ttk.Label(sub_plain_frame, text="Plain Alphabet:").pack(side='left')
        self.entry_sub_plain = ttk.Entry(sub_plain_frame, state='disabled')
        self.entry_sub_plain.pack(side='left', fill='x', expand=True, padx=(5, 5))
        
        clear_plain_btn = ttk.Button(sub_plain_frame, text="Clear", width=5,
                                    command=lambda: self.entry_sub_plain.delete(0, "end"))
        clear_plain_btn.pack(side='right')

        sub_cipher_frame = ttk.Frame(self)
        sub_cipher_frame.pack(fill='x', padx=10, pady=(0, 10))
        
        ttk.Label(sub_cipher_frame, text="Cipher Alphabet:").pack(side='left')
        self.entry_sub_cipher = ttk.Entry(sub_cipher_frame, state='disabled')
        self.entry_sub_cipher.pack(side='left', fill='x', expand=True, padx=(5, 5))
        
        clear_cipher_btn = ttk.Button(sub_cipher_frame, text="Clear", width=5,
                                     command=lambda: self.entry_sub_cipher.delete(0, "end"))
        clear_cipher_btn.pack(side='right')

        # Flag Patterns
        flag_frame = ttk.Frame(self)
        flag_frame.pack(fill='x', padx=10, pady=(0, 10))
        
        ttk.Label(flag_frame, text="Flag Patterns:").pack(side='left')
        self.text_flags = ttk.Entry(flag_frame)
        self.text_flags.pack(side='left', fill='x', expand=True, padx=(5, 5))
        self.text_flags.insert(0, "HTB{.*},FLAG{.*},CTF{.*},IDN_CTF{.*}")
        
        clear_flags_btn = ttk.Button(flag_frame, text="Clear", width=5,
                                    command=lambda: self.text_flags.delete(0, "end"))
        clear_flags_btn.pack(side='right')

        # Buttons
        frame_btn = ttk.Frame(self)
        frame_btn.pack(pady=5, padx=10, fill='x')

        self.btn_decode = ttk.Button(frame_btn, text="Decode", command=self.decode_and_display)
        self.btn_decode.pack(side='left', padx=5)

        self.btn_clear = ttk.Button(frame_btn, text="Clear All", command=self.clear_all)
        self.btn_clear.pack(side='left', padx=5)

        # Results
        ttk.Label(self, text="Decoding Results:").pack(anchor='w', padx=10, pady=10)
        self.text_results = ScrolledText(self, height=20, bg="#313244", fg="#ffffff", insertbackground="#ffffff", wrap='word')
        self.text_results.pack(fill='both', expand=True, padx=10, pady=(0, 10))
        
        # Initialize the toggle states
        self.toggle_vigenere()
        self.toggle_substitution()

    def toggle_vigenere(self):
        """Enable or disable Vigenère key entry based on checkbox state"""
        if self.use_vigenere.get():
            self.entry_vigenere.config(state='normal')
        else:
            self.entry_vigenere.delete(0, "end")
            self.entry_vigenere.config(state='disabled')

    def toggle_substitution(self):
        """Enable or disable substitution cipher entries based on checkbox state"""
        if self.use_substitution.get():
            self.entry_sub_plain.config(state='normal')
            self.entry_sub_cipher.config(state='normal')
        else:
            self.entry_sub_plain.delete(0, "end")
            self.entry_sub_cipher.delete(0, "end")
            self.entry_sub_plain.config(state='disabled')
            self.entry_sub_cipher.config(state='disabled')

    def decode_and_display(self):
        encoded_text = self.text_encoded.get("1.0", "end").strip()
        
        # Get Vigenère key if enabled
        vigenere_key = ""
        if self.use_vigenere.get():
            vigenere_key = self.entry_vigenere.get().strip()
        
        # Get substitution alphabets if enabled
        sub_plain = ""
        sub_cipher = ""
        if self.use_substitution.get():
            sub_plain = self.entry_sub_plain.get().strip()
            sub_cipher = self.entry_sub_cipher.get().strip()
        
        pattern_str = self.text_flags.get().strip()

        if not encoded_text:
            messagebox.showwarning("Input Missing", "Please enter some encoded text.")
            return

        patterns = pattern_str.split(',')
        results = all_decode_methods(encoded_text, vigenere_key, patterns, sub_plain, sub_cipher)

        self.text_results.delete("1.0", "end")

        found_matches = []

        for method, result in results:
            matched = check_flag_patterns(result, patterns)
            if matched:
                found_matches.append(result)
                self.text_results.insert("end", f"[{method}] 🔥 {result}\n\n", "highlight")
            else:
                self.text_results.insert("end", f"[{method}] {result}\n\n")

        self.text_results.tag_config("highlight", foreground="#a6e3a1", font=("Consolas", 10, "bold"))

        if found_matches:
            self.show_flag_popup(found_matches)

    def show_flag_popup(self, flags):
        popup = tk.Toplevel(self)
        popup.title("🎉 Flag(s) Found!")
        popup.geometry("500x300")
        popup.configure(bg="#1e1e2e")

        label = ttk.Label(popup, text="The following flag(s) were found:", font=('Arial', 12, 'bold'))
        label.pack(pady=10)

        text = ScrolledText(popup, bg="#313244", fg="#a6e3a1", wrap='word', height=10)
        text.pack(fill='both', expand=True, padx=10, pady=10)
        text.insert("1.0", "\n".join(flags))
        text.config(state='disabled')

        def copy_to_clipboard():
            self.clipboard_clear()
            self.clipboard_append("\n".join(flags))
            messagebox.showinfo("Copied", "Flags copied to clipboard!")

        btn_frame = ttk.Frame(popup)
        btn_frame.pack(pady=10)

        ttk.Button(btn_frame, text="Copy Flag", command=copy_to_clipboard).pack(side='left', padx=5)
        ttk.Button(btn_frame, text="Close", command=popup.destroy).pack(side='left', padx=5)

    def clear_all(self):
        self.text_encoded.delete("1.0", "end")
        
        # Reset Vigenère
        self.use_vigenere.set(False)
        self.toggle_vigenere()
        
        # Reset Substitution
        self.use_substitution.set(False)
        self.toggle_substitution()
        
        # Reset flags
        self.text_flags.delete(0, "end")
        self.text_flags.insert(0, "HTB{.*},FLAG{.*},CTF{.*},IDN_CTF{.*}")
        
        # Clear results
        self.text_results.delete("1.0", "end")

if __name__ == "__main__":
    app = CTFDecoderGUI()
    app.mainloop()
