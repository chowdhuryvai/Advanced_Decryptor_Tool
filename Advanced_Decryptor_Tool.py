import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import base64
import binascii
from collections import Counter
import string

class ChowdhuryVaiDecryptor:
    def __init__(self, root):
        self.root = root
        self.root.title("ChowdhuryVai Advanced Decryptor Tool")
        self.root.geometry("900x700")
        self.root.configure(bg='#0a0a0a')
        
        # Color scheme
        self.colors = {
            'bg': '#0a0a0a',
            'fg': '#00ff00',
            'accent': '#ff00ff',
            'secondary': '#0088ff',
            'warning': '#ffff00',
            'text_bg': '#1a1a1a'
        }
        
        self.setup_ui()
        
    def setup_ui(self):
        # Header
        header_frame = tk.Frame(self.root, bg=self.colors['bg'])
        header_frame.pack(fill='x', padx=20, pady=10)
        
        title_label = tk.Label(
            header_frame,
            text="▓▒░ CHOWDHURYVAI ADVANCED DECRYPTOR ░▒▓",
            font=('Courier', 20, 'bold'),
            fg=self.colors['accent'],
            bg=self.colors['bg']
        )
        title_label.pack()
        
        subtitle_label = tk.Label(
            header_frame,
            text="Professional Encryption Analysis Toolkit",
            font=('Courier', 12),
            fg=self.colors['fg'],
            bg=self.colors['bg']
        )
        subtitle_label.pack(pady=5)
        
        # Main content frame
        main_frame = tk.Frame(self.root, bg=self.colors['bg'])
        main_frame.pack(fill='both', expand=True, padx=20, pady=10)
        
        # Input section
        input_frame = tk.LabelFrame(
            main_frame,
            text=" ENCRYPTED INPUT ",
            font=('Courier', 10, 'bold'),
            fg=self.colors['secondary'],
            bg=self.colors['bg'],
            bd=2,
            relief='groove'
        )
        input_frame.pack(fill='x', pady=10)
        
        self.input_text = scrolledtext.ScrolledText(
            input_frame,
            height=6,
            font=('Courier', 10),
            fg=self.colors['fg'],
            bg=self.colors['text_bg'],
            insertbackground=self.colors['fg'],
            wrap=tk.WORD
        )
        self.input_text.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Method selection
        method_frame = tk.LabelFrame(
            main_frame,
            text=" DECRYPTION METHODS ",
            font=('Courier', 10, 'bold'),
            fg=self.colors['secondary'],
            bg=self.colors['bg'],
            bd=2,
            relief='groove'
        )
        method_frame.pack(fill='x', pady=10)
        
        methods = [
            "Base64", "Hex", "Binary", "ROT13", 
            "Caesar Cipher", "Reverse", "URL Encoding",
            "Morse Code", "Atbash Cipher"
        ]
        
        self.method_var = tk.StringVar(value="Base64")
        for i, method in enumerate(methods):
            rb = tk.Radiobutton(
                method_frame,
                text=method,
                variable=self.method_var,
                value=method,
                font=('Courier', 9),
                fg=self.colors['fg'],
                bg=self.colors['bg'],
                selectcolor=self.colors['text_bg'],
                activebackground=self.colors['bg']
            )
            rb.grid(row=i//3, column=i%3, sticky='w', padx=10, pady=5)
        
        # Control buttons
        button_frame = tk.Frame(main_frame, bg=self.colors['bg'])
        button_frame.pack(fill='x', pady=10)
        
        decrypt_btn = tk.Button(
            button_frame,
            text="▓▒░ DECRYPT NOW ░▒▓",
            font=('Courier', 12, 'bold'),
            fg='black',
            bg=self.colors['warning'],
            command=self.decrypt_text,
            width=20,
            height=2
        )
        decrypt_btn.pack(side='left', padx=5)
        
        clear_btn = tk.Button(
            button_frame,
            text="▓▒░ CLEAR ALL ░▒▓",
            font=('Courier', 12, 'bold'),
            fg='black',
            bg=self.colors['secondary'],
            command=self.clear_all,
            width=15,
            height=2
        )
        clear_btn.pack(side='left', padx=5)
        
        auto_btn = tk.Button(
            button_frame,
            text="▓▒░ AUTO DETECT ░▒▓",
            font=('Courier', 12, 'bold'),
            fg='black',
            bg=self.colors['accent'],
            command=self.auto_detect,
            width=15,
            height=2
        )
        auto_btn.pack(side='left', padx=5)
        
        # Output section
        output_frame = tk.LabelFrame(
            main_frame,
            text=" DECRYPTED OUTPUT ",
            font=('Courier', 10, 'bold'),
            fg=self.colors['secondary'],
            bg=self.colors['bg'],
            bd=2,
            relief='groove'
        )
        output_frame.pack(fill='both', expand=True, pady=10)
        
        self.output_text = scrolledtext.ScrolledText(
            output_frame,
            height=8,
            font=('Courier', 10),
            fg=self.colors['fg'],
            bg=self.colors['text_bg'],
            insertbackground=self.colors['fg'],
            wrap=tk.WORD
        )
        self.output_text.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Footer with contact info
        footer_frame = tk.Frame(self.root, bg=self.colors['bg'])
        footer_frame.pack(fill='x', pady=10)
        
        contact_info = [
            "Telegram ID: https://t.me/darkvaiadmin",
            "Telegram Channel: https://t.me/windowspremiumkey", 
            "Hacking/Cracking Website: https://crackyworld.com/"
        ]
        
        for info in contact_info:
            contact_label = tk.Label(
                footer_frame,
                text=info,
                font=('Courier', 9),
                fg=self.colors['secondary'],
                bg=self.colors['bg']
            )
            contact_label.pack(pady=2)
        
        status_label = tk.Label(
            footer_frame,
            text="▓▒░ CHOWDHURYVAI TOOLS - PROFESSIONAL HACKING SOLUTIONS ░▒▓",
            font=('Courier', 10, 'bold'),
            fg=self.colors['accent'],
            bg=self.colors['bg']
        )
        status_label.pack(pady=5)
    
    def decrypt_text(self):
        input_data = self.input_text.get('1.0', tk.END).strip()
        method = self.method_var.get()
        
        if not input_data:
            messagebox.showwarning("Warning", "Please enter encrypted text!")
            return
        
        try:
            result = ""
            
            if method == "Base64":
                result = self.decode_base64(input_data)
            elif method == "Hex":
                result = self.decode_hex(input_data)
            elif method == "Binary":
                result = self.decode_binary(input_data)
            elif method == "ROT13":
                result = self.decode_rot13(input_data)
            elif method == "Caesar Cipher":
                result = self.brute_force_caesar(input_data)
            elif method == "Reverse":
                result = self.decode_reverse(input_data)
            elif method == "URL Encoding":
                result = self.decode_url(input_data)
            elif method == "Morse Code":
                result = self.decode_morse(input_data)
            elif method == "Atbash Cipher":
                result = self.decode_atbash(input_data)
            
            self.output_text.delete('1.0', tk.END)
            self.output_text.insert('1.0', result)
            
        except Exception as e:
            self.output_text.delete('1.0', tk.END)
            self.output_text.insert('1.0', f"Error: {str(e)}\n\nPossible reasons:\n- Invalid format for selected method\n- Corrupted data\n- Wrong decryption method selected")
    
    def auto_detect(self):
        input_data = self.input_text.get('1.0', tk.END).strip()
        
        if not input_data:
            messagebox.showwarning("Warning", "Please enter encrypted text!")
            return
        
        results = []
        
        # Try different methods
        methods = [
            ("Base64", self.decode_base64),
            ("Hex", self.decode_hex),
            ("Binary", self.decode_binary),
            ("ROT13", self.decode_rot13),
            ("Reverse", self.decode_reverse),
            ("URL Encoding", self.decode_url),
            ("Atbash Cipher", self.decode_atbash)
        ]
        
        for method_name, method_func in methods:
            try:
                result = method_func(input_data)
                if result and len(result) > 0:
                    # Simple heuristic to check if result looks like text
                    if self.looks_like_text(result):
                        results.append((method_name, result))
            except:
                pass
        
        # Also try Caesar cipher brute force
        caesar_results = self.brute_force_caesar(input_data)
        if "Possible matches" in caesar_results:
            results.append(("Caesar Cipher", caesar_results))
        
        # Display results
        self.output_text.delete('1.0', tk.END)
        if results:
            output = "AUTO-DETECTION RESULTS:\n" + "="*50 + "\n\n"
            for method, result in results:
                output += f"🔍 {method}:\n{result}\n" + "-"*40 + "\n"
            self.output_text.insert('1.0', output)
        else:
            self.output_text.insert('1.0', "❌ No encryption method detected automatically.\nTry manual method selection.")
    
    def looks_like_text(self, text):
        """Simple heuristic to check if text looks like readable content"""
        if len(text) == 0:
            return False
        
        # Check if text contains mostly printable characters
        printable_count = sum(1 for c in text if c in string.printable)
        return (printable_count / len(text)) > 0.8
    
    def decode_base64(self, text):
        try:
            # Add padding if needed
            padding = 4 - len(text) % 4
            if padding != 4:
                text += '=' * padding
            
            decoded = base64.b64decode(text).decode('utf-8', errors='ignore')
            return f"Base64 Decoded:\n{decoded}"
        except:
            # Try URL-safe base64
            try:
                decoded = base64.urlsafe_b64decode(text).decode('utf-8', errors='ignore')
                return f"Base64 (URL-safe) Decoded:\n{decoded}"
            except:
                raise ValueError("Invalid Base64 encoding")
    
    def decode_hex(self, text):
        # Remove spaces and common prefixes
        text = text.replace(' ', '').replace('0x', '').replace('\\x', '')
        
        try:
            decoded = bytes.fromhex(text).decode('utf-8', errors='ignore')
            return f"Hex Decoded:\n{decoded}"
        except:
            raise ValueError("Invalid hex encoding")
    
    def decode_binary(self, text):
        # Remove spaces and split into bytes
        text = text.replace(' ', '')
        
        try:
            # Convert binary string to text
            chars = []
            for i in range(0, len(text), 8):
                byte = text[i:i+8]
                if len(byte) == 8:
                    chars.append(chr(int(byte, 2)))
            
            decoded = ''.join(chars)
            return f"Binary Decoded:\n{decoded}"
        except:
            raise ValueError("Invalid binary encoding")
    
    def decode_rot13(self, text):
        result = []
        for char in text:
            if 'a' <= char <= 'z':
                result.append(chr((ord(char) - ord('a') + 13) % 26 + ord('a')))
            elif 'A' <= char <= 'Z':
                result.append(chr((ord(char) - ord('A') + 13) % 26 + ord('A')))
            else:
                result.append(char)
        
        decoded = ''.join(result)
        return f"ROT13 Decoded:\n{decoded}"
    
    def brute_force_caesar(self, text):
        results = []
        for shift in range(1, 26):
            decoded = []
            for char in text:
                if 'a' <= char <= 'z':
                    decoded.append(chr((ord(char) - ord('a') - shift) % 26 + ord('a')))
                elif 'A' <= char <= 'Z':
                    decoded.append(chr((ord(char) - ord('A') - shift) % 26 + ord('A')))
                else:
                    decoded.append(char)
            results.append((shift, ''.join(decoded)))
        
        # Try to identify the most likely result
        likely_results = []
        for shift, result in results:
            if self.looks_like_text(result):
                likely_results.append((shift, result))
        
        output = "Caesar Cipher Brute Force:\n"
        if likely_results:
            output += "Most likely matches:\n"
            for shift, result in likely_results[:3]:  # Show top 3
                output += f"Shift {shift}: {result[:50]}...\n"
        else:
            output += "All possible shifts:\n"
            for shift, result in results:
                output += f"Shift {shift:2d}: {result}\n"
        
        return output
    
    def decode_reverse(self, text):
        return f"Reversed:\n{text[::-1]}"
    
    def decode_url(self, text):
        try:
            # Simple URL decoding
            decoded = text.replace('%20', ' ').replace('%21', '!').replace('%22', '"')
            decoded = decoded.replace('%23', '#').replace('%24', '$').replace('%25', '%')
            decoded = decoded.replace('%26', '&').replace('%27', "'").replace('%28', '(')
            decoded = decoded.replace('%29', ')').replace('%2B', '+').replace('%2C', ',')
            decoded = decoded.replace('%2F', '/').replace('%3A', ':').replace('%3B', ';')
            decoded = decoded.replace('%3D', '=').replace('%3F', '?').replace('%40', '@')
            
            return f"URL Decoded:\n{decoded}"
        except:
            raise ValueError("Invalid URL encoding")
    
    def decode_morse(self, text):
        morse_dict = {
            '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E',
            '..-.': 'F', '--.': 'G', '....': 'H', '..': 'I', '.---': 'J',
            '-.-': 'K', '.-..': 'L', '--': 'M', '-.': 'N', '---': 'O',
            '.--.': 'P', '--.-': 'Q', '.-.': 'R', '...': 'S', '-': 'T',
            '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X', '-.--': 'Y',
            '--..': 'Z', '-----': '0', '.----': '1', '..---': '2', '...--': '3',
            '....-': '4', '.....': '5', '-....': '6', '--...': '7', '---..': '8',
            '----.': '9', '/': ' '
        }
        
        try:
            words = text.split(' / ')
            decoded_words = []
            
            for word in words:
                letters = word.split(' ')
                decoded_letters = []
                for letter in letters:
                    if letter in morse_dict:
                        decoded_letters.append(morse_dict[letter])
                    else:
                        decoded_letters.append('?')
                decoded_words.append(''.join(decoded_letters))
            
            decoded = ' '.join(decoded_words)
            return f"Morse Code Decoded:\n{decoded}"
        except:
            raise ValueError("Invalid Morse code")
    
    def decode_atbash(self, text):
        result = []
        for char in text:
            if 'a' <= char <= 'z':
                result.append(chr(ord('z') - (ord(char) - ord('a'))))
            elif 'A' <= char <= 'Z':
                result.append(chr(ord('Z') - (ord(char) - ord('A'))))
            else:
                result.append(char)
        
        decoded = ''.join(result)
        return f"Atbash Cipher Decoded:\n{decoded}"
    
    def clear_all(self):
        self.input_text.delete('1.0', tk.END)
        self.output_text.delete('1.0', tk.END)

def main():
    root = tk.Tk()
    app = ChowdhuryVaiDecryptor(root)
    root.mainloop()

if __name__ == "__main__":
    main()
