#!/usr/bin/env python3
"""
CTFlow - A CTF analysis tool for beginners
Helps analyze challenge files and recommend appropriate tools
"""
import sys
import os
import argparse
from pathlib import Path
import pypdf  

HELP_FLAG_ART = """
 ****   *****  ******* **       *****   **   **
**  **    **   **      **      **   **  **   **
**        **   ******* **      **   **  ** * **
**        **   **      **      **   **  *******
 ****     **   **      *******   ****   **   **
"""

class CTFCategory:
    """CTF Category definitions"""
    WEB = "Web Exploitation"
    FORENSICS = "Digital Forensics"
    STEGO = "Steganography"
    OSINT = "OSINT"
    REVERSE = "Reverse Engineering"
    CRYPTO = "Cryptography"
    BINARY = "Binary Exploitation"

UNRESOLVED_HINTS = {
    CTFCategory.WEB: [
        "Try alternative HTTP methods: PUT, DELETE, OPTIONS.",
        "Check robots.txt and sitemap.xml for hidden endpoints.",
        "Look for encoded strings in JS (Base64, hex).",
        "Use ffuf or dirsearch to discover hidden paths."
    ],
    CTFCategory.FORENSICS: [
        "Use foremost or scalpel for file carving.",
        "Analyze file headers with xxd or hexdump.",
        "Try password cracking on archives with fcrackzip or rarcrack."
    ],
    CTFCategory.STEGO: [
        "For empty text files, try whitespace steganography (stegsnow).",
        "Convert images between formats (JPG→PNG) and retry extraction.",
        "For audio, examine spectrograms visually with Audacity.",
        "Analyze GIFs frame-by-frame for hidden data."
    ],
    CTFCategory.OSINT: [
        "Use Invidious or amnesty-youtube-dl to extract video metadata.",
        "Check usernames across platforms using sherlock.",
        "Map geolocation clues from image EXIF data."
    ],
    CTFCategory.REVERSE: [
        "Test binaries with different inputs for hidden functionality.",
        "Use radare2 for quick disassembly.",
        "If packed, try unpacking with UPX (`upx -d <file>`)."
    ],
    CTFCategory.CRYPTO: [
        "Try XOR analysis for same-length random-looking strings.",
        "Test multiple layers of base encoding.",
        "Use CyberChef for quick decoding pipelines.",
        "If ciphertext is numbers only, try ASCII decoding.",
        "the file might also contain whitespace encryption."
    ],
    CTFCategory.BINARY: [
        "Use pwntools to script exploit attempts.",
        "Check protections with checksec (ASLR, canaries).",
        "Generate cyclic patterns to find overflow offsets.",
        "Analyze core dumps for overwritten instruction pointers."
    ],
}

class CTFlowAnalyzer:
    def __init__(self):
        self.tool_matrix = self._build_tool_matrix()

    def _build_tool_matrix(self):
        """Map file extensions to CTF categories, tools, and commands"""
        return {
            '.html': {
                'category': CTFCategory.WEB,
                'tools': ['Burp Suite', 'curl','gobuster', 'nikto', 'View Source'],
                'commands': {
                    'kali': ['curl -I URL', 'gobuster dir -u URL -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt', 'nikto -h URL'],
                    'windows': ['Burp Suite Professional', 'curl -I URL (PowerShell)', 'Open in browser developer tools']
                }
            },
            '.php': {
                'category': CTFCategory.WEB,
                'tools': ['Burp Suite(indirectly)', 'curl', 'sqlmap', 'gobuster'],
                'commands': {
                    'kali': ['curl -X POST URL', 'sqlmap -u URL', 'gobuster dir -u URL -w wordlist.txt'],
                    'windows': ['Burp Suite', 'curl (PowerShell)']
                }
            },
            '.js': {
                'category': CTFCategory.WEB,
                'tools': ['JavaScript beautifier', 'Browser DevTools', 'strings'],
                'commands': {
                    'kali': ['strings file.js', 'cat file.js | grep -i flag', 'js-beautify file.js'],
                    'windows': ['notepad++ file.js', 'findstr /i "flag" file.js']
                }
            },
            
            # Image files - Steganography
            '.png': {  
                'category': CTFCategory.STEGO,
                'tools': ['file', 'strings', 'exiftool', 'binwalk', 'zsteg', 'stegsolve'],
                'commands': {
                    'kali': ['file image.png', 'strings image.png | grep -i flag', 'exiftool image.png', 'binwalk -e image.png', 'zsteg -a image.png'],
                    'windows': ['QuickStego', 'OpenStego', 'Silenteye', 'strings.exe image.png']
                }
            },
            '.jpg': {
                'category': CTFCategory.STEGO,
                'tools': ['file', 'strings', 'exiftool', 'steghide', 'binwalk'],
                'commands': {
                    'kali': ['file image.jpg', 'strings image.jpg', 'exiftool image.jpg', 'steghide extract -sf image.jpg', 'binwalk -e image.jpg'],
                    'windows': ['QuickStego', 'OpenStego', 'steghide extract -sf image.jpg']
                }
            },
            '.jpeg': {
                'category': CTFCategory.STEGO,
                'tools': ['file', 'strings', 'exiftool', 'steghide', 'binwalk'],
                'commands': {
                    'kali': ['file image.jpeg', 'strings image.jpeg', 'exiftool image.jpeg', 'steghide extract -sf image.jpeg'],
                    'windows': ['QuickStego', 'OpenStego', 'steghide extract -sf image.jpeg']
                }
            },
            '.bmp': {
                'category': CTFCategory.STEGO,
                'tools': ['file', 'strings', 'zsteg', 'exiftool'],
                'commands': {
                    'kali': ['file image.bmp', 'zsteg -a image.bmp', 'strings image.bmp'],
                    'windows': ['OpenStego', 'strings.exe image.bmp']
                }
            },
            '.gif': {
                'category': CTFCategory.STEGO,
                'tools': ['file', 'strings', 'exiftool', 'binwalk'],
                'commands': {
                    'kali': ['file image.gif', 'strings image.gif', 'exiftool image.gif', 'binwalk -e image.gif'],
                    'windows': ['OpenStego', 'strings.exe image.gif']
                }
            },
            
            # Audio files
            '.wav': {
                'category': CTFCategory.STEGO,
                'tools': ['file', 'strings', 'Spectro', 'DTMF', 'SSTV'],
                'commands': {
                    'kali': ['file audio.wav', 'strings audio.wav', 'audacity audio.wav', 'sox audio.wav -n spectrogram'],
                    'windows': ['Spectro', 'DTMF decoder', 'DEEP SOUND Software', 'Audacity']
                }
            },
            '.mp3': {
                'category': CTFCategory.STEGO,
                'tools': ['file', 'strings', 'exiftool', 'binwalk'],
                'commands': {
                    'kali': ['file audio.mp3', 'strings audio.mp3', 'exiftool audio.mp3', 'binwalk -e audio.mp3'],
                    'windows': ['DEEP SOUND Software', 'strings.exe audio.mp3']
                }
            },
            
            # Archive files
            '.zip': {
                'category': CTFCategory.FORENSICS,
                'tools': ['file', 'unzip', 'binwalk', 'strings'],
                'commands': {
                    'kali': ['file archive.zip', 'unzip -l archive.zip', 'binwalk archive.zip', 'strings archive.zip'],
                    'windows': ['7zip', 'WinRAR', 'strings.exe archive.zip']
                }
            },
            '.rar': {
                'category': CTFCategory.FORENSICS,
                'tools': ['file', 'unrar', 'binwalk', 'strings'],
                'commands': {
                    'kali': ['file archive.rar', 'unrar l archive.rar', 'binwalk archive.rar'],
                    'windows': ['WinRAR', '7zip', 'strings.exe archive.rar']
                }
            '.7z': {
                'category': CTFCategory.FORENSICS,
                'tools': ['file', '7z', 'binwalk', 'strings'],
                'commands': {
                    'kali': ['file archive.7z', '7z l archive.7z', '7z x archive.7z -ooutput', 'binwalk archive.7z', 'strings archive.7z'],
                    'windows': ['7zip', 'WinRAR', '7z.exe l archive.7z', 'strings.exe archive.7z']
                }
            },
            
            # Document files  
            '.pdf': {
                'category': CTFCategory.FORENSICS,
                'tools': ['file', 'strings', 'exiftool', 'binwalk', 'pdfinfo'],
                'commands': {
                    'kali': ['file document.pdf', 'strings document.pdf | grep -i flag', 'exiftool document.pdf', 'binwalk -e document.pdf', 'pdfinfo document.pdf'],
                    'windows': ['strings.exe document.pdf', 'Adobe Reader', 'PDFtk']
                }
            },
            '.docx': {
                'category': CTFCategory.FORENSICS,
                'tools': ['file', 'strings', 'binwalk', 'unzip'],
                'commands': {
                    'kali': ['file document.docx', 'unzip document.docx', 'strings document.docx', 'binwalk -e document.docx'],
                    'windows': ['7zip document.docx', 'strings.exe document.docx']
                }
            },
            
            # Binary/Executable files
            '.exe': {
                'category': CTFCategory.REVERSE,
                'tools': ['file', 'strings', 'Ghidra', 'IDA', 'Binary Ninja', 'DIE','objdump','GDB'],
                'commands': {
                    'kali': ['file binary.exe', 'strings binary.exe', 'objdump -d binary.exe', 'ltrace binary.exe'],
                    'windows': ['Ghidra', 'IDA', 'x64dbg', 'DIE (Detect It Easy)', 'strings.exe binary.exe']
                }
            },
            '.elf': {
                'category': CTFCategory.REVERSE,
                'tools': ['file', 'strings', 'GDB','IDA','Binary Ninja','DIE','Ghidra', 'objdump'],
                'commands': {
                    'kali': ['file binary.elf', 'strings binary.elf', 'objdump -d binary.elf', 'gdb binary.elf', 'ltrace binary.elf'],
                    'windows': ['Ghidra', 'IDA', 'strings.exe binary.elf']
                }
            },
            '.apk': {
                'category': CTFCategory.REVERSE,
                'tools': ['file', 'Jadx', 'apktool', 'strings'],
                'commands': {
                    'kali': ['file app.apk', 'jadx app.apk', 'apktool d app.apk', 'strings app.apk'],
                    'windows': ['Jadx GUI', 'apktool d app.apk', 'strings.exe app.apk']
                }
            },
            
            # Network files
            '.pcap': {
                'category': CTFCategory.FORENSICS,
                'tools': ['Wireshark', 'tcpdump', 'tshark', 'strings'],
                'commands': {
                    'kali': ['wireshark capture.pcap', 'tshark -r capture.pcap', 'tcpdump -r capture.pcap', 'strings capture.pcap'],
                    'windows': ['Wireshark', 'strings.exe capture.pcap']
                }
            },
            '.pcapng': {
                'category': CTFCategory.FORENSICS,
                'tools': ['Wireshark(sometimes)', 'tshark(sometimes)', 'strings'],
                'commands': {
                    'kali': ['wireshark capture.pcapng', 'tshark -r capture.pcapng', 'strings capture.pcapng'],
                    'windows': ['Wireshark', 'strings.exe capture.pcapng']
                }
            },
            
            # Text files
            '.txt': {
                'category': CTFCategory.CRYPTO,
                'tools': ['file', 'strings', 'cat', 'grep'],
                'commands': {
                    'kali': ['file text.txt', 'cat text.txt', 'strings text.txt', 'grep -i flag text.txt'],
                    'windows': ['type text.txt', 'findstr /i "flag" text.txt', 'notepad text.txt']
                }
            },
            
            # Default for unknown extensions
            'default': {
                'category': 'Unknown',
                'tools': ['file', 'strings', 'hexdump', 'binwalk'],
                'commands': {
                    'kali': ['file unknown_file', 'strings unknown_file', 'hexdump -C unknown_file | head', 'binwalk unknown_file'],
                    'windows': ['strings.exe unknown_file', 'HxD (hex editor)']
                }
            }
        }

    def display_banner(self):
        """Display banner with flag art only on help"""
        pass  

    def get_file_category(self, file_path):
        file_ext = Path(file_path).suffix.lower()
        return self.tool_matrix.get(file_ext, self.tool_matrix['default'])

    def suggest_tools(self, file_path):
        if not os.path.exists(file_path):
            print(f"❌ Error: File '{file_path}' not found!")
            return

        file_info = self.get_file_category(file_path)
        file_ext = Path(file_path).suffix.lower() or "unknown"

        print(f"\n# File: {file_path}")
        print(f"# Extension: {file_ext}")
        print(f"# CTF Category: {file_info['category']}\n")

        print("# Recommended Tools:")
        for i, tool in enumerate(file_info['tools'], 1):
            print(f"  {i}. {tool}")
        print()

        print("# Kali Linux Commands:")
        for i, cmd in enumerate(file_info['commands']['kali'], 1):
            actual_cmd = cmd.replace('<file>', file_path)
            print(f"  {i}. {actual_cmd}")
        print()

        print("# Windows Tools:")
        for i, tool in enumerate(file_info['commands']['windows'], 1):
            print(f"  {i}. {tool}")
        print()

        self._print_learning_tips(file_info['category'])

        solved = input("Is your problem solved? [y/N]: ").strip().lower()
        if solved and solved[0] == 'y':
            print("Glad that helped, keep learning!!\n")
        else:
            self._print_unresolved_hints(file_info['category'])
            print("Hope this might help!!")

    def _print_learning_tips(self, category):
        tips = {
            CTFCategory.WEB: [
                "Check the web page source code carefully.",
                "Check inspect-console,networks.",
                "Search for hidden parameters, comments, or JavaScript.",
                "Try common vulnerabilities: SQL injection, XSS."
            ],
            CTFCategory.STEGO: [
                "Start with 'file' and 'strings' to gather info.",
                "Check metadata using exiftool for hidden flags.",
                "Use binwalk to extract embedded files."
            ],
            CTFCategory.FORENSICS: [
                "Network captures may contain flag data in packets.",
                "Look for unusual signatures or hidden partitions.",
                "Passwords or keys can sometimes be found in memory dumps."
            ],
            CTFCategory.REVERSE: [
                "Use strings to find clues before deep analysis.",
                "Static analysis with Ghidra is beginner-friendly.",
                "Look for function names, debug info, and strings."
            ],
            CTFCategory.CRYPTO: [
                "Identify the cipher type: Caesar, Vigenère, etc.",
                "Try online decoders for common ciphers.",
                "Frequency analysis helps with substitution ciphers.",
                "sometimes it might contain empty folder with invisible characters that are represented by tabs '/t' and new line '/n' as well as binaries."
            ]
        }
        if category in tips:
            print("# Learning Tips:")
            for tip in tips[category]:
                print(f"  - {tip}")
            print()

    def _print_unresolved_hints(self, category):
        hints = UNRESOLVED_HINTS.get(category, [])
        if hints:
            print("# STILL NOT RESOLVED? GIVE THIS A TRY:")
            for hint in hints:
                print(f"  - {hint}")
            print()

    def show_help(self):
        print(HELP_FLAG_ART)
        help_text = """
CTFlow - CTF Analysis Tool for Beginners

USAGE:
  ctflow [OPTIONS] [FILE]

OPTIONS:
  -h, --help           Show this help message
  -s, --suggest FILE   Suggest tools and commands for the given file

EXAMPLES:
  ctflow -s challenge.png      # Get suggestions for a PNG image
  ctflow --suggest file.pcap   # Get tool recommendations for PCAP analysis
  ctflow -h                   # Show this help

SUPPORTED FILE TYPES:
  Images: .png, .jpg, .jpeg, .bmp, .gif
  Audio: .wav, .mp3
  Archives: .zip, .rar
  Documents: .pdf, .docx
  Binaries: .exe, .elf, .apk
  Network: .pcap, .pcapng
  Web: .html, .php, .js
  Text: .txt

  "DISCLAIMER!!: the file may contain double extensions or misleadling extension. make sure to know the true file type before using this."

CTF CATEGORIES:
  Web Exploitation    - Web based challenges
  Digital Forensics   - File and network analysis
  Steganography       - Hidden data in files
  OSINT               - Open source intelligence
  Reverse Engineering - Binary analysis
  Cryptography        - Cipher and encoding challenges
  Binary Exploitation - Exploiting binary vulnerabilities

CTFlow is in early development stage!
Visit: https://github.com/Pha3thon to contribute or report issues
"""
        print(help_text)

def main():
    analyzer = CTFlowAnalyzer()

    parser = argparse.ArgumentParser(description='CTFlow - CTF Analysis Tool for Beginners', add_help=False)
    parser.add_argument('-h', '--help', action='store_true', help='Show help message')
    parser.add_argument('-s', '--suggest', metavar='FILE', help='Suggest tools for the given file')
    parser.add_argument('file', nargs='?', help='File to analyze')

    if len(sys.argv) == 1:
        analyzer.show_help()
        return

    args = parser.parse_args()

    if args.help:
        analyzer.show_help()
        return

    if args.suggest:
        analyzer.suggest_tools(args.suggest)
        return

    if args.file:
        analyzer.suggest_tools(args.file)
        return

    analyzer.show_help()

if __name__ == "__main__":
    main()
