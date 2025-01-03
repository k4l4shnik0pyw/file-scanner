import clear
from colorama import Fore, init
import random



RED = Fore.RED
GREEN = Fore.GREEN
YELLOW = Fore.YELLOW

init(autoreset=True)


blacklisted_words = ["webhook", "wbhk", "wbh", "webk", "webhk", "keylogger", "stealer", "grabber", "exploit", "payload", "reverse shell", "trojan", "phishing", "backdoor", "botnet", "malware", "ransomware", "rootkit", "dropper", "c2", "shellcode", "cryptojacker", "vulnerability", "exploitkit", "spyware", "adware", "bypass", "inject", "logger", "zombie", "steganography", "brute force", "decryption", "stealth", "recon", "bypass", "fud", "shell", "hacker", "exploitdb", "remote access", "cmd", "powershell", "trojan horse", "backdoor shell", "script kiddie", "undetectable", "payloads", "keylogger", "injector", "bot", "exploitative", "flood", "crack", "debugger", "vnc", "attack", "remote exploit", "sql injection", "blackhat", "phishing", "malicious", "hidden", "ddos", "stealthy", "tunnel", "debug", "sniffer", "privilege escalation", "exploitative", "drop", "undetected", "ddos attack", "sniffing", "traffic manipulation", "webshell", "keylogger", "data exfiltration", "social engineering", "persistence", "insta", "hex", "reversed", "access control", "unauthorized access", "exfiltrate", "trojanized", "injection", "man in the middle", "virus", "worm", "network sniffing", "shell script", "payload delivery", "cross site scripting", "cmd.exe", "data breach", "malicious code", "buffer overflow", "app exploit", "java deserialization", "privilege", "social engineering", "credential stuffing", "session hijacking", "cryptojack", "vulnerability scanner", "side channel", "ad fraud", "command injection", "hacktool", "cipher", "cryptanalysis", "password cracking", "root access", "penetration testing", "metasploit", "backdoor access", "malicious payload", "social engineering attack", "advanced persistent threat", "APT", "brute force attack", "bot attack", "clickjacking", "cookie theft", "fake update", "drive-by download", "blackhat SEO", "key cracking", "manipulation", "IP spoofing", "scanning", "virus spreading", "red team", "blue team", "grey hat", "pharming", "malicious file", "data mining", "security hole", "sqlmap", "packet sniffing", "buffer overflow exploit", "HTTP request smuggling", "backdoor trojan", "exploit mitigation", "web hacking", "java applet", "payload injection", "remote code execution", "zero day exploit", "DNS spoofing", "trojan downloader", "CVE", "drive-by attack", "exploit broker", "APT group", "rootkit removal", "cross-site request forgery", "zero-day attack", "SQLi", "session fixation", "proxy attack", "code injection", "man-in-the-middle attack", "exploit chain", "credential harvesting", "social engineering technique", "fake certificate", "dns cache poisoning", "decryption tool", "malicious macros", "vulnerability scanning", "attack surface", "fake login", "HTTP header injection", "dumping passwords", "javascript injection", "password theft", "in-memory malware", "bootkit", "backdoor malware", "social engineering kit", "fileless malware", "lateral movement", "IP address spoofing", "fake security alert", "DNS hijacking", "formjacking", "C&C server", "shell injection", "SQL injection attack", "SYN flood", "XSS attack", "ransomware-as-a-service", "APT32", "fileless attack", "credential dump", "HTTP response splitting", "credential stuffing attack", "web shell attack", "malicious JavaScript", "redirection attack", "fake software update", "social engineering scam", "file overwriting", "backdoor script", "advanced exploit", "script injection", "malicious script", "browser exploit", "phishing link", "broadband exploit", "rootkit infection", "remote exploit tool", "fake antivirus", "wireless exploit", "data exfiltration tool", "malware analysis", "web scraping attack", "rootkit detection", "cyber attack", "cybersecurity exploit", "hostile script", "Trojan horse attack", "spyware detection", "network security breach", "command-line exploit", "script kiddie tool", "backdoor program", "exploit attempt", "compromised network", "network-based malware", "webshell detection", "zero-day vulnerability", "payload executor", "automated attack", "hexadecimal encoding", "exploiting weakness", "network vulnerability", "brute-force password attack", "exploit file", "security bypass", "network traffic analysis", "bypass detection", "exploit monitoring", "TCP/IP exploit", "ransomware decryption", "spybot", "remote code exploit", "banking trojan", "phishing attack vector", "spoofed packet", "botnet malware", "social engineering phishing", "webcam hacking", "spyware payload", "authentication bypass", "malicious upload", "phishing malware", "email-based malware", "network intrusion", "web application attack", "wiretap", "cybersecurity breach", "command-and-control server", "payload injection attack", "web browser exploit", "zero-day vulnerability scanner", "trojan horse file", "adware hijacking", "exploit injection", "fake webpage", "data exfiltration tool", "ransomware infection", "payload script", "browser vulnerability", "phishing kit", "fake alert", "javascript obfuscation", "man-in-the-middle exploit"]

menu = YELLOW + r""" ___________________________________________________________________________
|                                                                           |
|   ___________.__.__                                                       |
|   \_   _____/|__|  |   ____     ______ ____ _____    ____   ____          |
|    |    __)  |  |  | _/ __ \   /  ___// ___\\__  \  /    \ /    \         |
|    |     \   |  |  |_\  ___/   \___ \\  \___ / __ \|   |  \   |  \        |
|    \___  /   |__|____/\___  > /____  >\___  >____  /___|  /___|  /        |
|        \/                 \/       \/     \/     \/     \/     \/         |
|                                                                           |
|                               by K4L4SHNIK0V                              |
|___________________________________________________________________________|
|                                                                           |
|            Make sure the file you want to scan and this scanner           |
|                          are in the same folder                           |
|___________________________________________________________________________|
"""


while True:

    detected_words = []
    clear.clear()

    print(menu)
    file_name = input(RED + "  File name without extension (enter ! to leave the scanner) >>> ")
    print(file_name)

    if file_name == "!":
        exit()

    clear.clear()

    extension_menu = YELLOW + """ 
     _____________________________________________________________________________________
    |                                                                                     |
    |                                    EXTENSIONS                                       |
    |_____________________________________________________________________________________|
    |  .py  |   .js   |  .cpp  |   .h    | .java |  .rb   |  .php   |  .vbs | .bat | .ps1 |
    |_______|_________|________|___ _____|_______|________|_________|_______|______|______|
                    | .sh | .bash | .go  | .jar | .asm | .sct | .wsf | 
                    |_____|_______|______|______|______|______|______|

    """

    print(extension_menu)
    file_extension = input("File extension >>> ")
    print(RED + file_extension)
    clear.clear()
    print(YELLOW + "Recherche...")

    with open(file_name + file_extension, "r", encoding="utf-8") as file:
        file_content = file.read()

    total_detect = 0
    detect = 1
    for word in blacklisted_words:
        if word in file_content:
            print(RED + f"Detect n°{detect} : {word}")
            total_detect += 1
            detect += 1
            detected_words.append(word)
    if total_detect == 0:
        print(GREEN + f"{file_name}{file_extension} is clean !")
    conclusion = YELLOW + f""" 
     _____________________________________________________________________________________
    |                                                                                     |
    |                            Total detect(s) :  {total_detect}                                     |
    |_____________________________________________________________________________________|
    """
    print("\n" + conclusion)
    if detect > 0:
        save_or_not = input("Do you want to save a .txt file containing the detections? y/n >>> ")
        print("\n" + save_or_not)
        if save_or_not in ["y", "Y", "Yes", "YES"]:
            detect_file_id = ''.join(random.choices("0123456789", k=3))
            print(YELLOW + f"Saving {file_name}_{detect_file_id}.txt ... ")
            with open(f"{file_name}_{detect_file_id}.txt", "w") as file:
                for detected_word in detected_words:
                    file.write(f"Detected supect word in {file_name} : " + detected_word + "\n")
            print(GREEN + f"Detects_{detect_file_id}.txt successfully saved !")

    input("""

    Press ENTER to continue... """)
    
