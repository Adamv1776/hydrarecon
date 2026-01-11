"""
ftp_sftp_uploader.py

Module to upload files to a remote server via FTP, SFTP, or SSH.
- Used after scrubbing to overwrite original files for permanent deletion.
"""
import os
from urllib.parse import urlparse

class RemoteUploader:
    def __init__(self, protocol, host, username, password=None, port=None, keyfile=None):
        self.protocol = protocol
        self.host = host
        self.username = username
        self.password = password
        self.port = port
        self.keyfile = keyfile

    def upload(self, local_path, remote_path):
        if self.protocol == 'ftp':
            return self._upload_ftp(local_path, remote_path)
        elif self.protocol == 'sftp':
            return self._upload_sftp(local_path, remote_path)
        elif self.protocol == 'ssh':
            return self._upload_ssh(local_path, remote_path)
        else:
            raise ValueError(f"Unsupported protocol: {self.protocol}")

    def _upload_ftp(self, local_path, remote_path):
        from ftplib import FTP
        with FTP() as ftp:
            ftp.connect(self.host, self.port or 21)
            ftp.login(self.username, self.password)
            with open(local_path, 'rb') as f:
                ftp.storbinary(f'STOR {remote_path}', f)
        return True

    def _upload_sftp(self, local_path, remote_path):
        import paramiko
        transport = paramiko.Transport((self.host, self.port or 22))
        if self.keyfile:
            private_key = paramiko.RSAKey.from_private_key_file(self.keyfile)
            transport.connect(username=self.username, pkey=private_key)
        else:
            transport.connect(username=self.username, password=self.password)
        sftp = paramiko.SFTPClient.from_transport(transport)
        sftp.put(local_path, remote_path)
        sftp.close()
        transport.close()
        return True

    def _upload_ssh(self, local_path, remote_path):
        import paramiko
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        if self.keyfile:
            ssh.connect(self.host, port=self.port or 22, username=self.username, key_filename=self.keyfile)
        else:
            ssh.connect(self.host, port=self.port or 22, username=self.username, password=self.password)
        sftp = ssh.open_sftp()
        sftp.put(local_path, remote_path)
        sftp.close()
        ssh.close()
        return True

# Example usage:
# uploader = RemoteUploader('sftp', 'example.com', 'user', password='pass')
# uploader.upload('local/file.html', '/var/www/html/file.html')
