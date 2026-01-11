# How to Permanently Delete Words from a Website or Domain

## 1. Run the Scrubber Directly on the Server
- SSH into your web server.
- Install Python and required packages (requests, beautifulsoup4).
- Copy your word_scrubber.py and run with file:// URLs or direct file paths:

```
python3 word_scrubber_cli.py file:///var/www/html/index.html -w secret password --out-dir cleaned_html
```
- Overwrite the original files with the cleaned versions:

```
cp cleaned_html/index.html /var/www/html/index.html
```

## 2. Use FTP/SFTP/SSH Upload
- Scrub the site locally, then use core/ftp_sftp_uploader.py to upload cleaned files back to the server:

```
from core.ftp_sftp_uploader import RemoteUploader
uploader = RemoteUploader('sftp', 'example.com', 'user', password='pass')
uploader.upload('cleaned_html/index.html', '/var/www/html/index.html')
```

## 3. Use CMS API Integration (WordPress Example)
- Use core/cms_api_scrubber.py to authenticate and update posts/pages via the CMS API:

```
from core.cms_api_scrubber import WordPressScrubber
wp = WordPressScrubber('https://example.com', 'admin', 'password')
wp.scrub_posts([r'secret', r'password\\d+'])
```

## Notes
- Always back up your site before overwriting files.
- For other CMS (Drupal, Joomla, etc.), similar API logic can be added.
- For static sites, direct file editing is safest and most reliable.
