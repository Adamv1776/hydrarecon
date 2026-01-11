"""
cms_api_scrubber.py

Module to scrub and update content via CMS APIs (WordPress, Drupal, etc.)
- Authenticates and updates posts/pages to permanently delete words.
"""
import requests
import re

class WordPressScrubber:
    def __init__(self, base_url, username, password):
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        self.session.auth = (username, password)
        self.api_url = f"{self.base_url}/wp-json/wp/v2"

    def get_posts(self):
        resp = self.session.get(f"{self.api_url}/posts")
        resp.raise_for_status()
        return resp.json()

    def update_post(self, post_id, new_content):
        resp = self.session.post(f"{self.api_url}/posts/{post_id}", json={"content": new_content})
        resp.raise_for_status()
        return resp.json()

    def scrub_posts(self, patterns, replacement="[REDACTED]"):
        posts = self.get_posts()
        for post in posts:
            content = post['content']['rendered']
            new_content = content
            for pat in patterns:
                new_content = re.sub(pat, replacement, new_content, flags=re.IGNORECASE)
            if new_content != content:
                self.update_post(post['id'], new_content)

# Example usage:
# wp = WordPressScrubber('https://example.com', 'admin', 'password')
# wp.scrub_posts([r'secret', r'password\d+'])
