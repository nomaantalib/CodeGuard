import unittest
from unittest.mock import patch

from codeguard.config import Config
from codeguard.llm import LLM, parse_review


class LLMProviderTests(unittest.TestCase):
    def test_default_is_local_ollama_without_key(self):
        llm = LLM(Config())
        self.assertEqual(llm.provider, "ollama")
        self.assertEqual(llm.model, "qwen2.5-coder:3b")
        with patch("urllib.request.urlopen") as request:
            request.return_value.__enter__.return_value = __import__("io").BytesIO(
                b'{"models":[{"name":"qwen2.5-coder:3b"}]}')
            self.assertTrue(llm.available)

    def test_openai_compatible_requires_key(self):
        cfg = Config(provider="openai-compatible", api_key="", llm_url="https://api.example/v1")
        self.assertFalse(LLM(cfg).available)

    def test_openai_compatible_url_is_not_duplicated(self):
        llm = LLM(Config(provider="openai-compatible", api_key="x",
                         llm_url="https://api.example/v1"))
        self.assertEqual(llm.url + "/chat/completions",
                         "https://api.example/v1/chat/completions")

    def test_parse_review_rejects_non_array(self):
        self.assertEqual(parse_review("a.py", '{"message":"bad"}', 10), [])


if __name__ == "__main__":
    unittest.main()
