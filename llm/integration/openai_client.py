import os
from openai import OpenAI


class OpenAIClient:
    def __init__(self, model="gpt-4"):
        self.model = model
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            raise ValueError("OPENAI_API_KEY is not set in environment variables.")
        self.client = OpenAI(api_key=api_key)

    def submit(self, prompt_text):
        response = self.client.chat.completions.create(
            model=self.model,
            messages=[{"role": "user", "content": prompt_text}],
            temperature=0.7,
        )
        return response.choices[0].message.content
