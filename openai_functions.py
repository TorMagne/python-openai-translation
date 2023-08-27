import openai
import os
openai.api_key = os.environ.get("OPENAI_API_KEY")

def translation_openai(chat_input, selected_from_language, selected_to_language):
	chat_completion = openai.ChatCompletion.create(
		model = "gpt-3.5-turbo",
		messages = [
		{"role": "user", "content": f"you will be prompted with a text in {selected_from_language}, and your task is to translate it into {selected_to_language}: {chat_input}"}
		],
		max_tokens = 100,
	)
	return (chat_completion.choices[0].message["content"])