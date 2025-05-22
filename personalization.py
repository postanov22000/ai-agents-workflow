def personalize_template(template_text: str, past_emails: list, deal_data: dict, key: str) -> str:
    prompt = f"""
You are a real estate agent with a professional and assertive tone.

Original boilerplate:
\"\"\"
{template_text}
\"\"\"

Match the tone/style of these emails:
\"\"\"
{'\n'.join(past_emails)}
\"\"\"

Deal-specific data:
{deal_data}

Rewrite now:
"""

    response = requests.post(
        "https://api-inference.huggingface.co/models/mistralai/Mixtral-8x7B-Instruct-v0.1",
        headers={"Authorization": f"Bearer {key}"},
        json={
            "inputs": prompt,
            "parameters": {"max_new_tokens": 700},
            "options": {"use_cache": False}
        }
    )
    result = response.json()[0]["generated_text"]
    if "[/INST]" in result:
        return result.split("[/INST]", 1)[1].strip()
    return result.strip()
