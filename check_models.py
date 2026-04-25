from groq import Groq
import os
os.environ["GROQ_API_KEY"] = "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"
client = Groq(api_key=os.environ["GROQ_API_KEY"])
models = client.models.list()
for m in sorted(models.data, key=lambda x: x.id):
    print(m.id)