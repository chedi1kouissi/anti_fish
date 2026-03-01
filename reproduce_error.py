import requests
import json

url = "http://localhost:5000/api/analyze/email"
payload = {
    "text": "Please verify your PayPal account by clicking http://paypal-verify.com/login",
    "metadata": {}
}

try:
    response = requests.post(url, json=payload)
    print(f"Status Code: {response.status_code}")
    print("Response Body:")
    print(response.text)
except Exception as e:
    print(e)
