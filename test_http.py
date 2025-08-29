#!/usr/bin/env python3
import urllib.request

try:
    with urllib.request.urlopen('http://httpbin.org/get') as response:
        data = response.read()
        print("Response received:", len(data), "bytes")
except Exception as e:
    print(f"Error: {e}")
