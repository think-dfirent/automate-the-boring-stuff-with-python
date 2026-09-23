from dotenv import load_dotenv
import os

print("CWD:", os.getcwd())
load_dotenv()

print(bool(os.getenv("OPENWEATHER_API")))
print(bool(os.getenv("VIRUSTOTAL_API")))
print(bool(os.getenv("ABUSEIPDB_API")))
