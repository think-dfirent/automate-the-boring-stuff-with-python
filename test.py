import subprocess

proc = subprocess.run(['ping', '-n', '4', 'nostarch.com'], capture_output=True, text=True)
print(proc.stdout)