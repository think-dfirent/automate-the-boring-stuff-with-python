import pyperclip, re

phone_re = re.compile(
    r"""
    (\d{3}|\(\d{3}\))?
    (\s|-|\.)?
    (\d{3})
    (\s|-|\.)?
    (\d{4})
    (\s*(ext|x|ext\.)\s*(\d{2,5}))?
""",
    re.VERBOSE,
)


email_re = re.compile(
    r"""
    [a-zA-Z0-9%+-_.]+
    @
    [a-zA-Z0-9.-]+
    \.[a-zA-Z]{2,}
""",
    re.VERBOSE,
)

text = """Team Contact Directory:

- Operations: Jane Doe at 415-555-0143 or jane.doe@example.com
- Support Desk: (800) 555-0122 x402 | support+desk@service.example.org
- Engineering: Dial (212) 555-0199 or reach dev-alerts@system.example.net
- Direct Extension: Contact Michael at 650.555.0184 ext. 9012 (m.smith@example.com)
- Local Dispatch: Call 555-0155 during normal business hours."""
# text = string(pyperclip.paste())
p_matches = []

for groups in phone_re.findall(text):
    area_code = groups[0].strip("()")

    if area_code:
        phone_num = "-".join([area_code, groups[2], groups[4]])
    else:
        phone_num = "-".join([groups[2], groups[4]])
    if groups[7]:
        phone_num += " x" + groups[7]
    p_matches.append(phone_num)

e_matches = email_re.findall(text)
matches = p_matches + e_matches
if matches:
    output = "\n".join(matches)
    pyperclip.copy(output)
    print(output)
    print("\nCopied to clipboard!")

else:
    print("No phone numbers or email addresses found!")
