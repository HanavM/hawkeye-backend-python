import mailtrap as mt

mail = mt.Mail(
    sender=mt.Address(email="noresponse@demomailtrap.com", name="Mailtrap Test"),
    to=[mt.Address(email="hanavmw13@gmail.com")],
    subject="Email verification",
    text="Click the link below to verify your email",
    category="Email Verification Test",
)

client = mt.MailtrapClient(token="21c159c61ee1a211d7a3ad93602be796")
response = client.send(mail)

print(response)