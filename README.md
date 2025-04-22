To run the server , run these commands in windows powershell:

```
choco install ngrok

ngrok config add-authtoken 2w5PPX9XB1By6qH8RNC7QxTpwis_4vCtHHu4p2rr3wG8gsruB

ngrok http --url=squirrel-pet-bengal.ngrok-free.app 5000

```

To build the script into an executable file run this code:

```
pyinstaller --onefile --windowed --icon="icon name".ico "script name".exe
```
