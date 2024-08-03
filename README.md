# PySpy

PySpy is an open-source Discord RAT (Remote Access Trojan) that leverages Discord as a control interface. Inspired by DiscoRat, PySpy allows users to remotely control target systems using Discord commands. **Note: This project is intended for educational and research purposes only.**

## Features

- **Discord Command Control**: Use Discord commands to manage and control target systems.
- **Custom Payload Builder**: Easily configure and build your payload with a user-friendly setup.
- **Remote File Management**: Upload, download, and manipulate files on the target system.
- **Keylogging**: Capture and log keystrokes from the target system.
- **Screen Capture**: Take screenshots and record screen activities.
- **Process Management**: View and manage running processes on the target system.
- **Customizable**: Extend functionality through plugins and additional commands.

## Requirements

- Python 3.7+
- `PyInstaller` for building executables
- `discord.py` for Discord integration
- Additional Python packages listed in `requirements.txt`

## Installation

1. **Download the Zip File**:

   Download the latest version of PySpy from the [GitHub repository](https://github.com/yourusername/pyspy) as a zip file.

2. **Extract the Zip File**:

   Extract the contents of the zip file to a directory of your choice.

3. **Configure `config.json`**:

   Set up your configuration in the `config.json` file. Specify your Discord bot token, the command prefix, and other settings.

   ```json
   {
     "token": "YOUR_DISCORD_BOT_TOKEN",
     "prefix": "!",
     "admin_role": "Admin"
   }
