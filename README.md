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
The bot-manager has to be running on the **attackers computer** for clients to connect to the discord bot. There is no builder yet for the bot-manager, you will manually have to insert your guild id and bot token.
When a client runs the payload the bot-manager will send a log into the rat-log channel something like !register example, this is the commmand you wanna run to generate the channel for the infected system.
There is no prefix for commands. The bot-manager just listen for commands like "screenshot" directly.

**Available Commands**
-pwd                 : Show current working directory
-cd <path>           : Change directory
-ls                  : List files in current directory
-cmd <command>       : Run shell command
-ps <command>        : Run PowerShell command
-screenshot          : Take a screenshot
-webcam              : Capture image from webcam
-upload <filename>   : Upload a file (attach file to message)
-download <filename> : Download a file"
-critical            : Make payload critical process
-grabpasswords       : Steal user passwords
-grabcookies         : Steal user cookies
-listprocs           : List current running rats
-killrat             : Kill PID-specified rat process
-stream              : Start streaming screenshots
-disableuac          : Disable UAC permanently
-enableuac           : Enable UAC permanently
-stopstream          : Stop streaming screenshots
-persistpayload      : Add payload persistence\
-unpersistpayload    : Remove payload persistence
-getclipboard        : Retrieve the contents of the clipboard
-setclipboard <text> : Set the contents of the clipboard to specified text
