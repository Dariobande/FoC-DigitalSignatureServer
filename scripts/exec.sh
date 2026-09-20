# ************************************************************************************
# NOTE:
# Assume clients connect to the server on port 4242,
# which is hardcoded in the source code.
# ************************************************************************************

# 1. COMPILATION

make

read -p "Compilation completed. Press Enter to execute..."

# 2. EXECUTION

# 2.1 Run the server on port 4242
gnome-terminal --title="Server Terminal" -- sh -c "./server 4242; exec bash"

# 2.2 Run the client 1
gnome-terminal --title="Client 1 Terminal" -- sh -c "./client; exec bash"

# 2.3 Run the client 2
gnome-terminal --title="Client 2 Terminal" -- sh -c "./client; exec bash"

