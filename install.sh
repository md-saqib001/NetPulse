#!/bin/bash
set -e

echo "Installing NetPulse..."

# Detect the operating system
OS="$(uname -s)"
if [ "$OS" == "Linux" ]; then
    BINARY_NAME="netpulse-Linux"
elif [ "$OS" == "Darwin" ]; then
    BINARY_NAME="netpulse-macOS"
else
    echo "OS not supported by this installation script. Windows users should download the .exe directly."
    exit 1
fi

# Fetch the binary from the latest GitHub release
DOWNLOAD_URL="https://github.com/md-saqib001/NetPulse/releases/latest/download/$BINARY_NAME"

echo "Downloading from $DOWNLOAD_URL..."
curl -L -o netpulse "$DOWNLOAD_URL"

# Make the downloaded file executable
chmod +x netpulse

# Move to a directory in the user's PATH (requires sudo)
echo "Moving to /usr/local/bin (you may be prompted for your password)..."
sudo mv netpulse /usr/local/bin/netpulse

echo "NetPulse installed successfully! Run 'netpulse --help' to get started."