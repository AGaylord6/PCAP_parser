#!/bin/bash

# Check if requirements.txt exists
if [ ! -f requirements.txt ]; then
  echo "requirements.txt not found! Please make sure it's in the repository."
  exit 1
fi

# Remove the old virtual environment if it exists
if [ -d .venv ]; then
  echo "Removing existing .venv..."
  rm -rf .venv
fi

# Create a new virtual environment
echo "Creating new virtual environment..."
python3 -m venv .venv

# Activate the virtual environment
echo "Activating the virtual environment..."
# check if we have /bin/ or /Scripts/ in our .venv folder
if [ -d ".venv/bin" ]; then
  source .venv/bin/activate
elif [ -d ".venv/Scripts" ]; then
  source .venv/Scripts/activate
else
  echo "Virtual environment activation failed!"
  exit 1
fi

# Install the required dependencies from requirements.txt
echo "Installing dependencies from requirements.txt..."
pip install -r requirements.txt

# Confirm successful installation
echo "Virtual environment setup complete and dependencies installed."

