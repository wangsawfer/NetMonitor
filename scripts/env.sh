# NetMonitor build environment -- keeps ALL toolchain/caches on D:
export PROJECT_ROOT='D:\pythonProject\ipv6'
export RUSTUP_HOME='D:\pythonProject\ipv6\.toolchain\rustup'
export CARGO_HOME='D:\pythonProject\ipv6\.toolchain\cargo'
export CARGO_TARGET_DIR='D:\pythonProject\ipv6\.cache\target'
export NPCAP_SDK_DIR='D:\pythonProject\ipv6\.cache\deps\npcap-sdk'
export PATH="/d/pythonProject/ipv6/.toolchain/cargo/bin:$PATH"
# MSVC env (needed so rustc can find link.exe / Windows SDK)
