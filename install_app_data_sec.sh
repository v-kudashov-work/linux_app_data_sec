# ============================================================================
# УСТАНОВКА BPF ОБЪЕКТА
# ============================================================================

echo -e "\n${BLUE}[INFO]${NC} Installing BPF object..."

# Создаём директорию
mkdir -p /usr/local/lib/app_data_sec

# Проверяем наличие BPF объекта
if [ -f "app_data_sec.bpf.o" ]; then
    cp app_data_sec.bpf.o /usr/local/lib/app_data_sec/
    chmod 644 /usr/local/lib/app_data_sec/app_data_sec.bpf.o
    echo -e "${GREEN}[OK]${NC} Installed: /usr/local/lib/app_data_sec/app_data_sec.bpf.o"
else
    echo -e "${YELLOW}[WARNING]${NC} app_data_sec.bpf.o not found!"
    echo -e "${BLUE}[INFO]${NC} Compiling BPF program..."
    clang -g -O2 -target bpf -D__TARGET_ARCH_x86 -I. -c app_data_sec.bpf.c -o app_data_sec.bpf.o
    if [ -f "app_data_sec.bpf.o" ]; then
        cp app_data_sec.bpf.o /usr/local/lib/app_data_sec/
        chmod 644 /usr/local/lib/app_data_sec/app_data_sec.bpf.o
        echo -e "${GREEN}[OK]${NC} Compiled and installed: /usr/local/lib/app_data_sec/app_data_sec.bpf.o"
    else
        echo -e "${RED}[ERROR]${NC} Failed to compile BPF program!"
    fi
fi
