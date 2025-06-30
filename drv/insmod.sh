# kallsymsからアドレスを取得
TEXT_POKE_ADDR=$(sudo cat /proc/kallsyms | grep " text_poke$" | awk '{print $1}')
TEXT_POKE_ADDR=$(printf "0x%x" 0x${TEXT_POKE_ADDR})
HANDLE_PTE_FAULT_ADDR=$(sudo cat /proc/kallsyms | grep " handle_pte_fault$" | awk '{print $1}')
HANDLE_PTE_FAULT_ADDR=$(printf "0x%x" $(( 0x${HANDLE_PTE_FAULT_ADDR} + 5 )))

# アドレスが取得できたか確認
if [ -z "$TEXT_POKE_ADDR" ] || [ -z "$HANDLE_PTE_FAULT_ADDR" ]; then
    echo "エラー: kallsymsから必要なアドレスを取得できませんでした。"
    exit 1
fi


echo "text_poke のアドレス: $TEXT_POKE_ADDR"
echo "handle_pte_fault のアドレス: $HANDLE_PTE_FAULT_ADDR"

sudo dmesg --clear
sudo insmod refaulter.ko target_hook_address="$HANDLE_PTE_FAULT_ADDR" text_poke_address="$TEXT_POKE_ADDR" overwrite_len=6
sudo rmmod refaulter
sudo dmesg
