# 设置环境变量
export TA_DEV_KIT_DIR=/home/hfut/phytium-pi-os/output/build/phytium-optee-v4.6.0/optee_os/ta

# 检查 mk 目录是否存在
if [ -d "$TA_DEV_KIT_DIR/mk" ]; then
    echo "mk directory exists"
else
    echo "mk directory missing"
fi

# 检查关键 mk 文件
for file in ta_dev_kit.mk build-user-ta.mk link.mk compile.mk; do
    if [ -f "$TA_DEV_KIT_DIR/mk/$file" ]; then
        echo "Found $file"
    else
        echo "Missing $file"
    fi
done