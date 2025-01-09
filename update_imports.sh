#!/bin/bash

# 旧的和新的模块路径
OLD_MODULE_PATH="github.com/projectdiscovery/naabu/v2"
NEW_MODULE_PATH="github.com/xiaoyuer11223344/nabbu-fix/v2"

# 更新所有.go文件中的导入路径
find . -type f -name "*.go" | xargs sed -i '' "s|$OLD_MODULE_PATH|$NEW_MODULE_PATH|g"

# 更新 go.mod 文件中的模块路径
sed -i '' "s|^module.*|module $NEW_MODULE_PATH|" go.mod

# 运行 go mod tidy 来清理和下载依赖
go mod tidy

echo "导入路径更新完成！请检查是否有错误，并运行测试以确保一切正常。"