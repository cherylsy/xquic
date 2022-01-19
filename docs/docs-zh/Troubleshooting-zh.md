# Trouble Shooting Guide

> iOS 编译失败

类似 [Discussions #21](https://github.com/alibaba/xquic/discussions/21) 的问题，最新版本已经fix，请拉取最新代码。

> MacOS 编译失败

先检查是否添加了 `-DPLATFORM=mac` 参数。 

> 首次运行 test_server 后，报错：error create engine

需要先生成证书，见 [Testing](./Testing-zh.md)。