# mlx5-netperf

## Building
1. First, build the submodules:
```
make submodules
```

2. Build with MLX5 support turned on:
```
make CONFIG_MLX5=y
```

3. To enable debug prints, add a debug flag:
```
make CONFIG_MLX5=y DEBUG=y
```
