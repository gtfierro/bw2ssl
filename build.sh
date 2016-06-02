go build -buildmode=c-shared -o helper.so helper.go
gcc -shared -fPIC  bw2ssl.c helper.so -o bw2ssl.so -ldl -lrt
