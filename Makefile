.DEFAULT_GOAL := build

out_dir:
	if [ ! -d out ]; then mkdir out; fi

build: out_dir
	go build -o out/ntparser cmd/ntparser/main.go

clean: out_dir
	if [ -e out/ntparser ]; then rm out/ntparser; fi
