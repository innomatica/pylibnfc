PROJECT:=example

all: $(PROJECT) Makefile

$(PROJECT): $(PROJECT).c
	gcc -o $(PROJECT) $(PROJECT).c -lnfc


run: $(PROJECT)
	./$(PROJECT)

clean:
	rm -f $(PROJECT)
