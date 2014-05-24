
PREFIX:=../
DEST:=$(PREFIX)$(PROJECT)

# Expect to find rebar in the PATH. If you don't have rebar, you can get it
# from https://github.com/basho/rebar .
REBAR=rebar

.PHONY: all doc test clean

all:
	@$(REBAR) get-deps compile

doc:
	@$(REBAR) get-deps compile doc

test:
	@$(REBAR) skip_deps=true eunit

clean:
	@$(REBAR) clean
