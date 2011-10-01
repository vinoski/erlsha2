
PREFIX:=../
DEST:=$(PREFIX)$(PROJECT)

# Expect to find rebar in the PATH. If you don't have rebar, you can get it
# from https://github.com/basho/rebar .
REBAR=rebar

.PHONY: all edoc test clean build_plt dialyzer

all:
	@$(REBAR) get-deps compile

edoc:
	@$(REBAR) doc

test:
	@rm -rf .eunit
	@mkdir -p .eunit
	@$(REBAR) skip_deps=true eunit

clean:
	@$(REBAR) clean

build_plt:
	@$(REBAR) build-plt

dialyzer:
	@$(REBAR) dialyze
