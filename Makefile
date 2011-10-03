
PREFIX:=../
DEST:=$(PREFIX)$(PROJECT)

# Expect to find rebar in the PATH. If you don't have rebar, you can get it
# from https://github.com/basho/rebar .
REBAR=rebar

# Expect to find edown_make in the PATH. This is needed only to generate
# documentation. If you don't have it, you can get it from
# https://github.com/esl/edown.git .
EDOWN_MAKE=edown_make

.PHONY: all edoc test clean build_plt dialyzer

all:
	@$(REBAR) get-deps compile

edoc:
	$(EDOWN_MAKE) -config edown.config

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
