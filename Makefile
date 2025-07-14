lint:
	mdl -r ~MD013 README.md

test:
	# Some URLs could be flaky, try twice in case the first execution fails.
	./run_awesome_bot.sh || ./run_awesome_bot.sh
