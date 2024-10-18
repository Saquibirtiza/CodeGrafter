build:
	docker build -t erlking-img:5.0 .

# run: clean exec
run:
# 	docker-compose run erlking
	docker-compose run --service-ports erlking
# 	docker-compose up

run-chess:
	docker-compose run --service-ports erlking-chess

publish:
	docker build -t erlking-release:8.3 -f Dockerfile-release .

run-chess-release:
	docker-compose run --service-ports erlking-chess-release
# 	docker-compose run erlking-chess-release -f docker-compose.utd.yml

clean:
	rm -rf erlking/dwarvenking/__pycache__
	rm -rf erlking/dwarvenking/*.pyc
	rm -rf erlking/sigbin/__pycache__
	rm -rf erlking/sigbin/*.pyc
	rm -rf erlking/checker/__pycache__
	rm -rf erlking/checker/*.pyc
	rm -rf erlking/castle/__pycache__/
	rm -rf erlking/castle/*.pyc
	rm -rf erlking/mylogging/__pycache__
	rm -rf erlking/mylogging/*.pyc	
	rm -rf erlking/messages/__pycache__
	rm -rf erlking/messages/*.pyc
	rm -rf erlking/graphUtils/__pycache__
	rm -rf erlking/graphUtils/*.pyc
	rm -rf erlking/__pycache__
	rm -rf erlking/test/__pycache__/
	rm -rf erlking/test/.cache/
	rm -rf targets/**/src/.joernIndex
	rm -rf logs/erlking.log
	touch logs/erlking.log
