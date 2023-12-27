default:
	python preprocessing.py -idst misuse -t 8 -dp ./data/unprocessedCSVs -bq 8000 -eaq 200

anomaly:
	python preprocessing.py -idst anomaly -t 8 -dp ./data/unprocessedCSVs -bq 8000 -eaq 200

5Attacks:
	python preprocessing.py -idst misuse -a Bot_DDoS_DoSHulk_WebAttack_PortScan -t 8 -dp ./data/unprocessedCSVs -bq 8000 -eaq 200

singleAttacks:
	python preprocessing.py -idst misuse -a Bot -t 8 -dp ./data/unprocessedCSVs -bq 8000 -eaq 200
	python preprocessing.py -idst misuse -a DDoS -t 8 -dp ./data/unprocessedCSVs -bq 8000 -eaq 200
	python preprocessing.py -idst misuse -a DoSGoldenEye -t 8 -dp ./data/unprocessedCSVs -bq 8000 -eaq 200
	python preprocessing.py -idst misuse -a DoSHulk -t 8 -dp ./data/unprocessedCSVs -bq 8000 -eaq 200
	python preprocessing.py -idst misuse -a DoSslowloris -t 8 -dp ./data/unprocessedCSVs -bq 8000 -eaq 200
	python preprocessing.py -idst misuse -a FTP-Patator -t 8 -dp ./data/unprocessedCSVs -bq 8000 -eaq 200
	python preprocessing.py -idst misuse -a SSH-Patator -t 8 -dp ./data/unprocessedCSVs -bq 8000 -eaq 200
	python preprocessing.py -idst misuse -a PortScan -t 8 -dp ./data/unprocessedCSVs -bq 8000 -eaq 200
	python preprocessing.py -idst misuse -a WebAttack -t 8 -dp ./data/unprocessedCSVs -bq 8000 -eaq 200
	python preprocessing.py -idst misuse -a DoSSlowhttptest -t 8 -dp ./data/unprocessedCSVs -bq 8000 -eaq 200