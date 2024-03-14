python eval.py -l /home/ubuntu/eval-malloc/libhook.so -f /home/ubuntu/eval-malloc/ffmalloc/libffmallocnpst.so -r -p "ps -a"
python eval.py -c

python analyzer.py -P
python analyzer.py -m ./log/sort.log
