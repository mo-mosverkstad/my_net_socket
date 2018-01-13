from threading import Thread
from time import sleep
import sys

def print_progress(id):
    for count in range(0, 10000):
        sleep(1)
        print(f'{id}: {count}')

if __name__ == "__main__":
    print_thread = Thread(target=print_progress, args=('print_progress',))
    print_thread.daemon = True
    print_thread.start()
    while True:
        data = input('client:>')
        if data == 'exit':
            break
