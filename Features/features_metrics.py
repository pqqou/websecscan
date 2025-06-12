import time

def start_metrics():
    return time.time()

def end_metrics(start_time):
    duration = time.time() - start_time
    print(f"[Metrics] Scan duration: {duration:.2f} seconds")
    return duration
