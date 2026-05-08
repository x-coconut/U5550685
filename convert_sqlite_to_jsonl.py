import sqlite3
import json

def main():
    conn = sqlite3.connect("fine_tune.sqlite")
    cursor = conn.cursor()

    queries = [
        ("XSS", "SELECT input_request, output_request, mutation FROM XSS"),
        ("SQLi","SELECT input_request, output_request, mutation FROM SQLi"),
    ]

    with open("fine_tune.jsonl", "w", encoding="utf-8") as f:
        for label, query in queries:
            rows = cursor.execute(query)

            for input_req, output_req, mutation in rows:
                record = {"input": input_req, "response": output_req, "type": label, "mutation": mutation}
                json.dump(record, f, ensure_ascii=False)
                f.write("\n")

    conn.close()
    print(f"Saved to ./fine_tune.jsonl")

if __name__ == "__main__":
    main()